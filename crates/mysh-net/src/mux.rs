//! yamux multiplexing over a [`NoiseStream`] (docs/03-protocol.md §4–§5).
//!
//! A spawned driver task is the only holder of the `yamux::Connection`. It
//! continuously polls `poll_next_inbound` (which also drives all stream I/O)
//! and services outbound-open requests arriving on a channel. Inbound
//! streams are handed to [`Incoming`].

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::poll_fn;
use mysh_proto::limits;
use mysh_proto::open::{ErrorCode, Open, OpenReply};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::ConnectionError;

use crate::framing;
use crate::noise::{NoiseStream, StatsHandle, TransferStats};

/// Which side of the connection this mux is; client streams get odd ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

impl From<Mode> for yamux::Mode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Client => yamux::Mode::Client,
            Mode::Server => yamux::Mode::Server,
        }
    }
}

/// Failure to open a stream with a prologue.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    /// The acceptor answered `OpenReply::Err`.
    #[error("{code}: {message}")]
    Rejected { code: ErrorCode, message: String },
    /// No `OpenReply` within [`limits::OPEN_REPLY_DEADLINE`].
    #[error("peer did not answer the stream open in time")]
    Timeout,
    /// The connection is closed.
    #[error("connection closed")]
    Closed,
}

impl OpenError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Io(e) => e,
            Self::Closed => io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"),
            other @ Self::Timeout => io::Error::new(io::ErrorKind::TimedOut, other.to_string()),
            other @ Self::Rejected { .. } => io::Error::other(other.to_string()),
        }
    }
}

fn connection_error(err: ConnectionError) -> OpenError {
    match err {
        ConnectionError::Io(e) => OpenError::Io(e),
        ConnectionError::Closed => OpenError::Closed,
        other => OpenError::Io(io::Error::other(other)),
    }
}

/// A multiplexed stream; tokio `AsyncRead + AsyncWrite`.
///
/// `poll_shutdown` half-closes our write side; dropping without shutdown
/// resets the stream.
pub struct Stream(Compat<yamux::Stream>);

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Stream").field(&self.id()).finish()
    }
}

impl Stream {
    fn new(inner: yamux::Stream) -> Self {
        Self(FuturesAsyncReadCompatExt::compat(inner))
    }

    /// yamux stream id (odd = client-initiated, even = server-initiated).
    pub fn id(&self) -> u32 {
        self.0.get_ref().id().val()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Receiver of streams opened by the peer.
#[derive(Debug)]
pub struct Incoming(mpsc::Receiver<Stream>);

impl Incoming {
    /// Next peer-initiated stream; `None` once the connection has ended.
    pub async fn accept(&mut self) -> Option<Stream> {
        self.0.recv().await
    }
}

type OpenResult = Result<yamux::Stream, ConnectionError>;

enum Request {
    Open(oneshot::Sender<OpenResult>),
    Close,
}

struct Shared {
    requests: mpsc::Sender<Request>,
    done: watch::Receiver<bool>,
    stats: StatsHandle,
}

/// Handle to a multiplexed connection. Cheap to clone.
#[derive(Clone)]
pub struct Mux(Arc<Shared>);

impl fmt::Debug for Mux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mux")
            .field("done", &*self.0.done.borrow())
            .field("stats", &self.0.stats.get())
            .finish()
    }
}

fn config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(limits::MAX_STREAMS);
    // yamux 0.14 exposes no per-stream window cap; the connection-wide cap
    // must leave every stream its 256 KiB initial window.
    cfg.set_max_connection_receive_window(Some(
        limits::MAX_STREAMS * yamux::DEFAULT_CREDIT as usize,
    ));
    cfg.set_read_after_close(true);
    cfg
}

impl Mux {
    /// Start multiplexing over `stream`; spawns the driver task.
    pub fn new<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: NoiseStream<S>,
        mode: Mode,
    ) -> (Mux, Incoming) {
        let stats = stream.stats_handle();
        let conn = yamux::Connection::new(
            TokioAsyncReadCompatExt::compat(stream),
            config(),
            mode.into(),
        );
        let (requests, request_rx) = mpsc::channel(16);
        let (incoming_tx, incoming_rx) = mpsc::channel(limits::MAX_STREAMS);
        let (done_tx, done) = watch::channel(false);
        tokio::spawn(drive(conn, request_rx, incoming_tx, done_tx));
        let mux = Mux(Arc::new(Shared {
            requests,
            done,
            stats,
        }));
        (mux, Incoming(incoming_rx))
    }

    async fn open_inner(&self) -> Result<Stream, OpenError> {
        let (tx, rx) = oneshot::channel();
        self.0
            .requests
            .send(Request::Open(tx))
            .await
            .map_err(|_| OpenError::Closed)?;
        let stream = rx
            .await
            .map_err(|_| OpenError::Closed)?
            .map_err(connection_error)?;
        Ok(Stream::new(stream))
    }

    /// Open a new outbound stream without sending a prologue.
    pub async fn open_raw(&self) -> io::Result<Stream> {
        self.open_inner().await.map_err(OpenError::into_io)
    }

    /// Open a stream, send `open` and wait for the acceptor's reply within
    /// [`limits::OPEN_REPLY_DEADLINE`].
    pub async fn open(&self, open: &Open) -> Result<Stream, OpenError> {
        let mut stream = self.open_inner().await?;
        framing::write_open(&mut stream, open).await?;
        let reply = tokio::time::timeout(
            limits::OPEN_REPLY_DEADLINE,
            framing::read_reply(&mut stream),
        )
        .await
        .map_err(|_| OpenError::Timeout)??;
        match reply {
            OpenReply::Ok => Ok(stream),
            OpenReply::Err { code, message } => Err(OpenError::Rejected { code, message }),
        }
    }

    /// Gracefully close the connection and wait for the driver to finish.
    pub async fn close(&self) {
        let _ = self.0.requests.send(Request::Close).await;
        self.closed().await;
    }

    /// Resolves once the driver has finished (peer closed, error, or
    /// [`Mux::close`]).
    pub async fn closed(&self) {
        let mut done = self.0.done.clone();
        let _ = done.wait_for(|finished| *finished).await;
    }

    /// Plaintext byte counters of the underlying [`NoiseStream`].
    pub fn stats(&self) -> TransferStats {
        self.0.stats.get()
    }
}

/// Read the prologue of an accepted stream (`framing::read_open`). Apply
/// [`limits::OPEN_REPLY_DEADLINE`] with `tokio::time::timeout` if desired.
pub async fn accept_open(stream: &mut Stream) -> io::Result<Result<Open, u8>> {
    framing::read_open(stream).await
}

type Conn<S> = yamux::Connection<Compat<NoiseStream<S>>>;

/// Driver task: sole owner of the yamux connection.
async fn drive<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: Conn<S>,
    mut requests: mpsc::Receiver<Request>,
    incoming: mpsc::Sender<Stream>,
    done: watch::Sender<bool>,
) {
    let mut pending: Option<oneshot::Sender<OpenResult>> = None;
    let mut closing = false;

    let result: Result<(), ConnectionError> = poll_fn(|cx| {
        loop {
            if closing {
                return conn.poll_close(cx);
            }

            if let Some(reply) = pending.take() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(res) => {
                        if let Err(Err(e)) = reply.send(res) {
                            tracing::debug!(error = %e, "outbound open failed; requester gone");
                        }
                        continue;
                    }
                    Poll::Pending => pending = Some(reply),
                }
            } else {
                match requests.poll_recv(cx) {
                    Poll::Ready(Some(Request::Open(reply))) => {
                        pending = Some(reply);
                        continue;
                    }
                    Poll::Ready(Some(Request::Close) | None) => {
                        closing = true;
                        continue;
                    }
                    Poll::Pending => {}
                }
            }

            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    if let Err(err) = incoming.try_send(Stream::new(stream)) {
                        tracing::debug!(
                            stream = err.into_inner().id(),
                            "dropping inbound stream: no acceptor"
                        );
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;

    match result {
        Ok(()) => tracing::debug!("mux closed"),
        Err(e) => tracing::debug!(error = %e, "mux ended with error"),
    }
    if let Some(reply) = pending.take() {
        let _ = reply.send(Err(ConnectionError::Closed));
    }
    // Reset remaining streams, then end `Incoming` and wake `closed()`.
    drop(conn);
    drop(requests);
    drop(incoming);
    let _ = done.send(true);
    drop(done);
}

#[cfg(test)]
mod tests {
    use mysh_proto::session::{SessionKind, SessionRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::noise::tests::stream_pair;

    fn mux_pair() -> ((Mux, Incoming), (Mux, Incoming)) {
        let (a, b) = stream_pair(64 * 1024);
        (Mux::new(a, Mode::Client), Mux::new(b, Mode::Server))
    }

    /// Echo every accepted stream until it half-closes, then half-close back.
    async fn echo_server(mut incoming: Incoming, expected: usize) {
        let mut tasks = Vec::new();
        for _ in 0..expected {
            let mut stream = incoming.accept().await.expect("stream");
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                    stream.flush().await.unwrap();
                }
                stream.shutdown().await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn three_streams_echo_and_half_close() {
        let ((client, _client_in), (server, server_in)) = mux_pair();
        let server_task = tokio::spawn(echo_server(server_in, 3));

        let mut clients = Vec::new();
        for i in 0..3u8 {
            let client = client.clone();
            clients.push(tokio::spawn(async move {
                let mut s = client.open_raw().await.unwrap();
                assert_eq!(s.id() % 2, 1, "client streams have odd ids");
                let msg = vec![i; 100_000];
                s.write_all(&msg).await.unwrap();
                s.flush().await.unwrap();
                let mut got = vec![0u8; msg.len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(got, msg);
                // Half-close: the server sees EOF, echoes its own close.
                s.shutdown().await.unwrap();
                let mut tail = [0u8; 1];
                assert_eq!(s.read(&mut tail).await.unwrap(), 0);
            }));
        }
        for task in clients {
            task.await.unwrap();
        }
        server_task.await.unwrap();

        assert!(client.stats().bytes_out >= 300_000);
        client.close().await;
        server.closed().await;
    }

    #[tokio::test]
    async fn server_initiated_stream() {
        let ((client, mut client_in), (server, _server_in)) = mux_pair();
        let mut s = server.open_raw().await.unwrap();
        assert_eq!(s.id() % 2, 0, "server streams have even ids");
        s.write_all(b"from server").await.unwrap();
        s.flush().await.unwrap();

        let mut accepted = client_in.accept().await.unwrap();
        let mut buf = [0u8; 11];
        accepted.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from server");
        client.close().await;
    }

    #[tokio::test]
    async fn open_with_prologue_ok_and_rejected() {
        let ((client, _client_in), (server, mut server_in)) = mux_pair();
        let acceptor = tokio::spawn(async move {
            let mut s = server_in.accept().await.unwrap();
            assert_eq!(accept_open(&mut s).await.unwrap(), Ok(Open::Control));
            framing::write_reply(&mut s, &OpenReply::Ok).await.unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");

            let mut s2 = server_in.accept().await.unwrap();
            let open = accept_open(&mut s2).await.unwrap().unwrap();
            assert!(matches!(open, Open::Session(_)));
            framing::write_reply(
                &mut s2,
                &OpenReply::Err {
                    code: ErrorCode::Denied,
                    message: "no sessions".into(),
                },
            )
            .await
            .unwrap();
            server
        });

        let mut control = client.open(&Open::Control).await.unwrap();
        control.write_all(b"hi").await.unwrap();
        control.flush().await.unwrap();

        let session = Open::Session(SessionRequest {
            kind: SessionKind::Shell,
            env: vec![],
            pty: None,
            cwd: None,
            persist: false,
        });
        match client.open(&session).await {
            Err(OpenError::Rejected { code, message }) => {
                assert_eq!(code, ErrorCode::Denied);
                assert_eq!(message, "no sessions");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let server = acceptor.await.unwrap();
        client.close().await;
        server.closed().await;
        assert!(matches!(client.open_raw().await, Err(e) if e.kind() == io::ErrorKind::BrokenPipe));
    }

    #[tokio::test]
    async fn peer_close_ends_incoming() {
        let ((client, _client_in), (_server, mut server_in)) = mux_pair();
        client.close().await;
        assert!(server_in.accept().await.is_none());
    }
}
