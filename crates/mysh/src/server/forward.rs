//! Server side of TCP forwarding streams (docs/03-protocol.md §8,
//! docs/04-sessions.md "Port forwarding").
//!
//! `DirectTcp`: dial on the client's behalf, then pump bytes both ways.
//! `ForwardListen`: bind a listener on the server; each accepted socket is
//! handed to the client over a server-opened `ForwardedTcp` stream.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mysh_net::framing::{write_msg, write_reply};
use mysh_net::mux::{Mux, Stream};
use mysh_proto::forward::Bound;
use mysh_proto::limits;
use mysh_proto::open::{ErrorCode, Open, OpenReply};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

use crate::cli::Feature;
use crate::server::ConnCtx;
use crate::server::audit::{Event, Extra, Handle};
use crate::server::files::send_error;

/// Upper bound on resolving + connecting for `DirectTcp`.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failed `accept()` (EMFILE and friends) before retrying.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// `Open::DirectTcp`: dial `host:port`, reply, then relay.
#[allow(clippy::needless_pass_by_value)] // signature fixed by the dispatch contract
pub async fn handle_direct_tcp(mut stream: Stream, host: String, port: u16, ctx: ConnCtx) {
    if ctx.policy.deny.contains(&Feature::ForwardLocal) {
        ctx.audit
            .denied("forward", "local forwarding is disabled by server policy");
        send_error(
            &mut stream,
            ErrorCode::Denied,
            "local forwarding is disabled by server policy",
        )
        .await;
        return;
    }
    let started = std::time::Instant::now();
    let socket = match tokio::time::timeout(DIAL_TIMEOUT, dial(&host, port)).await {
        Ok(Ok(socket)) => socket,
        Ok(Err((code, err))) => {
            debug!(%host, port, %err, "direct-tcp dial failed");
            ctx.audit.emit(Event::Forward, || {
                serde_json::json!({ "kind": "direct", "host": host, "port": port, "error": err.to_string() })
            });
            send_error(&mut stream, code, &err.to_string()).await;
            return;
        }
        Err(_) => {
            debug!(%host, port, "direct-tcp dial timed out");
            ctx.audit.emit(Event::Forward, || {
                serde_json::json!({ "kind": "direct", "host": host, "port": port, "error": "connect timed out" })
            });
            send_error(&mut stream, ErrorCode::Io, "connect timed out").await;
            return;
        }
    };
    if let Err(err) = write_reply(&mut stream, &OpenReply::Ok).await {
        debug!(%err, "direct-tcp: reply failed");
        return;
    }
    let relayed = relay(stream, socket).await;
    if let Err(err) = &relayed {
        debug!(%host, port, %err, "direct-tcp relay ended with error");
    }
    let (bytes_out, bytes_in) = relayed.unwrap_or_default();
    ctx.audit.emit_with(
        Event::Forward,
        Extra::traffic(bytes_in, bytes_out, started),
        || serde_json::json!({ "kind": "direct", "host": host, "port": port }),
    );
}

/// Resolve then connect, trying each address in order. Resolution failures
/// and empty results are `NotFound`; connect failures are `Io`.
async fn dial(host: &str, port: u16) -> Result<TcpStream, (ErrorCode, io::Error)> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| (ErrorCode::NotFound, err))?
        .collect();
    if addrs.is_empty() {
        return Err((
            ErrorCode::NotFound,
            io::Error::new(io::ErrorKind::NotFound, format!("{host}: no addresses")),
        ));
    }
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(socket) => return Ok(socket),
            Err(err) => last = Some(err),
        }
    }
    let err = last.unwrap_or_else(|| io::Error::other("connect failed"));
    let code = if err.kind() == io::ErrorKind::NotFound {
        ErrorCode::NotFound
    } else {
        ErrorCode::Io
    };
    Err((code, err))
}

/// Copy bytes both ways with half-close propagation: when one direction hits
/// EOF the peer's write side is shut down; the other direction keeps going.
/// An error on either side ends both (dropping the yamux stream resets it).
/// Returns `(bytes to the socket, bytes to the stream)`.
pub(crate) async fn relay(stream: Stream, socket: TcpStream) -> io::Result<(u64, u64)> {
    let (mut stream_rd, mut stream_wr) = tokio::io::split(stream);
    let (mut sock_rd, mut sock_wr) = socket.into_split();
    let to_socket = async {
        let n = tokio::io::copy(&mut stream_rd, &mut sock_wr).await?;
        sock_wr.shutdown().await?;
        Ok::<u64, io::Error>(n)
    };
    let to_stream = async {
        let n = tokio::io::copy(&mut sock_rd, &mut stream_wr).await?;
        stream_wr.shutdown().await?;
        Ok::<u64, io::Error>(n)
    };
    let (out, inn) = tokio::try_join!(to_socket, to_stream)?;
    debug!(bytes_out = out, bytes_in = inn, "relay finished");
    Ok((out, inn))
}

/// Decrements the connection's listener count when the listener ends.
struct ListenerSlot(Arc<AtomicUsize>);

impl Drop for ListenerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `Open::ForwardListen`: bind, reply `Ok` + `Bound`, then accept until the
/// client closes the stream.
#[allow(clippy::needless_pass_by_value)] // signature fixed by the dispatch contract
pub async fn handle_forward_listen(mut stream: Stream, host: String, port: u16, ctx: ConnCtx) {
    if ctx.policy.deny.contains(&Feature::ForwardRemote) {
        ctx.audit
            .denied("forward", "remote forwarding is disabled by server policy");
        send_error(
            &mut stream,
            ErrorCode::Denied,
            "remote forwarding is disabled by server policy",
        )
        .await;
        return;
    }
    if ctx.listeners.fetch_add(1, Ordering::SeqCst) >= limits::MAX_LISTENERS {
        ctx.listeners.fetch_sub(1, Ordering::SeqCst);
        send_error(
            &mut stream,
            ErrorCode::Limit,
            &format!(
                "at most {} remote listeners per connection",
                limits::MAX_LISTENERS
            ),
        )
        .await;
        return;
    }
    let _slot = ListenerSlot(Arc::clone(&ctx.listeners));

    let bind_host = match host.as_str() {
        "" | "*" => "0.0.0.0",
        other => other,
    };
    let listener = match TcpListener::bind((bind_host, port)).await {
        Ok(listener) => listener,
        Err(err) => {
            debug!(%host, port, %err, "forward-listen bind failed");
            send_error(&mut stream, ErrorCode::Io, &err.to_string()).await;
            return;
        }
    };
    let bound_port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => {
            send_error(&mut stream, ErrorCode::Io, &err.to_string()).await;
            return;
        }
    };
    let id = ctx.next_listener_id();
    let bound = Bound {
        listener: id,
        port: bound_port,
    };
    if let Err(err) = write_reply(&mut stream, &OpenReply::Ok).await {
        debug!(%err, "forward-listen: reply failed");
        return;
    }
    if let Err(err) = write_msg(&mut stream, &bound).await {
        debug!(%err, "forward-listen: Bound failed");
        return;
    }
    debug!(listener = id, %host, port = bound_port, "remote listener bound");
    let started = std::time::Instant::now();
    ctx.audit.emit(Event::Forward, || {
        serde_json::json!({ "kind": "listen", "listener": id, "host": host, "port": bound_port })
    });

    // The control-ish stream carries nothing after `Bound`; its EOF (or
    // reset) is the cancel signal. Anything the client does send is ignored.
    let mut sink = [0u8; 64];
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((socket, peer)) => {
                    let mux = ctx.mux.clone();
                    tokio::spawn(forwarded(mux, id, socket, peer, ctx.audit.clone()));
                }
                Err(err) => {
                    debug!(listener = id, %err, "accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            read = stream.read(&mut sink) => match read {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
        }
    }
    debug!(listener = id, "remote listener closed");
    ctx.audit.emit_with(Event::Forward, Extra::elapsed(started), || {
        serde_json::json!({ "kind": "listen", "listener": id, "host": host, "port": bound_port, "closed": true })
    });
    let _ = stream.shutdown().await;
}

/// Hand one accepted socket to the client over a `ForwardedTcp` stream.
async fn forwarded(mux: Mux, listener: u32, socket: TcpStream, peer: SocketAddr, audit: Handle) {
    let open = Open::ForwardedTcp {
        listener,
        peer: peer.to_string(),
    };
    let started = std::time::Instant::now();
    match mux.open(&open).await {
        Ok(stream) => {
            let relayed = relay(stream, socket).await;
            if let Err(err) = &relayed {
                debug!(listener, %peer, %err, "forwarded relay ended with error");
            }
            let (bytes_out, bytes_in) = relayed.unwrap_or_default();
            audit.emit_with(
                Event::Forward,
                Extra::traffic(bytes_in, bytes_out, started),
                || serde_json::json!({ "kind": "forwarded", "listener": listener, "peer": peer.to_string() }),
            );
        }
        Err(err) => {
            debug!(listener, %peer, %err, "client refused forwarded connection");
            audit.emit(Event::Forward, || {
                serde_json::json!({ "kind": "forwarded", "listener": listener, "peer": peer.to_string(), "error": err.to_string() })
            });
            drop(socket);
        }
    }
}

#[cfg(test)]
mod tests {
    use mysh_net::framing::read_msg;
    use mysh_net::mux::{OpenError, accept_open};

    use super::*;
    use crate::server::files::tests::harness;

    /// Loopback echo server; each accepted socket is echoed until EOF, then
    /// the write side is shut down. Returns the bound address.
    async fn echo_listener() -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut rd, mut wr) = socket.split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    let _ = wr.shutdown().await;
                });
            }
        });
        addr
    }

    async fn echo_through(stream: &mut Stream) {
        let payload: Vec<u8> = (0..100_000u32)
            .map(|i| u8::try_from(i % 241).expect("fits"))
            .collect();
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).await.expect("read echo");
        assert_eq!(got, payload);
        // Half-close: the echo side sees EOF and shuts down its writer,
        // which reaches us as EOF on the stream.
        stream.shutdown().await.expect("half-close");
        let mut tail = [0u8; 1];
        assert_eq!(stream.read(&mut tail).await.expect("eof"), 0);
    }

    #[tokio::test]
    async fn direct_tcp_echo_and_half_close() {
        let h = harness(&[]).await;
        let echo = echo_listener().await;
        let mut stream = h
            .client
            .open(&Open::DirectTcp {
                host: echo.ip().to_string(),
                port: echo.port(),
            })
            .await
            .expect("direct-tcp accepted");
        echo_through(&mut stream).await;
    }

    #[tokio::test]
    async fn direct_tcp_half_close_reaches_socket() {
        let h = harness(&[]).await;
        // A raw acceptor that reports when it reads EOF.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            socket.read_to_end(&mut buf).await.expect("read until eof");
            let _ = eof_tx.send(buf);
            // Keep the socket open a little so the test observes a one-way
            // close, then answer and close.
            socket.write_all(b"bye").await.expect("write");
            socket.shutdown().await.expect("shutdown");
        });
        let mut stream = h
            .client
            .open(&Open::DirectTcp {
                host: "127.0.0.1".into(),
                port: addr.port(),
            })
            .await
            .expect("direct-tcp accepted");
        stream.write_all(b"ping").await.expect("write");
        stream.shutdown().await.expect("half-close");
        assert_eq!(eof_rx.await.expect("eof observed"), b"ping");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("read reply");
        assert_eq!(got, b"bye");
    }

    #[tokio::test]
    async fn direct_tcp_refused_and_denied() {
        // A port that nobody listens on: bind then drop.
        let free = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let port = free.local_addr().expect("addr").port();
        drop(free);

        let h = harness(&[]).await;
        match h
            .client
            .open(&Open::DirectTcp {
                host: "127.0.0.1".into(),
                port,
            })
            .await
        {
            Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::Io),
            other => panic!("expected Io rejection, got {other:?}"),
        }

        let denied = harness(&[Feature::ForwardLocal]).await;
        match denied
            .client
            .open(&Open::DirectTcp {
                host: "127.0.0.1".into(),
                port,
            })
            .await
        {
            Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::Denied),
            other => panic!("expected Denied rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forward_listen_round_trip() {
        let h = harness(&[]).await;
        let mut client_in = h.client_in;
        let mut control = h
            .client
            .open(&Open::ForwardListen {
                host: "127.0.0.1".into(),
                port: 0,
            })
            .await
            .expect("forward-listen accepted");
        let bound: Bound = read_msg(&mut control).await.expect("Bound");
        assert_ne!(bound.port, 0);

        // Client side: accept the ForwardedTcp stream and echo on it.
        let echo_task = tokio::spawn(async move {
            let mut stream = client_in.accept().await.expect("forwarded stream");
            let open = accept_open(&mut stream)
                .await
                .expect("open")
                .expect("decoded");
            match open {
                Open::ForwardedTcp { listener, peer } => {
                    assert_eq!(listener, bound.listener);
                    assert!(peer.starts_with("127.0.0.1:"));
                }
                other => panic!("unexpected open {other:?}"),
            }
            write_reply(&mut stream, &OpenReply::Ok)
                .await
                .expect("reply");
            let (mut rd, mut wr) = tokio::io::split(stream);
            tokio::io::copy(&mut rd, &mut wr).await.expect("echo");
            wr.shutdown().await.expect("shutdown");
        });

        let mut socket = TcpStream::connect(("127.0.0.1", bound.port))
            .await
            .expect("connect to remote listener");
        socket
            .write_all(b"through the tunnel")
            .await
            .expect("write");
        socket.shutdown().await.expect("half-close");
        let mut got = Vec::new();
        socket.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, b"through the tunnel");
        echo_task.await.expect("echo task");

        // Closing the control stream cancels the listener.
        drop(control);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut refused = false;
        for _ in 0..20 {
            if TcpStream::connect(("127.0.0.1", bound.port)).await.is_err() {
                refused = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(refused, "listener still accepting after control close");
    }

    #[tokio::test]
    async fn forward_listen_denied() {
        let h = harness(&[Feature::ForwardRemote]).await;
        match h
            .client
            .open(&Open::ForwardListen {
                host: "127.0.0.1".into(),
                port: 0,
            })
            .await
        {
            Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::Denied),
            other => panic!("expected Denied rejection, got {other:?}"),
        }
    }
}
