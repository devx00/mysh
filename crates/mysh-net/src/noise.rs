//! `NoiseStream`: tokio `AsyncRead + AsyncWrite` over length-framed Noise
//! transport messages (docs/03-protocol.md §3).
//!
//! Wire format per message: `u16-BE ciphertext_len ‖ ciphertext`. Plaintext
//! is chunked at [`MAX_PLAINTEXT`] bytes. The stream uses snow's
//! `StatelessTransportState` with independent send/receive nonce counters, so
//! the two directions never contend on a cipher state.
//!
//! Write side: plaintext is buffered until a full chunk is available or the
//! caller flushes, then sealed into a single outgoing frame that is drained
//! into the inner stream before any further plaintext is accepted. Read side:
//! one frame is read and decrypted at a time; `poll_read` is served from the
//! decrypted buffer.
//!
//! A decrypt failure, a truncated frame or a malformed header poisons the
//! stream: every later operation fails with the same error kind.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use mysh_proto::{NOISE_MAX_MESSAGE, NOISE_TAG_LEN};
use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest plaintext carried by one Noise transport message.
pub const MAX_PLAINTEXT: usize = NOISE_MAX_MESSAGE - NOISE_TAG_LEN;

/// Length prefix size.
const HEADER_LEN: usize = 2;

/// Plaintext byte counters, readable after the stream moved into the mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Default)]
struct Counters {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

/// Shared handle to a stream's [`TransferStats`].
#[derive(Debug, Clone, Default)]
pub struct StatsHandle(Arc<Counters>);

impl StatsHandle {
    pub fn get(&self) -> TransferStats {
        TransferStats {
            bytes_in: self.0.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.0.bytes_out.load(Ordering::Relaxed),
        }
    }
}

/// Encrypted, authenticated byte stream over `S`.
pub struct NoiseStream<S> {
    inner: S,
    transport: StatelessTransportState,
    send_nonce: u64,
    recv_nonce: u64,
    /// Plaintext accepted by `poll_write` but not yet sealed; `< MAX_PLAINTEXT`.
    pending: Vec<u8>,
    /// One sealed frame (`header ‖ ciphertext`) waiting to reach `inner`.
    out: Vec<u8>,
    out_pos: usize,
    /// Incoming frame being assembled: `header ‖ ciphertext`.
    frame: Vec<u8>,
    /// Bytes of `frame` filled so far.
    frame_len: usize,
    /// Bytes `frame` must reach before it can be decrypted (`HEADER_LEN`
    /// until the header is complete).
    frame_need: usize,
    /// Decrypted plaintext not yet handed to the reader.
    plain: Vec<u8>,
    plain_pos: usize,
    plain_len: usize,
    poisoned: Option<io::ErrorKind>,
    stats: StatsHandle,
}

impl<S> fmt::Debug for NoiseStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseStream")
            .field("send_nonce", &self.send_nonce)
            .field("recv_nonce", &self.recv_nonce)
            .field("pending", &self.pending.len())
            .field("out", &(self.out.len() - self.out_pos))
            .field("plain", &(self.plain_len - self.plain_pos))
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<S> NoiseStream<S> {
    /// Wrap `inner` with a finished handshake's transport state.
    pub(crate) fn new(inner: S, transport: StatelessTransportState) -> Self {
        Self {
            inner,
            transport,
            send_nonce: 0,
            recv_nonce: 0,
            pending: Vec::with_capacity(MAX_PLAINTEXT),
            out: Vec::with_capacity(HEADER_LEN + NOISE_MAX_MESSAGE),
            out_pos: 0,
            frame: vec![0u8; HEADER_LEN + NOISE_MAX_MESSAGE],
            frame_len: 0,
            frame_need: HEADER_LEN,
            plain: vec![0u8; MAX_PLAINTEXT],
            plain_pos: 0,
            plain_len: 0,
            poisoned: None,
            stats: StatsHandle::default(),
        }
    }

    /// Plaintext byte counters so far.
    pub fn stats(&self) -> TransferStats {
        self.stats.get()
    }

    /// Clonable handle to the counters; survives moving the stream elsewhere.
    pub fn stats_handle(&self) -> StatsHandle {
        self.stats.clone()
    }

    /// The wrapped transport.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    fn check_poison(&self) -> io::Result<()> {
        match self.poisoned {
            Some(kind) => Err(io::Error::new(
                kind,
                "noise stream poisoned by an earlier error",
            )),
            None => Ok(()),
        }
    }

    fn poison(&mut self, err: io::Error) -> io::Error {
        self.poisoned = Some(err.kind());
        err
    }

    /// Encrypt `pending` into `out`. Requires `out` to be empty.
    fn seal_pending(&mut self) -> io::Result<()> {
        debug_assert_eq!(self.out_pos, self.out.len());
        let plain_len = self.pending.len();
        let ct_len = plain_len + NOISE_TAG_LEN;
        self.out.clear();
        self.out_pos = 0;
        self.out.resize(HEADER_LEN + ct_len, 0);
        let written = self
            .transport
            .write_message(self.send_nonce, &self.pending, &mut self.out[HEADER_LEN..])
            .map_err(|e| io::Error::other(format!("noise encrypt: {e}")));
        let written = match written {
            Ok(n) => n,
            Err(e) => {
                self.out.clear();
                return Err(self.poison(e));
            }
        };
        debug_assert_eq!(written, ct_len);
        #[allow(clippy::cast_possible_truncation)] // ct_len ≤ NOISE_MAX_MESSAGE ≤ u16::MAX
        let header = (ct_len as u16).to_be_bytes();
        self.out[..HEADER_LEN].copy_from_slice(&header);
        self.send_nonce += 1;
        self.pending.clear();
        self.stats
            .0
            .bytes_out
            .fetch_add(plain_len as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Decrypt the complete frame in `frame[..frame_need]` into `plain`.
    fn open_frame(&mut self) -> io::Result<()> {
        let ct = &self.frame[HEADER_LEN..self.frame_need];
        let n = self
            .transport
            .read_message(self.recv_nonce, ct, &mut self.plain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("noise decrypt: {e}")));
        self.frame_len = 0;
        self.frame_need = HEADER_LEN;
        match n {
            Ok(n) => {
                self.recv_nonce += 1;
                self.plain_pos = 0;
                self.plain_len = n;
                self.stats.0.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(self.poison(e)),
        }
    }
}

impl<S: AsyncWrite + Unpin> NoiseStream<S> {
    /// Push the sealed frame in `out` to `inner`. Ready once `out` is empty.
    fn poll_drain_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "inner stream accepted no bytes",
                )));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> NoiseStream<S> {
    /// Assemble one complete frame in `frame`. `Ready(Ok(false))` on a clean
    /// EOF at a frame boundary.
    fn poll_fill_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if self.frame_len == self.frame_need {
                if self.frame_need > HEADER_LEN {
                    return Poll::Ready(Ok(true));
                }
                // Header complete: learn the ciphertext length.
                let ct_len = usize::from(u16::from_be_bytes([self.frame[0], self.frame[1]]));
                if ct_len < NOISE_TAG_LEN {
                    return Poll::Ready(Err(self.poison(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("noise frame of {ct_len} bytes is shorter than the tag"),
                    ))));
                }
                self.frame_need = HEADER_LEN + ct_len;
                continue;
            }
            let mut buf = ReadBuf::new(&mut self.frame[self.frame_len..self.frame_need]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                if self.frame_len == 0 {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(self.poison(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                ))));
            }
            self.frame_len += n;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_pos < this.plain_len {
                let avail = &this.plain[this.plain_pos..this.plain_len];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            this.check_poison()?;
            if !ready!(this.poll_fill_frame(cx))? {
                return Poll::Ready(Ok(()));
            }
            this.open_frame()?;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_poison()?;
        ready!(this.poll_drain_out(cx))?;
        let room = MAX_PLAINTEXT - this.pending.len();
        let n = buf.len().min(room);
        this.pending.extend_from_slice(&buf[..n]);
        if this.pending.len() == MAX_PLAINTEXT {
            this.seal_pending()?;
            // Opportunistic push; a Pending here merely registers a waker.
            if let Poll::Ready(Err(e)) = this.poll_drain_out(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_poison()?;
        ready!(this.poll_drain_out(cx))?;
        if !this.pending.is_empty() {
            this.seal_pending()?;
            ready!(this.poll_drain_out(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use mysh_proto::NOISE_PATTERN;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::keys::SecretKey;

    /// Two transport states from an in-process XX handshake.
    pub(crate) fn transport_pair() -> (StatelessTransportState, StatelessTransportState) {
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();
        let ck = SecretKey::generate();
        let sk = SecretKey::generate();
        let mut i = snow::Builder::new(params.clone())
            .local_private_key(ck.as_bytes())
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut r = snow::Builder::new(params)
            .local_private_key(sk.as_bytes())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut msg = [0u8; 1024];
        let mut payload = [0u8; 1024];
        let n = i.write_message(&[], &mut msg).unwrap();
        r.read_message(&msg[..n], &mut payload).unwrap();
        let n = r.write_message(&[], &mut msg).unwrap();
        i.read_message(&msg[..n], &mut payload).unwrap();
        let n = i.write_message(&[], &mut msg).unwrap();
        r.read_message(&msg[..n], &mut payload).unwrap();
        (
            i.into_stateless_transport_mode().unwrap(),
            r.into_stateless_transport_mode().unwrap(),
        )
    }

    /// Connected `NoiseStream` pair over a tokio duplex pipe.
    pub(crate) fn stream_pair(
        pipe: usize,
    ) -> (
        NoiseStream<tokio::io::DuplexStream>,
        NoiseStream<tokio::io::DuplexStream>,
    ) {
        let (ti, tr) = transport_pair();
        let (a, b) = tokio::io::duplex(pipe);
        (NoiseStream::new(a, ti), NoiseStream::new(b, tr))
    }

    /// Deterministic xorshift so the random split test is reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn pattern(len: usize, seed: u64) -> Vec<u8> {
        let mut rng = Rng(seed | 1);
        (0..len)
            .map(|_| u8::try_from(rng.next() & 0xff).expect("masked to a byte"))
            .collect()
    }

    async fn round_trip(len: usize, pipe: usize, splits: Option<u64>) {
        let (mut a, mut b) = stream_pair(pipe);
        let data = pattern(len, 0x9e37_79b9_7f4a_7c15 ^ len as u64);
        let expected = data.clone();
        let writer = tokio::spawn(async move {
            match splits {
                None => a.write_all(&data).await.unwrap(),
                Some(seed) => {
                    let mut rng = Rng(seed);
                    let mut pos = 0;
                    while pos < data.len() {
                        let max = (data.len() - pos).min(100_000);
                        let n = usize::try_from(rng.next() % max as u64).unwrap() + 1;
                        a.write_all(&data[pos..pos + n]).await.unwrap();
                        if rng.next().is_multiple_of(3) {
                            a.flush().await.unwrap();
                        }
                        pos += n;
                    }
                }
            }
            a.shutdown().await.unwrap();
            a
        });
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert!(got == expected, "round trip of {len} bytes differs");
        let a = writer.await.unwrap();
        assert_eq!(a.stats().bytes_out, len as u64);
        assert_eq!(b.stats().bytes_in, len as u64);
        assert_eq!(b.stats_handle().get().bytes_in, len as u64);
    }

    #[tokio::test]
    async fn round_trip_one_byte() {
        round_trip(1, 64, None).await;
    }

    #[tokio::test]
    async fn round_trip_multi_frame() {
        round_trip(70_000, 4096, None).await;
    }

    #[tokio::test]
    async fn round_trip_one_mib_random_splits() {
        round_trip(1 << 20, 1234, Some(42)).await;
    }

    #[tokio::test]
    async fn small_writes_are_coalesced_until_flush() {
        let (mut a, mut b) = stream_pair(4096);
        a.write_all(b"hello ").await.unwrap();
        a.write_all(b"world").await.unwrap();
        assert_eq!(a.send_nonce, 0);
        a.flush().await.unwrap();
        assert_eq!(a.send_nonce, 1);
        let mut buf = [0u8; 11];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[tokio::test]
    async fn truncated_frame_is_unexpected_eof_and_poisons() {
        let (ti, _tr) = transport_pair();
        let (_ti2, tr2) = transport_pair();
        let (raw_a, raw_b) = tokio::io::duplex(4096);
        let mut a = NoiseStream::new(raw_a, ti);
        let mut b = NoiseStream::new(raw_b, tr2);
        a.write_all(b"data").await.unwrap();
        a.flush().await.unwrap();
        // Wrong keys: the tag fails to verify.
        let mut buf = [0u8; 16];
        let err = b.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = b.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Truncated frame: header promises more than arrives.
        let (_, tr) = transport_pair();
        let (mut raw_a, raw_b) = tokio::io::duplex(4096);
        let mut b = NoiseStream::new(raw_b, tr);
        raw_a.write_all(&[0, 40, 1, 2, 3]).await.unwrap();
        drop(raw_a);
        let err = b.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn clean_eof_at_frame_boundary() {
        let (mut a, mut b) = stream_pair(64);
        a.write_all(b"x").await.unwrap();
        a.shutdown().await.unwrap();
        drop(a);
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"x");
    }
}
