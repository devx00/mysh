//! Version preamble, `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake and the
//! post-handshake verdict (docs/03-protocol.md §1–§3).
//!
//! Handshake messages travel with the same `u16-BE len ‖ bytes` framing as
//! transport messages. Payloads inside Noise messages 2 and 3 are raw
//! postcard (no `Msg` header); the verdict after the handshake is a regular
//! `Msg<Verdict>` on the resulting [`NoiseStream`].

use std::io;

use mysh_proto::handshake::{ClientHello, ServerHello, Verdict};
use mysh_proto::open::ErrorCode;
use mysh_proto::{
    MAGIC, NOISE_MAX_MESSAGE, NOISE_PATTERN, PROLOGUE_PREFIX, PROTOCOL_VERSION, limits,
};
use snow::HandshakeState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::framing;
use crate::keys::{PublicKey, SecretKey};
use crate::noise::NoiseStream;

/// Result of a successful handshake.
#[derive(Debug)]
pub struct Handshaken<S> {
    pub stream: NoiseStream<S>,
    /// The peer's static public key.
    pub remote: PublicKey,
    /// Agreed protocol version.
    pub version: u16,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("peer did not send the mysh preamble")]
    BadMagic,
    #[error("protocol version {0} is not supported")]
    VersionUnsupported(u16),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("codec: {0}")]
    Codec(#[from] mysh_proto::frame::Error),
    /// The client's `verify_server` callback refused the server key.
    #[error("server not trusted: {0}")]
    Trust(#[source] BoxError),
    /// The server refused the client (`Verdict::Denied`); on the server side,
    /// `authorize` refused and the verdict has already been sent.
    #[error("{code}: {message}")]
    Denied { code: ErrorCode, message: String },
    #[error("handshake timed out")]
    Timeout,
}

const PREAMBLE_LEN: usize = MAGIC.len() + 2;

fn preamble(version: u16) -> [u8; PREAMBLE_LEN] {
    let mut out = [0u8; PREAMBLE_LEN];
    out[..MAGIC.len()].copy_from_slice(&MAGIC);
    out[MAGIC.len()..].copy_from_slice(&version.to_le_bytes());
    out
}

/// Parse a received preamble; `Ok(version)` or `BadMagic`.
fn parse_preamble(bytes: [u8; PREAMBLE_LEN]) -> Result<u16, HandshakeError> {
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(HandshakeError::BadMagic);
    }
    Ok(u16::from_le_bytes([
        bytes[MAGIC.len()],
        bytes[MAGIC.len() + 1],
    ]))
}

fn prologue(version: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROLOGUE_PREFIX.len() + 2);
    out.extend_from_slice(PROLOGUE_PREFIX);
    out.extend_from_slice(&version.to_le_bytes());
    out
}

fn builder<'a>(
    identity: &'a SecretKey,
    prologue: &'a [u8],
) -> Result<snow::Builder<'a>, HandshakeError> {
    Ok(snow::Builder::new(NOISE_PATTERN.parse()?)
        .prologue(prologue)?
        .local_private_key(identity.as_bytes())?)
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, HandshakeError> {
    postcard::to_allocvec(value).map_err(|e| HandshakeError::Codec(e.into()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, HandshakeError> {
    postcard::from_bytes(bytes).map_err(|e| HandshakeError::Codec(e.into()))
}

/// Write one length-framed handshake message and flush.
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "handshake message too long"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(msg).await?;
    w.flush().await
}

/// Read one length-framed handshake message into `buf`; returns its length.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut header = [0u8; 2];
    r.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes(header));
    if len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handshake message exceeds the noise message limit",
        ));
    }
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// Working buffers for one handshake.
struct Buffers {
    msg: Vec<u8>,
    payload: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            msg: vec![0u8; NOISE_MAX_MESSAGE],
            payload: vec![0u8; NOISE_MAX_MESSAGE],
        }
    }

    /// Build a handshake message carrying `payload` and send it.
    async fn send<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        hs: &mut HandshakeState,
        payload: &[u8],
    ) -> Result<(), HandshakeError> {
        let n = hs.write_message(payload, &mut self.msg)?;
        write_frame(io, &self.msg[..n]).await?;
        Ok(())
    }

    /// Receive a handshake message; returns its decrypted payload.
    async fn recv<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        hs: &mut HandshakeState,
    ) -> Result<&[u8], HandshakeError> {
        let n = read_frame(io, &mut self.msg).await?;
        let len = hs.read_message(&self.msg[..n], &mut self.payload)?;
        Ok(&self.payload[..len])
    }
}

fn remote_static(hs: &HandshakeState) -> Result<PublicKey, HandshakeError> {
    let bytes = hs
        .get_remote_static()
        .and_then(|rs| <[u8; 32]>::try_from(rs).ok())
        .ok_or(snow::Error::State(
            snow::error::StateProblem::MissingKeyMaterial,
        ))?;
    Ok(PublicKey::from_bytes(bytes))
}

/// Run the client side of the handshake over `io`.
///
/// `verify_server` is called with the server's static key and `ServerHello`
/// before message 3 is sent; on `Err` the connection is dropped without
/// revealing the client's identity.
#[allow(clippy::needless_pass_by_value)] // `hello` is by value per the crate API
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut io: S,
    identity: &SecretKey,
    hello: ClientHello,
    verify_server: impl FnOnce(&PublicKey, &ServerHello) -> Result<(), BoxError>,
) -> Result<(Handshaken<S>, ServerHello), HandshakeError> {
    io.write_all(&preamble(PROTOCOL_VERSION)).await?;
    io.flush().await?;
    let mut bytes = [0u8; PREAMBLE_LEN];
    io.read_exact(&mut bytes).await?;
    let version = parse_preamble(bytes)?;
    if version == 0 || version > PROTOCOL_VERSION {
        return Err(HandshakeError::VersionUnsupported(version));
    }

    let prologue = prologue(version);
    let mut hs = builder(identity, &prologue)?.build_initiator()?;
    let mut buf = Buffers::new();

    // msg1: e
    buf.send(&mut io, &mut hs, &[]).await?;
    // msg2: e, ee, s, es ‖ ServerHello
    let server_hello: ServerHello = decode(buf.recv(&mut io, &mut hs).await?)?;
    let remote = remote_static(&hs)?;
    if let Err(err) = verify_server(&remote, &server_hello) {
        tracing::debug!(fingerprint = %remote.fingerprint(), "server key rejected");
        return Err(HandshakeError::Trust(err));
    }
    // msg3: s, se ‖ ClientHello
    let payload = encode(&hello)?;
    buf.send(&mut io, &mut hs, &payload).await?;
    drop(buf);

    let mut stream = NoiseStream::new(io, hs.into_stateless_transport_mode()?);
    let verdict: Verdict = framing::read_msg(&mut stream).await?;
    match verdict {
        Verdict::Accepted => Ok((
            Handshaken {
                stream,
                remote,
                version,
            },
            server_hello,
        )),
        Verdict::Denied { code, message } => Err(HandshakeError::Denied { code, message }),
    }
}

/// Run the server side of the handshake over `io`, bounded by
/// [`limits::HANDSHAKE_DEADLINE`].
///
/// `authorize` is called with the client's static key and `ClientHello`
/// after message 3. On refusal the verdict is sent and
/// `HandshakeError::Denied` is returned.
pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    io: S,
    identity: &SecretKey,
    hello: ServerHello,
    authorize: impl FnOnce(&PublicKey, &ClientHello) -> Result<(), (ErrorCode, String)>,
) -> Result<Handshaken<S>, HandshakeError> {
    tokio::time::timeout(
        limits::HANDSHAKE_DEADLINE,
        server_handshake_inner(io, identity, hello, authorize),
    )
    .await
    .map_err(|_| HandshakeError::Timeout)?
}

#[allow(clippy::needless_pass_by_value)] // mirrors `server_handshake`
async fn server_handshake_inner<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut io: S,
    identity: &SecretKey,
    hello: ServerHello,
    authorize: impl FnOnce(&PublicKey, &ClientHello) -> Result<(), (ErrorCode, String)>,
) -> Result<Handshaken<S>, HandshakeError> {
    let mut bytes = [0u8; PREAMBLE_LEN];
    io.read_exact(&mut bytes).await?;
    let client_version = parse_preamble(bytes)?;
    if client_version == 0 {
        return Err(HandshakeError::VersionUnsupported(client_version));
    }
    let version = client_version.min(PROTOCOL_VERSION);
    io.write_all(&preamble(version)).await?;
    io.flush().await?;

    let prologue = prologue(version);
    let mut hs = builder(identity, &prologue)?.build_responder()?;
    let mut buf = Buffers::new();

    // msg1: e
    buf.recv(&mut io, &mut hs).await?;
    // msg2: e, ee, s, es ‖ ServerHello
    let payload = encode(&hello)?;
    buf.send(&mut io, &mut hs, &payload).await?;
    // msg3: s, se ‖ ClientHello
    let client_hello: ClientHello = decode(buf.recv(&mut io, &mut hs).await?)?;
    drop(buf);
    let remote = remote_static(&hs)?;

    let mut stream = NoiseStream::new(io, hs.into_stateless_transport_mode()?);
    match authorize(&remote, &client_hello) {
        Ok(()) => {
            framing::write_msg(&mut stream, &Verdict::Accepted).await?;
            Ok(Handshaken {
                stream,
                remote,
                version,
            })
        }
        Err((code, message)) => {
            tracing::debug!(fingerprint = %remote.fingerprint(), %code, "client refused");
            let verdict = Verdict::Denied {
                code,
                message: message.clone(),
            };
            framing::write_msg(&mut stream, &verdict).await?;
            let _ = stream.shutdown().await;
            Err(HandshakeError::Denied { code, message })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello() -> ServerHello {
        ServerHello {
            name: "testhost".into(),
            caps: 0,
        }
    }

    #[tokio::test]
    async fn full_handshake_exchanges_keys_and_version() {
        let client_key = SecretKey::generate();
        let server_key = SecretKey::generate();
        let client_pk = client_key.public();
        let server_pk = server_key.public();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(a, &client_key, ClientHello { caps: 0 }, |pk, hello| {
            assert_eq!(*pk, server_pk);
            assert_eq!(hello.name, "testhost");
            Ok(())
        });
        let server = server_handshake(b, &server_key, server_hello(), |pk, hello| {
            assert_eq!(*pk, client_pk);
            assert_eq!(hello.caps, 0);
            Ok(())
        });
        let (client, server) = tokio::join!(client, server);
        let (mut client, hello) = client.unwrap();
        let mut server = server.unwrap();
        assert_eq!(hello.name, "testhost");
        assert_eq!(client.remote, server_pk);
        assert_eq!(server.remote, client_pk);
        assert_eq!(client.version, PROTOCOL_VERSION);
        assert_eq!(server.version, PROTOCOL_VERSION);

        // The transport works in both directions afterwards.
        client.stream.write_all(b"ping").await.unwrap();
        client.stream.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.stream.write_all(b"pong").await.unwrap();
        server.stream.flush().await.unwrap();
        client.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn untrusted_server_closes_before_msg3() {
        let client_key = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(a, &client_key, ClientHello { caps: 0 }, |_, _| {
            Err("unknown host key".into())
        });
        let server = server_handshake(b, &server_key, server_hello(), |_, _| {
            panic!("authorize must not run when the client never sends msg3")
        });
        let (client, server) = tokio::join!(client, server);
        assert!(matches!(client, Err(HandshakeError::Trust(_))));
        match server {
            Err(HandshakeError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("unexpected server result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unauthorized_client_gets_denied() {
        let client_key = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(a, &client_key, ClientHello { caps: 0 }, |_, _| Ok(()));
        let server = server_handshake(b, &server_key, server_hello(), |_, _| {
            Err((ErrorCode::Unauthorized, "not in authorized_keys".into()))
        });
        let (client, server) = tokio::join!(client, server);
        match client {
            Err(HandshakeError::Denied { code, message }) => {
                assert_eq!(code, ErrorCode::Unauthorized);
                assert_eq!(message, "not in authorized_keys");
            }
            other => panic!("unexpected client result: {other:?}"),
        }
        assert!(matches!(
            server,
            Err(HandshakeError::Denied {
                code: ErrorCode::Unauthorized,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn bad_magic_is_rejected() {
        let server_key = SecretKey::generate();
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"SSH-2.0").await.unwrap();
        let err = server_handshake(b, &server_key, server_hello(), |_, _| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(err, HandshakeError::BadMagic));
    }

    #[tokio::test]
    async fn newer_server_version_is_rejected_by_client() {
        let client_key = SecretKey::generate();
        let (a, mut b) = tokio::io::duplex(64);
        let client = client_handshake(a, &client_key, ClientHello { caps: 0 }, |_, _| Ok(()));
        let fake_server = async move {
            let mut got = [0u8; PREAMBLE_LEN];
            b.read_exact(&mut got).await.unwrap();
            b.write_all(&preamble(PROTOCOL_VERSION + 1)).await.unwrap();
            b
        };
        let (client, _b) = tokio::join!(client, fake_server);
        assert!(matches!(
            client,
            Err(HandshakeError::VersionUnsupported(v)) if v == PROTOCOL_VERSION + 1
        ));
    }
}
