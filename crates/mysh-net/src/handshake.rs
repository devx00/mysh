//! Version preamble, `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake and the
//! post-handshake verdict (docs/03-protocol.md §1–§3).
//!
//! Handshake messages travel with the same `u16-BE len ‖ bytes` framing as
//! transport messages. Payloads inside Noise messages 2 and 3 are raw
//! postcard (no `Msg` header); the verdict after the handshake is a regular
//! `Msg<Verdict>` on the resulting [`NoiseStream`].

use std::fmt;
use std::io;
use std::pin::Pin;

use mysh_proto::handshake::{AuthProof, ClientHello, SIG_AUTH_LABEL, ServerHello, Verdict};
use mysh_proto::open::ErrorCode;
use mysh_proto::{
    MAGIC, NOISE_MAX_MESSAGE, NOISE_PATTERN, PROLOGUE_PREFIX, PROTOCOL_VERSION, caps, limits,
};
use snow::HandshakeState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::framing;
use crate::keys::{Fingerprint, PublicKey, SecretKey};
use crate::noise::NoiseStream;

/// Who the client proved to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
    /// Authenticated by the Noise static key.
    Static(PublicKey),
    /// Authenticated by an ed25519 signature over the handshake hash; the
    /// Noise static was ephemeral.
    Ed25519([u8; 32]),
}

impl Peer {
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Static(key) => key.fingerprint(),
            Self::Ed25519(pk) => Fingerprint::of_ssh_ed25519(pk),
        }
    }

    /// `"x25519"` or `"ssh-ed25519"`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Static(_) => "x25519",
            Self::Ed25519(_) => "ssh-ed25519",
        }
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind(), self.fingerprint())
    }
}

/// Result of a successful handshake.
#[derive(Debug)]
pub struct Handshaken<S> {
    pub stream: NoiseStream<S>,
    /// The peer's Noise static public key (ephemeral when the client used
    /// signature authentication).
    pub remote: PublicKey,
    /// Who the client proved to be (on the client side, `Peer::Static` of
    /// the server's key).
    pub peer: Peer,
    /// Agreed protocol version.
    pub version: u16,
    /// The server accepted this connection for pairing only
    /// (`Verdict::Pairing`); only `Open::Control` and `Open::Pair` work.
    pub pairing: bool,
}

/// Produces ed25519 signatures for [`ClientAuth::Ed25519`].
pub trait Signer: Send {
    /// Sign `message` (`SIG_AUTH_LABEL ‖ h2`) and return the 64-byte signature.
    fn sign<'a>(
        &'a mut self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<[u8; 64]>> + Send + 'a>>;
}

/// Client-side proof of identity for message 3.
pub enum ClientAuth<'a> {
    /// The Noise static key is the identity.
    Static,
    /// `public` is the ed25519 key; `sign` receives `SIG_AUTH_LABEL ‖ h2`.
    Ed25519 {
        public: [u8; 32],
        sign: &'a mut dyn Signer,
    },
}

impl fmt::Debug for ClientAuth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static => f.write_str("Static"),
            Self::Ed25519 { public, .. } => f
                .debug_struct("Ed25519")
                .field("public", &Fingerprint::of_ssh_ed25519(public))
                .finish_non_exhaustive(),
        }
    }
}

/// What the server's `authorize` callback grants a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accept {
    /// A trusted key: `Verdict::Accepted`, full service.
    Normal,
    /// An untrusted key asking to pair while a window is open:
    /// `Verdict::Pairing`, only `Open::Control` and `Open::Pair`.
    Pairing,
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
    /// The client wanted signature authentication but the server did not
    /// advertise [`caps::SIG_AUTH`]; nothing identifying was sent.
    #[error("server does not support signature authentication")]
    SigAuthUnsupported,
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
/// `static_key` is the Noise static; for [`ClientAuth::Ed25519`] it should be
/// a fresh per-connection key. `verify_server` is called with the server's
/// static key and `ServerHello` before message 3 is sent; on `Err` the
/// connection is dropped without revealing the client's identity. With
/// `ClientAuth::Ed25519` and a server that does not advertise
/// [`caps::SIG_AUTH`], [`HandshakeError::SigAuthUnsupported`] is returned at
/// the same point.
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut io: S,
    static_key: &SecretKey,
    caps: u32,
    verify_server: impl FnOnce(&PublicKey, &ServerHello) -> Result<(), BoxError>,
    auth: ClientAuth<'_>,
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
    let mut hs = builder(static_key, &prologue)?.build_initiator()?;
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
    let auth = match auth {
        ClientAuth::Static => AuthProof::Static,
        ClientAuth::Ed25519 { public, sign } => {
            if server_hello.caps & caps::SIG_AUTH == 0 {
                return Err(HandshakeError::SigAuthUnsupported);
            }
            let signature = sign.sign(&sig_message(hs.get_handshake_hash())).await?;
            AuthProof::Ed25519 {
                public_key: public,
                signature: signature.to_vec(),
            }
        }
    };
    // msg3: s, se ‖ ClientHello
    let payload = encode(&ClientHello { caps, auth })?;
    buf.send(&mut io, &mut hs, &payload).await?;
    drop(buf);

    let mut stream = NoiseStream::new(io, hs.into_stateless_transport_mode()?);
    let verdict: Verdict = framing::read_msg(&mut stream).await?;
    let pairing = match verdict {
        Verdict::Accepted => false,
        Verdict::Pairing => true,
        Verdict::Denied { code, message } => {
            return Err(HandshakeError::Denied { code, message });
        }
    };
    Ok((
        Handshaken {
            stream,
            remote,
            peer: Peer::Static(remote),
            version,
            pairing,
        },
        server_hello,
    ))
}

/// `SIG_AUTH_LABEL ‖ h2`.
fn sig_message(h2: &[u8]) -> Vec<u8> {
    [SIG_AUTH_LABEL, h2].concat()
}

/// Check an ed25519 proof against the handshake hash snapshot.
fn verify_sig_auth(public_key: &[u8; 32], signature: &[u8], h2: &[u8]) -> bool {
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .and_then(|key| key.verify_strict(&sig_message(h2), &signature))
        .is_ok()
}

/// Run the server side of the handshake over `io`, bounded by
/// [`limits::HANDSHAKE_DEADLINE`].
///
/// `authorize` is called with who the client proved to be and its
/// `ClientHello` after message 3; it answers [`Accept::Normal`] for a
/// trusted key or [`Accept::Pairing`] for a pairing-only connection. On
/// refusal the verdict is sent and `HandshakeError::Denied` is returned.
/// An [`AuthProof::Ed25519`] proof is verified before `authorize` runs; a
/// bad proof, or any proof when `hello` does not advertise
/// [`caps::SIG_AUTH`], is refused without consulting it.
pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    io: S,
    identity: &SecretKey,
    hello: ServerHello,
    authorize: impl FnOnce(&Peer, &ClientHello) -> Result<Accept, (ErrorCode, String)>,
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
    authorize: impl FnOnce(&Peer, &ClientHello) -> Result<Accept, (ErrorCode, String)>,
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
    let h2 = hs.get_handshake_hash().to_vec();
    // msg3: s, se ‖ ClientHello
    let client_hello: ClientHello = decode(buf.recv(&mut io, &mut hs).await?)?;
    drop(buf);
    let remote = remote_static(&hs)?;

    let mut stream = NoiseStream::new(io, hs.into_stateless_transport_mode()?);
    let verdict = match &client_hello.auth {
        AuthProof::Static => Ok(Peer::Static(remote)),
        AuthProof::Ed25519 { .. } if hello.caps & caps::SIG_AUTH == 0 => Err((
            ErrorCode::Unsupported,
            "signature authentication is disabled".to_owned(),
        )),
        AuthProof::Ed25519 {
            public_key,
            signature,
        } => {
            if verify_sig_auth(public_key, signature, &h2) {
                Ok(Peer::Ed25519(*public_key))
            } else {
                Err((ErrorCode::Unauthorized, "bad signature".to_owned()))
            }
        }
    };
    let verdict =
        verdict.and_then(|peer| authorize(&peer, &client_hello).map(|accept| (peer, accept)));
    match verdict {
        Ok((peer, accept)) => {
            let pairing = accept == Accept::Pairing;
            let verdict = if pairing {
                Verdict::Pairing
            } else {
                Verdict::Accepted
            };
            framing::write_msg(&mut stream, &verdict).await?;
            Ok(Handshaken {
                stream,
                remote,
                peer,
                version,
                pairing,
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

        let client = client_handshake(
            a,
            &client_key,
            0,
            |pk, hello| {
                assert_eq!(*pk, server_pk);
                assert_eq!(hello.name, "testhost");
                Ok(())
            },
            ClientAuth::Static,
        );
        let server = server_handshake(b, &server_key, server_hello(), |peer, hello| {
            assert_eq!(*peer, Peer::Static(client_pk));
            assert_eq!(hello.caps, 0);
            assert_eq!(hello.auth, AuthProof::Static);
            Ok(Accept::Normal)
        });
        let (client, server) = tokio::join!(client, server);
        let (mut client, hello) = client.unwrap();
        let mut server = server.unwrap();
        assert_eq!(hello.name, "testhost");
        assert_eq!(client.remote, server_pk);
        assert_eq!(server.remote, client_pk);
        assert_eq!(server.peer, Peer::Static(client_pk));
        assert_eq!(client.peer, Peer::Static(server_pk));
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

        let client = client_handshake(
            a,
            &client_key,
            0,
            |_, _| Err("unknown host key".into()),
            ClientAuth::Static,
        );
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

        let client = client_handshake(a, &client_key, 0, |_, _| Ok(()), ClientAuth::Static);
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
    async fn pairing_accept_sets_the_pairing_verdict() {
        let client_key = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(
            a,
            &client_key,
            caps::PAIR_REQUEST,
            |_, _| Ok(()),
            ClientAuth::Static,
        );
        let server = server_handshake(b, &server_key, server_hello(), |_, hello| {
            assert_eq!(hello.caps & caps::PAIR_REQUEST, caps::PAIR_REQUEST);
            Ok(Accept::Pairing)
        });
        let (client, server) = tokio::join!(client, server);
        let (client, _) = client.unwrap();
        let server = server.unwrap();
        assert!(client.pairing);
        assert!(server.pairing);
    }

    #[tokio::test]
    async fn bad_magic_is_rejected() {
        let server_key = SecretKey::generate();
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"SSH-2.0").await.unwrap();
        let err = server_handshake(b, &server_key, server_hello(), |_, _| Ok(Accept::Normal))
            .await
            .unwrap_err();
        assert!(matches!(err, HandshakeError::BadMagic));
    }

    #[tokio::test]
    async fn newer_server_version_is_rejected_by_client() {
        let client_key = SecretKey::generate();
        let (a, mut b) = tokio::io::duplex(64);
        let client = client_handshake(a, &client_key, 0, |_, _| Ok(()), ClientAuth::Static);
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

    // ---- signature authentication ----

    use ed25519_dalek::Signer as _;
    use rand_core::RngCore as _;

    fn sig_server_hello() -> ServerHello {
        ServerHello {
            name: "testhost".into(),
            caps: caps::SIG_AUTH,
        }
    }

    fn ed25519_keypair() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Signs with a local key and remembers the last signature.
    struct LocalSigner {
        key: ed25519_dalek::SigningKey,
        last: Option<[u8; 64]>,
    }

    impl Signer for LocalSigner {
        fn sign<'a>(
            &'a mut self,
            message: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<[u8; 64]>> + Send + 'a>> {
            Box::pin(async move {
                assert!(message.starts_with(SIG_AUTH_LABEL));
                assert_eq!(message.len(), SIG_AUTH_LABEL.len() + 32);
                let sig = self.key.sign(message).to_bytes();
                self.last = Some(sig);
                Ok(sig)
            })
        }
    }

    /// Returns a canned signature regardless of the message.
    struct FixedSigner([u8; 64]);

    impl Signer for FixedSigner {
        fn sign<'a>(
            &'a mut self,
            _message: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<[u8; 64]>> + Send + 'a>> {
            let sig = self.0;
            Box::pin(async move { Ok(sig) })
        }
    }

    #[tokio::test]
    async fn sig_auth_happy_path() {
        let (sk, pk) = ed25519_keypair();
        let mut signer = LocalSigner {
            key: sk,
            last: None,
        };
        let ephemeral = SecretKey::generate();
        let ephemeral_pk = ephemeral.public();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(
            a,
            &ephemeral,
            0,
            |_, hello| {
                assert_eq!(hello.caps, caps::SIG_AUTH);
                Ok(())
            },
            ClientAuth::Ed25519 {
                public: pk,
                sign: &mut signer,
            },
        );
        let server = server_handshake(b, &server_key, sig_server_hello(), |peer, hello| {
            assert_eq!(*peer, Peer::Ed25519(pk));
            assert_eq!(peer.kind(), "ssh-ed25519");
            assert!(matches!(
                hello.auth,
                AuthProof::Ed25519 { public_key, .. } if public_key == pk
            ));
            Ok(Accept::Normal)
        });
        let (client, server) = tokio::join!(client, server);
        let (mut client, _) = client.unwrap();
        let mut server = server.unwrap();
        assert_eq!(server.peer, Peer::Ed25519(pk));
        assert_eq!(server.remote, ephemeral_pk);
        assert_eq!(server.peer.fingerprint(), Fingerprint::of_ssh_ed25519(&pk));
        assert!(signer.last.is_some());

        client.stream.write_all(b"ping").await.unwrap();
        client.stream.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn sig_auth_wrong_signature_is_unauthorized() {
        let (_, pk) = ed25519_keypair();
        let mut signer = FixedSigner([7u8; 64]);
        let ephemeral = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(
            a,
            &ephemeral,
            0,
            |_, _| Ok(()),
            ClientAuth::Ed25519 {
                public: pk,
                sign: &mut signer,
            },
        );
        let server = server_handshake(b, &server_key, sig_server_hello(), |_, _| {
            panic!("authorize must not run for a bad proof")
        });
        let (client, server) = tokio::join!(client, server);
        match client {
            Err(HandshakeError::Denied { code, message }) => {
                assert_eq!(code, ErrorCode::Unauthorized);
                assert_eq!(message, "bad signature");
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
    async fn sig_auth_requires_server_cap() {
        let (sk, pk) = ed25519_keypair();
        let mut signer = LocalSigner {
            key: sk,
            last: None,
        };
        let ephemeral = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(
            a,
            &ephemeral,
            0,
            |_, _| Ok(()),
            ClientAuth::Ed25519 {
                public: pk,
                sign: &mut signer,
            },
        );
        let server = server_handshake(b, &server_key, server_hello(), |_, _| {
            panic!("authorize must not run when the client never sends msg3")
        });
        let (client, server) = tokio::join!(client, server);
        assert!(matches!(client, Err(HandshakeError::SigAuthUnsupported)));
        match server {
            Err(HandshakeError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("unexpected server result: {other:?}"),
        }
        assert!(signer.last.is_none(), "nothing must be signed");
    }

    #[tokio::test]
    async fn static_proof_with_sig_auth_server_stays_static() {
        let client_key = SecretKey::generate();
        let client_pk = client_key.public();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);

        let client = client_handshake(a, &client_key, 0, |_, _| Ok(()), ClientAuth::Static);
        let server = server_handshake(b, &server_key, sig_server_hello(), |peer, hello| {
            assert_eq!(*peer, Peer::Static(client_pk));
            assert_eq!(hello.auth, AuthProof::Static);
            Ok(Accept::Normal)
        });
        let (client, server) = tokio::join!(client, server);
        client.unwrap();
        let server = server.unwrap();
        assert_eq!(server.peer, Peer::Static(client_pk));
        assert_eq!(server.peer.kind(), "x25519");
    }

    #[tokio::test]
    async fn replayed_signature_is_rejected() {
        let (sk, pk) = ed25519_keypair();
        let server_key = SecretKey::generate();

        // First connection: genuine, record the signature.
        let mut signer = LocalSigner {
            key: sk,
            last: None,
        };
        let ephemeral = SecretKey::generate();
        let (a, b) = tokio::io::duplex(4096);
        let client = client_handshake(
            a,
            &ephemeral,
            0,
            |_, _| Ok(()),
            ClientAuth::Ed25519 {
                public: pk,
                sign: &mut signer,
            },
        );
        let server = server_handshake(b, &server_key, sig_server_hello(), |_, _| {
            Ok(Accept::Normal)
        });
        let (client, server) = tokio::join!(client, server);
        client.unwrap();
        server.unwrap();
        let recorded = signer.last.expect("first handshake signed");

        // Second connection: replay it (same static, same server, fresh
        // ephemerals → different h2).
        let mut replay = FixedSigner(recorded);
        let (a, b) = tokio::io::duplex(4096);
        let client = client_handshake(
            a,
            &ephemeral,
            0,
            |_, _| Ok(()),
            ClientAuth::Ed25519 {
                public: pk,
                sign: &mut replay,
            },
        );
        let server = server_handshake(b, &server_key, sig_server_hello(), |_, _| {
            panic!("authorize must not run for a replayed proof")
        });
        let (client, server) = tokio::join!(client, server);
        assert!(matches!(
            client,
            Err(HandshakeError::Denied {
                code: ErrorCode::Unauthorized,
                ..
            })
        ));
        assert!(matches!(
            server,
            Err(HandshakeError::Denied {
                code: ErrorCode::Unauthorized,
                ..
            })
        ));
    }

    /// A non-conforming client that sends a valid proof even though the
    /// server did not advertise `SIG_AUTH` is refused as `Unsupported`.
    #[tokio::test]
    async fn proof_to_disabled_server_is_unsupported() {
        let (sk, pk) = ed25519_keypair();
        let ephemeral = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (mut a, b) = tokio::io::duplex(4096);

        let rogue_client = async move {
            a.write_all(&preamble(PROTOCOL_VERSION)).await.unwrap();
            let mut bytes = [0u8; PREAMBLE_LEN];
            a.read_exact(&mut bytes).await.unwrap();
            let version = parse_preamble(bytes).unwrap();
            let prologue = prologue(version);
            let mut hs = builder(&ephemeral, &prologue)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut buf = Buffers::new();
            buf.send(&mut a, &mut hs, &[]).await.unwrap();
            buf.recv(&mut a, &mut hs).await.unwrap();
            let signature = sk.sign(&sig_message(hs.get_handshake_hash())).to_vec();
            let hello = ClientHello {
                caps: 0,
                auth: AuthProof::Ed25519 {
                    public_key: pk,
                    signature,
                },
            };
            buf.send(&mut a, &mut hs, &encode(&hello).unwrap())
                .await
                .unwrap();
            let mut stream = NoiseStream::new(a, hs.into_stateless_transport_mode().unwrap());
            framing::read_msg::<_, Verdict>(&mut stream).await.unwrap()
        };
        let server = server_handshake(b, &server_key, server_hello(), |_, _| {
            panic!("authorize must not run when signature auth is disabled")
        });
        let (verdict, server) = tokio::join!(rogue_client, server);
        assert_eq!(
            verdict,
            Verdict::Denied {
                code: ErrorCode::Unsupported,
                message: "signature authentication is disabled".into()
            }
        );
        assert!(matches!(
            server,
            Err(HandshakeError::Denied {
                code: ErrorCode::Unsupported,
                ..
            })
        ));
    }
}
