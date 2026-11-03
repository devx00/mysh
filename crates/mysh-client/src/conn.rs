//! One client connection: dial, server-trust check, Noise handshake, the
//! control stream (pings, notices, shutdown) and the acceptor for streams
//! the server opens (`ForwardedTcp`). See docs/03-protocol.md §1–§6 and
//! docs/02-security.md "Server trust (client)".
//!
//! TOFU is a two-step dance because the handshake's `verify_server` callback
//! is synchronous: an unknown key is reported out of the callback as
//! `TrustError::Unknown` (the handshake aborts without revealing our
//! identity), the caller's [`TrustPrompt`] is asked, and on `yes` the key
//! is appended to `known_hosts` and we dial again — the second handshake
//! then sees a known key.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_net::{
    agent::{Agent, AgentKey},
    framing::{read_msg, write_msg, write_reply},
    handshake::{ClientAuth, HandshakeError, Handshaken, Signer, client_handshake},
    keys::{Fingerprint, PublicKey, SecretKey},
    mux::{Incoming, Mode, Mux, OpenError, Stream, accept_open},
    noise::TransferStats,
    trust::KnownHosts,
};
use mysh_proto::{
    control::ControlMsg,
    handshake::ServerHello,
    limits,
    open::{ErrorCode, Open, OpenReply},
};
use portable_atomic::AtomicU64;
use tokio::{
    io::{AsyncWriteExt as _, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{
    config::{Paths, Target},
    identity::{
        Baked, Caller, Callers, ClientIdentity, ClientTrust, TrustDecision, client_identities,
    },
    report::{Reporter, TrustPrompt},
    types::{ConnectionOut, Event, code_name, coded, codes, millis},
};

/// Per-address TCP connect budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Client-side bound on the whole handshake (the server allows 5 s).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long [`Connection::bind`] waits for the server's answer.
const BIND_TIMEOUT: Duration = Duration::from_secs(10);

/// Handler for `Open::ForwardedTcp` streams; must answer the `OpenReply`
/// itself (registered by `client::forward::Forwards`).
pub type ForwardedHandler = Box<dyn Fn(Stream, u32, String) + Send + Sync>;

/// Why the server key was refused inside the handshake callback.
#[derive(Debug)]
enum TrustError {
    /// Loud, no bypass.
    Mismatch {
        source: String,
        line: usize,
        expected: Fingerprint,
        actual: Fingerprint,
    },
    /// Not known anywhere; carries the key so the caller can ask the user.
    Unknown { key: PublicKey },
    /// Not known and `--strict`.
    Strict { actual: Fingerprint },
    /// An inbound connection from a server that is not in the callers file.
    NotACaller { actual: Fingerprint },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch {
                source,
                line,
                expected,
                actual,
            } => write!(
                f,
                "server key mismatch (recorded in {source} line {line}: expected {expected}, got {actual})"
            ),
            Self::Unknown { key } => {
                write!(f, "server key {} is not known", key.fingerprint())
            }
            Self::Strict { actual } => write!(f, "server key {actual} is not known (--strict)"),
            Self::NotACaller { actual } => {
                write!(
                    f,
                    "server key {actual} is not a caller (not in the callers file)"
                )
            }
        }
    }
}

impl std::error::Error for TrustError {}

struct Inner {
    mux: Mux,
    target: Target,
    hello: ServerHello,
    remote: PublicKey,
    via: String,
    identity: ClientIdentity,
    connected_at: Instant,
    version: u16,
    peer_addr: SocketAddr,
    control: mpsc::Sender<ControlMsg>,
    pending: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    next_nonce: AtomicU64,
    last_rtt: Mutex<Option<Duration>>,
    /// `Some(reason)` once the connection is gone.
    closed: watch::Sender<Option<String>>,
    /// The `bind` request waiting for `Bound`/`Unbound`.
    bind_waiter: Mutex<Option<oneshot::Sender<Result<String, String>>>>,
    handler: Mutex<Option<ForwardedHandler>>,
    reporter: Arc<dyn Reporter>,
}

/// Handle to a live connection; cheap to clone.
#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("target", &self.inner.target.display)
            .field("peer", &self.inner.peer_addr)
            .field("remote", &self.inner.remote.fingerprint())
            .field("via", &self.inner.via)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// The stream multiplexer underneath.
    pub fn mux(&self) -> &Mux {
        &self.inner.mux
    }

    /// What was connected to.
    pub fn target(&self) -> &Target {
        &self.inner.target
    }

    /// The server's hello (capabilities, limits).
    pub fn server_hello(&self) -> &ServerHello {
        &self.inner.hello
    }

    /// The server's static key.
    pub fn remote_key(&self) -> PublicKey {
        self.inner.remote
    }

    /// The reporter this connection surfaces notices to.
    pub fn reporter(&self) -> &Arc<dyn Reporter> {
        &self.inner.reporter
    }

    /// How the server key was trusted (`pin`, `baked`, a `known_hosts` file…).
    pub fn trusted_via(&self) -> &str {
        &self.inner.via
    }

    /// The identity the server accepted.
    pub fn identity(&self) -> &ClientIdentity {
        &self.inner.identity
    }

    /// Fingerprint of the identity the server accepted.
    pub fn identity_fingerprint(&self) -> Fingerprint {
        self.inner.identity.fingerprint()
    }

    /// Our public key as an `authorized_keys` line (for `authorize`).
    pub fn identity_line(&self) -> String {
        self.inner.identity.public_line()
    }

    /// When the handshake completed.
    pub fn connected_at(&self) -> Instant {
        self.inner.connected_at
    }

    /// Negotiated protocol version.
    pub fn version(&self) -> u16 {
        self.inner.version
    }

    /// The server's socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr
    }

    /// Round trip of the most recent ping (keep-alive or `ping`).
    pub fn last_rtt(&self) -> Option<Duration> {
        self.inner.last_rtt.lock().ok().and_then(|r| *r)
    }

    /// Open a stream of kind `open`.
    pub async fn open(&self, open: &Open) -> Result<Stream, OpenError> {
        self.inner.mux.open(open).await
    }

    /// One control-stream round trip.
    pub async fn ping(&self) -> Result<Duration> {
        let nonce = self.inner.next_nonce.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.inner
            .pending
            .lock()
            .map_err(|_| anyhow!("ping table poisoned"))?
            .insert(nonce, tx);
        let start = Instant::now();
        let sent = self.inner.control.send(ControlMsg::Ping { nonce }).await;
        if sent.is_err() {
            self.forget_ping(nonce);
            bail!("connection closed");
        }
        match timeout(limits::PING_INTERVAL, rx).await {
            Ok(Ok(())) => {
                let rtt = start.elapsed();
                if let Ok(mut last) = self.inner.last_rtt.lock() {
                    *last = Some(rtt);
                }
                Ok(rtt)
            }
            Ok(Err(_)) => {
                self.forget_ping(nonce);
                bail!("connection closed")
            }
            Err(_) => {
                self.forget_ping(nonce);
                bail!("ping timed out")
            }
        }
    }

    fn forget_ping(&self, nonce: u64) {
        if let Ok(mut p) = self.inner.pending.lock() {
            p.remove(&nonce);
        }
    }

    /// Ask the server for the cwd of session `session`'s foreground process
    /// (docs/03-protocol.md §10). `None` on any failure.
    pub async fn cwd_probe(&self, session: u32) -> Option<String> {
        let mut stream = match self.open(&Open::Cwd { session }).await {
            Ok(s) => s,
            Err(e) => {
                debug!(session, error = %e, "cwd probe refused");
                return None;
            }
        };
        match timeout(
            limits::OPEN_REPLY_DEADLINE,
            read_msg::<_, Option<String>>(&mut stream),
        )
        .await
        {
            Ok(Ok(cwd)) => cwd,
            Ok(Err(e)) => {
                debug!(session, error = %e, "cwd probe failed");
                None
            }
            Err(_) => {
                debug!(session, "cwd probe timed out");
                None
            }
        }
    }

    /// Bytes in and out on the encrypted transport.
    pub fn stats(&self) -> TransferStats {
        self.inner.mux.stats()
    }

    /// `Open::Info`; `None` when the server does not implement it.
    pub async fn info(&self) -> Result<Option<mysh_proto::info::Info>> {
        match self.open(&Open::Info).await {
            Ok(mut stream) => Ok(Some(
                read_msg(&mut stream).await.context("reading server info")?,
            )),
            Err(OpenError::Rejected {
                code: ErrorCode::Unsupported,
                ..
            }) => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context("server info")),
        }
    }

    /// The connection's facts for `info` (`InfoOut::connection`).
    pub fn connection_out(&self) -> ConnectionOut {
        let stats = self.stats();
        ConnectionOut {
            host: self.target().host.clone(),
            port: self.target().port,
            peer: self.peer_addr().to_string(),
            peer_fingerprint: self.remote_key().fingerprint().to_string(),
            trusted_via: self.trusted_via().to_owned(),
            our_key: self.identity().describe(),
            protocol: self.version(),
            cipher: mysh_proto::NOISE_PATTERN.to_owned(),
            connected_secs: self.connected_at().elapsed().as_secs(),
            rtt_ms: self.last_rtt().map(millis),
            bytes_in: stats.bytes_in,
            bytes_out: stats.bytes_out,
            rekeys: stats.rekeys_in + stats.rekeys_out,
        }
    }

    /// Register the handler for server-opened `ForwardedTcp` streams.
    pub fn set_forwarded_handler(&self, handler: ForwardedHandler) {
        if let Ok(mut h) = self.inner.handler.lock() {
            *h = Some(handler);
        }
    }

    /// Whether the connection has ended (peer closed, ping timeout,
    /// shutdown notice, or [`Connection::close`]).
    pub fn is_closed(&self) -> bool {
        self.inner.closed.borrow().is_some()
    }

    /// Why the connection ended, once it has.
    pub fn close_reason(&self) -> Option<String> {
        self.inner.closed.borrow().clone()
    }

    /// Resolves once the connection has ended.
    pub async fn closed(&self) {
        let mut rx = self.inner.closed.subscribe();
        let _ = rx.wait_for(std::option::Option::is_some).await;
    }

    /// Ask the server to bind a listener at `addr` for ordinary clients to
    /// dial (docs/03-protocol.md §6 "Bind on request"); `idle` closes it
    /// after that long without an accepted connection (zero: until
    /// [`Connection::unbind`] or the server exits). Returns the bound
    /// address; a refusal carries the `denied` code.
    pub async fn bind(&self, addr: &str, idle: Duration) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        {
            let mut waiter = self
                .inner
                .bind_waiter
                .lock()
                .map_err(|_| anyhow!("bind table poisoned"))?;
            if waiter.is_some() {
                bail!("a bind request is already in flight");
            }
            *waiter = Some(tx);
        }
        let idle_secs = u32::try_from(idle.as_secs()).unwrap_or(u32::MAX);
        let sent = self
            .inner
            .control
            .send(ControlMsg::Bind {
                addr: addr.to_owned(),
                idle_secs,
            })
            .await;
        if sent.is_err() {
            self.forget_bind();
            bail!("connection closed");
        }
        match timeout(BIND_TIMEOUT, rx).await {
            Ok(Ok(Ok(bound))) => Ok(bound),
            Ok(Ok(Err(reason))) => Err(coded(
                codes::DENIED,
                anyhow!("bind {addr}: server refused: {reason}"),
            )),
            Ok(Err(_)) => {
                self.forget_bind();
                bail!("connection closed")
            }
            Err(_) => {
                self.forget_bind();
                bail!("bind {addr}: no answer from the server")
            }
        }
    }

    fn forget_bind(&self) {
        if let Ok(mut w) = self.inner.bind_waiter.lock() {
            *w = None;
        }
    }

    /// Close the listener a [`Connection::bind`] opened.
    pub async fn unbind(&self) -> Result<()> {
        self.inner
            .control
            .send(ControlMsg::Unbind)
            .await
            .map_err(|_| anyhow!("connection closed"))
    }

    /// Graceful close: tell the server, close the mux, wait for the driver.
    pub async fn close(&self) {
        let _ = timeout(
            Duration::from_secs(1),
            self.inner.control.send(ControlMsg::Shutdown {
                reason: "client exiting".to_owned(),
            }),
        )
        .await;
        self.inner.mux.close().await;
        self.inner.mark_closed("closed by client");
    }
}

impl Inner {
    fn mark_closed(&self, reason: &str) {
        self.closed.send_if_modified(|c| {
            if c.is_some() {
                false
            } else {
                *c = Some(reason.to_owned());
                true
            }
        });
    }
}

/// Resolve and dial `host:port`, trying each address in order. Failures
/// carry the `connect_failed` code.
pub(crate) async fn dial(host: &str, port: u16) -> Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            return Err(coded(
                codes::CONNECT_FAILED,
                anyhow::Error::from(e).context(format!("resolving {host}")),
            ));
        }
    };
    if addrs.is_empty() {
        return Err(coded(
            codes::CONNECT_FAILED,
            anyhow!("{host}: no addresses"),
        ));
    }
    let mut last: Option<anyhow::Error> = None;
    for addr in addrs {
        debug!(%addr, "connecting");
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true).context("TCP_NODELAY")?;
                return Ok(stream);
            }
            Ok(Err(e)) => last = Some(anyhow!("{addr}: {e}")),
            Err(_) => last = Some(anyhow!("{addr}: connect timed out")),
        }
    }
    Err(coded(
        codes::CONNECT_FAILED,
        last.unwrap_or_else(|| anyhow!("{host}:{port}: connect failed")),
    ))
}

/// Outcome of one handshake attempt.
enum Attempt {
    Done(Box<AttemptDone>),
    /// Unknown key; ask the user.
    Unknown(PublicKey),
    /// `Denied { Unauthorized }` with the server's message; try the next
    /// identity.
    Refused(String),
    /// The server does not advertise `caps::SIG_AUTH`; agent identities
    /// cannot be used against it. Nothing identifying was sent.
    SigAuthUnsupported,
}

struct AttemptDone {
    handshaken: Handshaken<TcpStream>,
    hello: ServerHello,
    via: String,
}

/// [`Signer`] backed by one `ssh-agent` key: the agent signs
/// `SIG_AUTH_LABEL ‖ h2`; the private key never leaves it.
#[derive(Debug)]
pub(crate) struct AgentSigner {
    agent: Agent,
    key: AgentKey,
}

impl AgentSigner {
    pub(crate) async fn connect(socket: &Path, key: AgentKey) -> Result<Self> {
        let agent = Agent::connect(socket)
            .await
            .with_context(|| format!("connecting to ssh-agent at {}", socket.display()))?;
        Ok(Self { agent, key })
    }
}

impl Signer for AgentSigner {
    fn sign<'a>(
        &'a mut self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<[u8; 64]>> + Send + 'a>> {
        Box::pin(self.agent.sign(&self.key, message))
    }
}

/// Per-connection Noise material for an identity: a key file is the static
/// itself; an agent key gets a fresh static and proves itself by signature.
enum Material<'a> {
    Static(&'a SecretKey),
    Agent {
        fresh: SecretKey,
        public: [u8; 32],
        signer: AgentSigner,
    },
}

impl<'a> Material<'a> {
    async fn for_identity(identity: &'a ClientIdentity) -> Result<Self> {
        Ok(match identity {
            ClientIdentity::Static(id) => Self::Static(&id.secret),
            ClientIdentity::Agent { socket, key } => Self::Agent {
                fresh: SecretKey::generate(),
                public: key.public,
                signer: AgentSigner::connect(socket, key.clone()).await?,
            },
        })
    }

    fn parts(&mut self) -> (&SecretKey, ClientAuth<'_>) {
        match self {
            Self::Static(secret) => (secret, ClientAuth::Static),
            Self::Agent {
                fresh,
                public,
                signer,
            } => (
                fresh,
                ClientAuth::Ed25519 {
                    public: *public,
                    sign: signer,
                },
            ),
        }
    }
}

/// Turn an inbound TCP connection from a server in connect-back mode into
/// a [`Connection`] (docs/02-security.md "Callers"): the client is still
/// the Noise initiator; the server's key is looked up in `callers` by
/// fingerprint (its address means nothing), and with `accept_new` an
/// unknown key is recorded there first. A key that is neither is refused
/// with `trust_unknown` before our identity is revealed, and reported as
/// an [`Event::Refused`].
///
/// The caller bounds the handshake; this function does not.
pub async fn accept_connection(
    stream: TcpStream,
    identity: &ClientIdentity,
    callers: &Callers,
    accept_new: bool,
    reporter: Arc<dyn Reporter>,
) -> Result<(Connection, Caller)> {
    let peer = stream.peer_addr().context("peer address")?;
    let mut material = Material::for_identity(identity).await?;
    let (static_key, auth) = material.parts();
    let mut matched: Option<Caller> = None;
    let verify = |key: &PublicKey,
                  _hello: &ServerHello|
     -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(caller) = callers.lookup(key) {
            matched = Some(caller);
            return Ok(());
        }
        if accept_new {
            let caller = callers.record(key)?;
            info!(fingerprint = %key.fingerprint(), path = %callers.path().display(), "accepted new caller");
            matched = Some(caller);
            return Ok(());
        }
        Err(Box::new(TrustError::NotACaller {
            actual: key.fingerprint(),
        }))
    };
    let result = client_handshake(stream, static_key, 0, verify, auth).await;
    let (handshaken, hello) = match result {
        Ok(done) => done,
        Err(HandshakeError::Trust(err)) => {
            let fingerprint = match err.downcast_ref::<TrustError>() {
                Some(TrustError::NotACaller { actual }) => actual.to_string(),
                _ => String::new(),
            };
            let reason = err.to_string();
            warn!(peer = %peer, %fingerprint, %reason, "inbound connection refused");
            reporter.event(&Event::Refused {
                fingerprint,
                addr: peer.to_string(),
                reason: reason.clone(),
            });
            return Err(coded(
                codes::TRUST_UNKNOWN,
                anyhow!("inbound connection from {peer} refused: {reason}"),
            ));
        }
        Err(HandshakeError::Denied { code, message }) => {
            return Err(coded(
                code_name(code),
                anyhow!("server at {peer} refused our identity: {code}: {message}"),
            ));
        }
        Err(e) => return Err(e).with_context(|| format!("handshake with {peer} failed")),
    };
    let caller = matched.ok_or_else(|| anyhow!("handshake completed without a caller match"))?;
    let conn = establish(
        Target::accepted(&caller.label()),
        identity.clone(),
        handshaken,
        hello,
        caller.via.clone(),
        reporter,
    )
    .await?;
    Ok((conn, caller))
}

async fn attempt(
    target: &Target,
    identity: &ClientIdentity,
    trust: &ClientTrust,
) -> Result<Attempt> {
    let mut material = Material::for_identity(identity).await?;
    let (static_key, auth) = material.parts();
    let tcp = dial(&target.host, target.port).await?;
    let mut via = String::new();
    let verify = |key: &PublicKey,
                  _hello: &ServerHello|
     -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match trust.evaluate(&target.host, target.port, key) {
            TrustDecision::Trusted { via: v } => {
                via = v;
                Ok(())
            }
            TrustDecision::Mismatch {
                source,
                line,
                expected,
            } => Err(Box::new(TrustError::Mismatch {
                source,
                line,
                expected,
                actual: key.fingerprint(),
            })),
            TrustDecision::Unknown if trust.strict => Err(Box::new(TrustError::Strict {
                actual: key.fingerprint(),
            })),
            TrustDecision::Unknown if trust.accept_new => {
                KnownHosts::append(&trust.write_to, &target.host, target.port, key)?;
                info!(fingerprint = %key.fingerprint(), path = %trust.write_to.display(), "accepted new server key");
                "accept-new".clone_into(&mut via);
                Ok(())
            }
            TrustDecision::Unknown => Err(Box::new(TrustError::Unknown { key: *key })),
        }
    };
    let result = timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake(tcp, static_key, 0, verify, auth),
    )
    .await;
    match result {
        Ok(Ok((handshaken, hello))) => Ok(Attempt::Done(Box::new(AttemptDone {
            handshaken,
            hello,
            via,
        }))),
        Ok(Err(HandshakeError::Trust(err))) => match err.downcast::<TrustError>() {
            Ok(trust_err) => match *trust_err {
                TrustError::Unknown { key } => Ok(Attempt::Unknown(key)),
                TrustError::Mismatch {
                    source,
                    line,
                    expected,
                    actual,
                } => Err(coded(
                    codes::TRUST_MISMATCH,
                    mismatch_error(target, &source, line, &expected, &actual),
                )),
                other @ (TrustError::Strict { .. } | TrustError::NotACaller { .. }) => {
                    Err(coded(codes::TRUST_UNKNOWN, anyhow!("{other}")))
                }
            },
            Err(other) => Err(anyhow!("server not trusted: {other}")),
        },
        Ok(Err(HandshakeError::Denied {
            code: ErrorCode::Unauthorized,
            message,
        })) => Ok(Attempt::Refused(message)),
        Ok(Err(HandshakeError::SigAuthUnsupported)) => Ok(Attempt::SigAuthUnsupported),
        Ok(Err(HandshakeError::Denied { code, message })) => Err(coded(
            code_name(code),
            anyhow!("server refused the connection: {code}: {message}"),
        )),
        Ok(Err(e)) => {
            Err(e).with_context(|| format!("handshake with {}:{} failed", target.host, target.port))
        }
        Err(_) => Err(coded(
            codes::CONNECT_FAILED,
            anyhow!("handshake with {}:{} timed out", target.host, target.port),
        )),
    }
}

fn mismatch_error(
    target: &Target,
    source: &str,
    line: usize,
    expected: &Fingerprint,
    actual: &Fingerprint,
) -> anyhow::Error {
    anyhow!(
        "\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
The key presented by {host}:{port} does not match the one recorded in\n\
  {source}, line {line}\n\
expected: {expected}\n\
actual:   {actual}\n\
Someone could be eavesdropping on you right now, or the server's key was\n\
replaced. There is no bypass flag: if the change is legitimate, remove or\n\
fix that entry and connect again.",
        host = target.host,
        port = target.port,
    )
}

/// Accept an unknown server key: `--accept-new` is handled inside the
/// handshake callback, so reaching here means the [`TrustPrompt`] decides.
/// Returns after the key is appended; the caller reconnects.
fn accept_unknown(
    target: &Target,
    trust: &ClientTrust,
    key: PublicKey,
    reporter: &dyn Reporter,
    prompt: &dyn TrustPrompt,
) -> Result<()> {
    if !prompt.confirm_unknown(&target.host, target.port, &key.fingerprint()) {
        return Err(coded(
            codes::TRUST_UNKNOWN,
            anyhow!(
                "host key verification failed: {}:{} is not in known_hosts (key {}); \
                 use --accept-new or add it to {}",
                target.host,
                target.port,
                key.fingerprint(),
                trust.write_to.display()
            ),
        ));
    }
    KnownHosts::append(&trust.write_to, &target.host, target.port, &key)
        .with_context(|| format!("writing {}", trust.write_to.display()))?;
    reporter.println(&format!(
        "Warning: permanently added {}:{} ({}) to {}.",
        target.host,
        target.port,
        key.fingerprint(),
        trust.write_to.display()
    ));
    Ok(())
}

/// Resolve the identities, verify the server, and handshake with each
/// identity in turn until one is accepted; then start the connection
/// tasks. Only `Denied { Unauthorized }` moves on to the next identity; a
/// server without signature authentication ends the agent attempts.
///
/// `reporter` receives server notices for the life of the connection;
/// `prompt` decides about an unknown server key and supplies key
/// passphrases.
pub async fn connect(
    target: &Target,
    paths: &Paths,
    baked: &Baked,
    reporter: Arc<dyn Reporter>,
    prompt: &dyn TrustPrompt,
) -> Result<Connection> {
    if target.via_socket_only {
        return Err(coded(
            codes::CONNECT_FAILED,
            anyhow!(
                "no accepted connection named {} (is `mysh accept` running?)",
                target.host.trim_start_matches('@')
            ),
        ));
    }
    let identities = client_identities(target, paths, baked, &mut |source| {
        prompt.passphrase(source)
    })
    .await?;
    let trust = ClientTrust::for_target(target, paths, baked)?;
    let mut accepted: Option<PublicKey> = None;
    let mut refused: Vec<String> = Vec::new();
    let mut last_message = String::new();
    let mut agent_unsupported = false;
    for identity in &identities {
        if agent_unsupported && matches!(identity, ClientIdentity::Agent { .. }) {
            continue;
        }
        loop {
            match attempt(target, identity, &trust).await? {
                Attempt::Done(done) => {
                    let AttemptDone {
                        handshaken,
                        hello,
                        via,
                    } = *done;
                    return establish(
                        target.clone(),
                        identity.clone(),
                        handshaken,
                        hello,
                        via,
                        reporter,
                    )
                    .await;
                }
                Attempt::Unknown(key) => {
                    if accepted == Some(key) {
                        bail!(
                            "server key {} still unknown after accepting it",
                            key.fingerprint()
                        );
                    }
                    accept_unknown(target, &trust, key, reporter.as_ref(), prompt)?;
                    accepted = Some(key);
                    // Reconnect: the aborted handshake never sent our
                    // identity, and `evaluate` re-reads known_hosts, so the
                    // next attempt finds the key.
                }
                Attempt::Refused(message) => {
                    debug!(identity = %identity.describe(), %message, "identity refused");
                    refused.push(identity.describe());
                    last_message = message;
                    break;
                }
                Attempt::SigAuthUnsupported => {
                    let agent_keys = identities
                        .iter()
                        .filter(|i| matches!(i, ClientIdentity::Agent { .. }))
                        .count();
                    warn!(
                        server = %format_args!("{}:{}", target.host, target.port),
                        agent_keys,
                        "server does not support agent keys (signature authentication is disabled); skipping them"
                    );
                    agent_unsupported = true;
                    break;
                }
            }
        }
    }
    let agent_note = if agent_unsupported {
        "; the server does not support agent keys (signature authentication is disabled), use a key file"
    } else {
        ""
    };
    let err = match refused.as_slice() {
        [] => anyhow!(
            "no usable identity for {}:{}{agent_note}",
            target.host,
            target.port
        ),
        [only] => anyhow!("server refused our key {only}: {last_message}{agent_note}"),
        many => anyhow!(
            "server refused every identity: {last_message} (tried {}){agent_note}",
            many.join(", ")
        ),
    };
    Err(coded(codes::UNAUTHORIZED, err))
}

async fn establish(
    target: Target,
    identity: ClientIdentity,
    handshaken: Handshaken<TcpStream>,
    hello: ServerHello,
    via: String,
    reporter: Arc<dyn Reporter>,
) -> Result<Connection> {
    let Handshaken {
        stream,
        remote,
        peer: _,
        version,
        pairing: _,
    } = handshaken;
    let peer_addr = stream.get_ref().peer_addr().context("peer address")?;
    info!(
        peer = %peer_addr,
        fingerprint = %remote.fingerprint(),
        via,
        version,
        identity = %identity.describe(),
        "connected"
    );
    let (mux, incoming) = Mux::new(stream, Mode::Client);
    let (control_tx, control_rx) = mpsc::channel(32);
    let (closed, _) = watch::channel(None);
    let inner = Arc::new(Inner {
        mux,
        target,
        hello,
        remote,
        via,
        identity,
        connected_at: Instant::now(),
        version,
        peer_addr,
        control: control_tx,
        pending: Mutex::new(HashMap::new()),
        next_nonce: AtomicU64::new(1),
        last_rtt: Mutex::new(None),
        closed,
        bind_waiter: Mutex::new(None),
        handler: Mutex::new(None),
        reporter,
    });
    let conn = Connection { inner };
    // The server requires the first stream to be Control; open and get it
    // acknowledged before anyone can `open()` another stream on this
    // connection.
    let control = conn
        .inner
        .mux
        .open(&Open::Control)
        .await
        .context("opening control stream")?;
    start_control(conn.clone(), control, control_rx);
    tokio::spawn(acceptor(conn.clone(), incoming));
    tokio::spawn({
        let conn = conn.clone();
        async move {
            conn.inner.mux.closed().await;
            conn.inner.mark_closed("connection closed");
        }
    });
    Ok(conn)
}

/// Run the control stream's reader, writer and the pinger.
fn start_control(conn: Connection, stream: Stream, control_rx: mpsc::Receiver<ControlMsg>) {
    let (rd, wr) = tokio::io::split(stream);
    tokio::spawn(control_writer(wr, control_rx));
    tokio::spawn(control_reader(conn.clone(), rd));
    tokio::spawn(pinger(conn));
}

async fn control_writer(mut wr: WriteHalf<Stream>, mut rx: mpsc::Receiver<ControlMsg>) {
    while let Some(msg) = rx.recv().await {
        let shutdown = matches!(msg, ControlMsg::Shutdown { .. });
        if let Err(e) = write_msg(&mut wr, &msg).await {
            debug!(error = %e, "control write failed");
            break;
        }
        if shutdown {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

async fn control_reader(conn: Connection, mut rd: ReadHalf<Stream>) {
    loop {
        match read_msg::<_, ControlMsg>(&mut rd).await {
            Ok(ControlMsg::Pong { nonce }) => {
                let waiter = conn
                    .inner
                    .pending
                    .lock()
                    .ok()
                    .and_then(|mut p| p.remove(&nonce));
                if let Some(tx) = waiter {
                    let _ = tx.send(());
                }
            }
            Ok(ControlMsg::Ping { nonce }) => {
                if conn
                    .inner
                    .control
                    .send(ControlMsg::Pong { nonce })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(ControlMsg::Notice(text)) => conn.inner.reporter.notice(&format!("server: {text}")),
            Ok(ControlMsg::Bound { addr }) => {
                let waiter = conn
                    .inner
                    .bind_waiter
                    .lock()
                    .ok()
                    .and_then(|mut w| w.take());
                match waiter {
                    Some(tx) => {
                        let _ = tx.send(Ok(addr));
                    }
                    None => conn
                        .inner
                        .reporter
                        .notice(&format!("server: listener bound at {addr}")),
                }
            }
            Ok(ControlMsg::Unbound { addr, reason }) => {
                let waiter = conn
                    .inner
                    .bind_waiter
                    .lock()
                    .ok()
                    .and_then(|mut w| w.take());
                match waiter {
                    Some(tx) => {
                        let _ = tx.send(Err(reason));
                    }
                    None => conn
                        .inner
                        .reporter
                        .notice(&format!("server: listener {addr} closed: {reason}")),
                }
            }
            // Client → server messages; a server never sends them.
            Ok(ControlMsg::Bind { .. } | ControlMsg::Unbind) => {}
            Ok(ControlMsg::Shutdown { reason }) => {
                conn.inner
                    .mark_closed(&format!("server shutting down: {reason}"));
                conn.inner.mux.close().await;
                break;
            }
            Err(e) => {
                debug!(error = %e, "control stream ended");
                if !conn.is_closed() {
                    conn.inner.mark_closed("control stream closed");
                    conn.inner.mux.close().await;
                }
                break;
            }
        }
    }
}

/// Keep-alive: a ping every `PING_INTERVAL`; `PING_DEAD_AFTER` consecutive
/// misses declare the connection dead.
async fn pinger(conn: Connection) {
    let mut unanswered: u32 = 0;
    loop {
        tokio::select! {
            () = tokio::time::sleep(limits::PING_INTERVAL) => {}
            () = conn.closed() => return,
        }
        match conn.ping().await {
            Ok(rtt) => {
                unanswered = 0;
                debug!(?rtt, "pong");
            }
            Err(e) => {
                if conn.is_closed() {
                    return;
                }
                unanswered += 1;
                warn!(unanswered, error = %e, "ping unanswered");
                if unanswered >= limits::PING_DEAD_AFTER {
                    conn.inner.mark_closed("ping timeout");
                    conn.inner.mux.close().await;
                    return;
                }
            }
        }
    }
}

/// Streams opened by the server: only `ForwardedTcp` is meaningful.
async fn acceptor(conn: Connection, mut incoming: Incoming) {
    while let Some(mut stream) = incoming.accept().await {
        let conn = conn.clone();
        tokio::spawn(async move {
            let open = match timeout(limits::OPEN_REPLY_DEADLINE, accept_open(&mut stream)).await {
                Ok(Ok(Ok(open))) => open,
                Ok(Ok(Err(tag))) => {
                    debug!(tag, "unknown stream kind from server");
                    reply_unsupported(&mut stream, "unknown stream kind").await;
                    return;
                }
                Ok(Err(e)) => {
                    debug!(error = %e, "bad stream prologue from server");
                    return;
                }
                Err(_) => {
                    debug!("server stream prologue timed out");
                    return;
                }
            };
            match open {
                Open::ForwardedTcp { listener, peer } => {
                    let mut stream = Some(stream);
                    if let Ok(guard) = conn.inner.handler.lock()
                        && let Some(handler) = guard.as_ref()
                        && let Some(s) = stream.take()
                    {
                        handler(s, listener, peer);
                    }
                    if let Some(mut s) = stream {
                        debug!(listener, "ForwardedTcp with no handler registered");
                        reply_unsupported(&mut s, "no remote forward handler").await;
                    }
                }
                other => {
                    debug!(?other, "server opened an unexpected stream kind");
                    reply_unsupported(&mut stream, "clients only accept ForwardedTcp").await;
                }
            }
        });
    }
    debug!("incoming stream channel closed");
}

async fn reply_unsupported(stream: &mut Stream, message: &str) {
    let _ = write_reply(
        stream,
        &OpenReply::Err {
            code: ErrorCode::Unsupported,
            message: message.to_owned(),
        },
    )
    .await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_is_send_sync() {
        fn check<T: Send + Sync>() {}
        check::<Connection>();
    }

    #[test]
    fn trust_error_messages_name_fingerprints() {
        let key = PublicKey::from_bytes([7u8; 32]);
        let fp = key.fingerprint();
        let err = TrustError::Mismatch {
            source: "/tmp/kh".to_owned(),
            line: 3,
            expected: fp.clone(),
            actual: fp.clone(),
        };
        let text = err.to_string();
        assert!(text.contains("/tmp/kh line 3"));
        assert!(text.contains(fp.as_str()));
        assert!(
            TrustError::Unknown { key }
                .to_string()
                .contains(fp.as_str())
        );
    }
}
