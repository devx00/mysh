//! One client connection: dial, server-trust check, Noise handshake, the
//! control stream (pings, notices, shutdown) and the acceptor for streams
//! the server opens (`ForwardedTcp`). See docs/03-protocol.md §1–§6 and
//! docs/02-security.md "Server trust (client)".
//!
//! TOFU is a two-step dance because the handshake's `verify_server` callback
//! is synchronous: an unknown key is reported out of the callback as
//! [`TrustError::Unknown`] (the handshake aborts without revealing our
//! identity), the user is asked on the console, and on `yes` the key is
//! appended to `known_hosts` and we dial again — the second handshake then
//! sees a known key.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
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
use tokio::{
    io::{AsyncWriteExt as _, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{
    client::console::Console,
    config::{Paths, Target},
    identity::{Baked, ClientIdentity, ClientTrust, TrustDecision, client_identities},
    output::{code_name, coded, codes},
};

/// Per-address TCP connect budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Client-side bound on the whole handshake (the server allows 5 s).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    handler: Mutex<Option<ForwardedHandler>>,
    console: Console,
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
    pub fn mux(&self) -> &Mux {
        &self.inner.mux
    }

    pub fn target(&self) -> &Target {
        &self.inner.target
    }

    pub fn server_hello(&self) -> &ServerHello {
        &self.inner.hello
    }

    pub fn remote_key(&self) -> PublicKey {
        self.inner.remote
    }

    /// How the server key was trusted (`pin`, `baked`, a `known_hosts` file…).
    pub fn trusted_via(&self) -> &str {
        &self.inner.via
    }

    /// The identity the server accepted.
    pub fn identity(&self) -> &ClientIdentity {
        &self.inner.identity
    }

    pub fn identity_fingerprint(&self) -> Fingerprint {
        self.inner.identity.fingerprint()
    }

    /// Our public key as an `authorized_keys` line (for `authorize`).
    pub fn identity_line(&self) -> String {
        self.inner.identity.public_line()
    }

    pub fn connected_at(&self) -> Instant {
        self.inner.connected_at
    }

    pub fn version(&self) -> u16 {
        self.inner.version
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr
    }

    /// Round trip of the most recent ping (keep-alive or `ping`).
    pub fn last_rtt(&self) -> Option<Duration> {
        self.inner.last_rtt.lock().ok().and_then(|r| *r)
    }

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

    pub fn stats(&self) -> TransferStats {
        self.inner.mux.stats()
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

async fn attempt(
    target: &Target,
    identity: &ClientIdentity,
    trust: &ClientTrust,
) -> Result<Attempt> {
    // Per-connection material: a key file is the Noise static itself; an
    // agent key gets a fresh static and proves itself by signature.
    let fresh;
    let mut signer;
    let (static_key, auth) = match identity {
        ClientIdentity::Static(id) => (&id.secret, ClientAuth::Static),
        ClientIdentity::Agent { socket, key } => {
            signer = AgentSigner::connect(socket, key.clone()).await?;
            fresh = SecretKey::generate();
            (
                &fresh,
                ClientAuth::Ed25519 {
                    public: key.public,
                    sign: &mut signer,
                },
            )
        }
    };
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
                other @ TrustError::Strict { .. } => {
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

/// Ask the user whether to trust `key`; `Ok(true)` only on an explicit yes.
async fn tofu_prompt(target: &Target, key: &PublicKey, console: &Console) -> Result<bool> {
    console.print(&format!(
        "The authenticity of host {}:{} can't be established.\n\
         Fingerprint {}\n\
         Are you sure you want to continue connecting (yes/no)? ",
        target.host,
        target.port,
        key.fingerprint()
    ));
    console.flush().await;
    let answer = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await
    .context("stdin reader")?
    .context("reading answer")?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

/// Accept an unknown server key: `--accept-new` is handled inside the
/// handshake callback, so reaching here means a console prompt is needed.
/// Returns after the key is appended; the caller reconnects.
async fn accept_unknown(
    target: &Target,
    trust: &ClientTrust,
    key: PublicKey,
    console: &Console,
) -> Result<()> {
    let stdin_tty = mysh_pty::terminal::is_terminal(std::io::stdin());
    if !(console.is_tty() && stdin_tty && console.mode() == crate::output::Mode::Human) {
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
    if !tofu_prompt(target, &key, console).await? {
        return Err(coded(
            codes::TRUST_UNKNOWN,
            anyhow!("host key verification failed"),
        ));
    }
    KnownHosts::append(&trust.write_to, &target.host, target.port, &key)
        .with_context(|| format!("writing {}", trust.write_to.display()))?;
    console.println(&format!(
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
pub async fn connect(
    target: &Target,
    paths: &Paths,
    baked: &Baked,
    console: &Console,
) -> Result<Connection> {
    let identities = client_identities(target, paths, baked).await?;
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
                        console,
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
                    accept_unknown(target, &trust, key, console).await?;
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
    console: &Console,
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
        handler: Mutex::new(None),
        console: console.clone(),
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
            Ok(ControlMsg::Notice(text)) => conn.inner.console.notice(&format!("server: {text}")),
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
