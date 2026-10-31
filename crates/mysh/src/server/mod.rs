//! Server: listen loop, per-connection authorization and dispatch, sessions,
//! files, forwards. Layout per `docs/01-architecture.md`.
//!
//! One task per TCP listener accepts connections; each connection runs the
//! Noise handshake (bounded by a semaphore of concurrent handshakes), checks
//! the client key against the trust set, then multiplexes streams. The first
//! stream must be `Open::Control`; every later stream is dispatched to the
//! handler for its `Open` kind (docs/03-protocol.md §5–§10).
//!
//! The server is single-user: it serves the OS user that runs it, with no
//! privilege separation and no path sandboxing beyond `~` expansion.

pub mod files;
pub mod forward;
pub mod session;

use std::{
    collections::HashSet,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use mysh_net::{
    framing::{read_msg, write_msg, write_reply},
    handshake::{HandshakeError, server_handshake},
    keys::{Identity, PublicKey},
    mux::{Incoming, Mode, Mux, Stream, accept_open},
};
use mysh_proto::{
    DEFAULT_PORT,
    control::ControlMsg,
    handshake::ServerHello,
    limits::{OPEN_REPLY_DEADLINE, SERVER_IDLE},
    open::{ErrorCode, Open, OpenReply},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::{
    cli::{Feature, ServeArgs},
    config::Paths,
    identity::{TrustSource, baked, load_server_identity},
};
use session::Sessions;

/// Concurrent handshakes per server; further connections are closed at once
/// (docs/02-security.md, "Limits and hardening").
const MAX_HANDSHAKES: usize = 64;

/// How long `Server::run` waits for connections to finish after shutdown,
/// and how long a connection keeps serving after `ControlMsg::Shutdown`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Pause after a failed `accept` (EMFILE and friends) before retrying.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Session policy derived from `mysh serve` options and the server's own
/// environment (docs/04-sessions.md, "Shell and home resolution").
#[derive(Debug, Clone)]
pub struct Policy {
    /// Features switched off with `--deny`.
    pub deny: HashSet<Feature>,
    /// Extra client environment names accepted (`--accept-env`); an entry
    /// ending in `*` matches by prefix.
    pub accept_env: Vec<String>,
    /// `--shell` override for `Shell` sessions and `$SHELL`.
    pub shell: Option<PathBuf>,
    /// Name sent in the `ServerHello`.
    pub name: String,
    /// Home directory: default session cwd and `~` expansion base.
    pub home: PathBuf,
    /// `USER`/`LOGNAME` for session children.
    pub user: String,
    /// `PATH` for session children and for resolving `Exec` programs.
    pub path: String,
}

impl Policy {
    /// Whether `feature` was switched off with `--deny`.
    pub fn denies(&self, feature: Feature) -> bool {
        self.deny.contains(&feature)
    }

    /// Policy for `mysh serve`: `--deny`, `--accept-env`, `--shell`,
    /// `--name` (default: hostname), and the server's home/user/`PATH`.
    pub fn from_args(args: &ServeArgs) -> Self {
        Self {
            deny: args.deny.iter().copied().collect(),
            accept_env: args.accept_env.clone(),
            shell: args.shell.clone(),
            name: args.name.clone().unwrap_or_else(hostname),
            home: mysh_pty::process::home_dir(),
            user: mysh_pty::process::user_name(),
            path: std::env::var("PATH")
                .ok()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| mysh_pty::process::default_path().to_owned()),
        }
    }
}

/// Everything a [`Server`] needs; built by [`serve`] or directly by tests.
#[derive(Debug)]
pub struct ServerConfig {
    /// Addresses to listen on; empty → `[::]:7722`, falling back to
    /// `0.0.0.0:7722` when IPv6 is unavailable.
    pub listen: Vec<SocketAddr>,
    /// Host identity.
    pub identity: Identity,
    /// Trusted client keys; re-read on every connection.
    pub trust: TrustSource,
    pub policy: Policy,
}

/// State shared by every connection of one server.
#[derive(Debug)]
struct Shared {
    identity: Identity,
    trust: TrustSource,
    policy: Arc<Policy>,
    handshakes: Arc<Semaphore>,
}

/// A bound server; [`Server::run`] serves until the shutdown future resolves.
#[derive(Debug)]
pub struct Server {
    listeners: Vec<TcpListener>,
    shared: Arc<Shared>,
}

impl Server {
    /// Bind every listen address (all must succeed). With no addresses the
    /// default `[::]:7722` is tried first and `0.0.0.0:7722` second.
    pub async fn bind(cfg: ServerConfig) -> Result<Self> {
        let mut listeners = Vec::with_capacity(cfg.listen.len().max(1));
        if cfg.listen.is_empty() {
            let v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, DEFAULT_PORT));
            match TcpListener::bind(v6).await {
                Ok(listener) => listeners.push(listener),
                Err(e) => {
                    let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT));
                    warn!(error = %e, "cannot bind {v6}; falling back to {v4}");
                    listeners.push(
                        TcpListener::bind(v4)
                            .await
                            .with_context(|| format!("bind {v4}"))?,
                    );
                }
            }
        } else {
            for addr in &cfg.listen {
                listeners.push(
                    TcpListener::bind(addr)
                        .await
                        .with_context(|| format!("bind {addr}"))?,
                );
            }
        }
        Ok(Self {
            listeners,
            shared: Arc::new(Shared {
                identity: cfg.identity,
                trust: cfg.trust,
                policy: Arc::new(cfg.policy),
                handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
            }),
        })
    }

    /// Actually bound addresses (port 0 requests resolved).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .collect()
    }

    /// Accept connections until `shutdown` resolves; then send
    /// `ControlMsg::Shutdown` to every connection, wait up to 5 s for them
    /// to finish, and return.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) -> Result<()> {
        let (shutdown_tx, shutdown_rx) = watch::channel(None::<String>);
        let tracker = TaskTracker::new();
        let mut acceptors = JoinSet::new();
        for listener in self.listeners {
            acceptors.spawn(accept_loop(
                listener,
                Arc::clone(&self.shared),
                tracker.clone(),
                shutdown_rx.clone(),
            ));
        }
        drop(shutdown_rx);

        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                ended = acceptors.join_next() => match ended {
                    None => bail!("every listener has stopped"),
                    Some(Ok(())) => warn!("a listener stopped unexpectedly"),
                    Some(Err(e)) => warn!(error = %e, "a listener task failed"),
                },
            }
        }

        info!("shutting down");
        acceptors.abort_all();
        let _ = shutdown_tx.send(Some("server shutting down".to_owned()));
        tracker.close();
        if timeout(SHUTDOWN_GRACE, tracker.wait()).await.is_err() {
            warn!(
                connections = tracker.len(),
                "connections still open after the shutdown grace period"
            );
        }
        Ok(())
    }
}

/// `mysh serve`: load identity and trust, bind, serve until SIGTERM/SIGINT.
#[allow(clippy::needless_pass_by_value)] // entry-point signature per the crate contract
pub async fn serve(args: ServeArgs, paths: Paths) -> Result<()> {
    let baked = baked()?;
    let identity = load_server_identity(&args, &paths, &baked)?;
    let trust = TrustSource::for_server(&args, &paths, &baked)?;
    if trust.load().is_empty() {
        bail!(
            "no authorized client keys: add one to {} or pass --authorized-key",
            paths.authorized_keys.display()
        );
    }
    let listen = parse_listen(&args.listen)?;
    let policy = Policy::from_args(&args);
    let fingerprint = identity.public.fingerprint();
    let source = identity.source.clone();

    let server = Server::bind(ServerConfig {
        listen,
        identity,
        trust,
        policy,
    })
    .await?;
    for addr in server.local_addrs() {
        info!(%addr, "listening");
    }
    info!(%fingerprint, %source, "host identity");
    server.run(shutdown_signal()).await
}

/// Parse `--listen` values; each must be a full `HOST:PORT` socket address.
fn parse_listen(values: &[String]) -> Result<Vec<SocketAddr>> {
    values
        .iter()
        .map(|s| {
            s.parse::<SocketAddr>().with_context(|| {
                format!("--listen {s}: expected HOST:PORT (e.g. 0.0.0.0:7722 or [::]:7722)")
            })
        })
        .collect()
}

/// Resolves on SIGTERM or SIGINT.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => Some(term),
        Err(e) => {
            warn!(error = %e, "cannot listen for SIGTERM");
            None
        }
    };
    let sigterm = async {
        if let Some(term) = term.as_mut() {
            term.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT received"),
        () = sigterm => info!("SIGTERM received"),
    }
}

/// `$HOSTNAME` → `/etc/hostname` → `/proc/sys/kernel/hostname` → `"mysh"`.
fn hostname() -> String {
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.trim().is_empty()
    {
        return name.trim().to_owned();
    }
    for path in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(text) = std::fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return text.trim().to_owned();
        }
    }
    "mysh".to_owned()
}

/// Accept connections on one listener forever; transient `accept` errors are
/// logged and retried after a short pause.
#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    tracker: TaskTracker,
    shutdown: watch::Receiver<Option<String>>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "accept failed");
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&shared.handshakes).try_acquire_owned() else {
            debug!(%peer, "too many concurrent handshakes; closing");
            continue;
        };
        let local = stream
            .local_addr()
            .or_else(|_| listener.local_addr())
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        tokio::spawn(tracker.track_future(handle_connection(
            stream,
            peer,
            local,
            Arc::clone(&shared),
            permit,
            shutdown.clone(),
        )));
    }
}

/// Handshake, authorize, take the control stream, then dispatch streams
/// until the connection ends.
#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    shared: Arc<Shared>,
    permit: OwnedSemaphorePermit,
    shutdown: watch::Receiver<Option<String>>,
) {
    // TCP keepalive is not configurable through `tokio::net::TcpStream`
    // (that needs `socket2`); the control-stream idle timeout covers it.
    if let Err(e) = stream.set_nodelay(true) {
        debug!(%peer, error = %e, "set_nodelay failed");
    }
    let hello = ServerHello {
        name: shared.policy.name.clone(),
        caps: 0,
    };
    let trust = shared.trust.load();
    let mut offered: Option<PublicKey> = None;
    let result = server_handshake(stream, &shared.identity.secret, hello, |key, _| {
        offered = Some(*key);
        if trust.contains(key) {
            Ok(())
        } else {
            Err((ErrorCode::Unauthorized, "key not authorized".to_owned()))
        }
    })
    .await;
    drop(permit);
    let hs = match result {
        Ok(hs) => hs,
        Err(HandshakeError::Denied { .. }) => {
            let fingerprint =
                offered.map_or_else(|| "?".to_owned(), |k| k.fingerprint().to_string());
            warn!(%peer, %fingerprint, "unauthorized client key");
            return;
        }
        Err(e) => {
            debug!(%peer, error = %e, "handshake failed");
            return;
        }
    };
    let client_key = hs.remote;
    info!(%peer, fingerprint = %client_key.fingerprint(), version = hs.version, "client connected");

    let (mux, mut incoming) = Mux::new(hs.stream, Mode::Server);
    let Some(control) = take_control(&mut incoming, peer).await else {
        mux.close().await;
        return;
    };
    let ctx = ConnCtx::new(
        Arc::clone(&shared.policy),
        mux.clone(),
        peer,
        local,
        client_key,
    );
    let control_task = tokio::spawn(control_loop(control, mux.clone(), shutdown, peer));

    while let Some(stream) = incoming.accept().await {
        tokio::spawn(dispatch(stream, ctx.clone()));
    }
    let _ = control_task.await;
    info!(%peer, "client disconnected");
}

/// The first stream must be `Open::Control`; answer `Ok` and return it.
async fn take_control(incoming: &mut Incoming, peer: SocketAddr) -> Option<Stream> {
    let mut control = match timeout(OPEN_REPLY_DEADLINE, incoming.accept()).await {
        Ok(Some(stream)) => stream,
        Ok(None) => return None,
        Err(_) => {
            warn!(%peer, "client opened no control stream in time");
            return None;
        }
    };
    let first = timeout(OPEN_REPLY_DEADLINE, accept_open(&mut control)).await;
    if !matches!(first, Ok(Ok(Ok(Open::Control)))) {
        warn!(%peer, "first stream is not Control ({first:?}); closing");
        files::send_error(
            &mut control,
            ErrorCode::Protocol,
            "first stream must be Control",
        )
        .await;
        return None;
    }
    write_reply(&mut control, &OpenReply::Ok).await.ok()?;
    Some(control)
}

/// Control stream (docs/03-protocol.md §6): answer pings, honour the
/// client's `Shutdown`, relay the server's, and enforce `SERVER_IDLE`.
/// Closes the mux when it ends.
#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
async fn control_loop(
    control: Stream,
    mux: Mux,
    mut shutdown: watch::Receiver<Option<String>>,
    peer: SocketAddr,
) {
    use tokio::io::AsyncWriteExt as _;

    let (mut rd, mut wr) = tokio::io::split(control);
    let (tx, mut rx) = mpsc::channel::<ControlMsg>(8);
    let reader = tokio::spawn(async move {
        while let Ok(msg) = read_msg::<_, ControlMsg>(&mut rd).await {
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut close_at: Option<Instant> = None;
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                None => {
                    debug!(%peer, "control stream closed");
                    break;
                }
                Some(ControlMsg::Ping { nonce }) => {
                    if write_msg(&mut wr, &ControlMsg::Pong { nonce }).await.is_err() {
                        break;
                    }
                }
                Some(ControlMsg::Shutdown { reason }) => {
                    info!(%peer, reason, "client requested shutdown");
                    break;
                }
                Some(ControlMsg::Pong { .. } | ControlMsg::Notice(_)) => {}
            },
            changed = shutdown.changed(), if close_at.is_none() => {
                let reason = if changed.is_ok() {
                    shutdown.borrow_and_update().clone()
                } else {
                    None
                }
                .unwrap_or_else(|| "server stopped".to_owned());
                let _ = write_msg(&mut wr, &ControlMsg::Shutdown { reason }).await;
                let _ = wr.shutdown().await;
                close_at = Some(Instant::now() + SHUTDOWN_GRACE);
            },
            () = tokio::time::sleep_until(close_at.unwrap_or_else(Instant::now)), if close_at.is_some() => {
                debug!(%peer, "shutdown grace period expired");
                break;
            },
            // Recreated on every iteration: any control message restarts it.
            () = tokio::time::sleep(SERVER_IDLE) => {
                warn!(%peer, "no control traffic for {}s; closing", SERVER_IDLE.as_secs());
                break;
            },
        }
    }
    reader.abort();
    mux.close().await;
}

/// Read the prologue of an accepted stream and hand it to its handler.
async fn dispatch(mut stream: Stream, ctx: ConnCtx) {
    let open = match timeout(OPEN_REPLY_DEADLINE, accept_open(&mut stream)).await {
        Err(_) => {
            debug!(peer = %ctx.peer, "stream sent no Open within the deadline");
            return;
        }
        Ok(Err(e)) => {
            debug!(peer = %ctx.peer, error = %e, "malformed Open");
            return;
        }
        Ok(Ok(Err(tag))) => {
            files::send_error(
                &mut stream,
                ErrorCode::Unsupported,
                &format!("unknown stream kind {tag}"),
            )
            .await;
            return;
        }
        Ok(Ok(Ok(open))) => open,
    };
    match open {
        Open::Control => {
            files::send_error(
                &mut stream,
                ErrorCode::Protocol,
                "control stream already open",
            )
            .await;
        }
        Open::Session(req) => session::handle_session(stream, req, ctx).await,
        Open::DirectTcp { host, port } => forward::handle_direct_tcp(stream, host, port, ctx).await,
        Open::ForwardListen { host, port } => {
            forward::handle_forward_listen(stream, host, port, ctx).await;
        }
        Open::ForwardedTcp { .. } => {
            files::send_error(
                &mut stream,
                ErrorCode::Unsupported,
                "the server does not accept ForwardedTcp",
            )
            .await;
        }
        Open::File { op, cwd } => files::handle_file(stream, op, cwd, ctx).await,
        Open::Cwd { session } => session::handle_cwd(stream, session, ctx).await,
        Open::Attach { .. } | Open::ListSessions => {
            files::send_error(
                &mut stream,
                ErrorCode::Unsupported,
                "session persistence is not enabled",
            )
            .await;
        }
    }
}

/// Per-connection context handed to every stream handler.
#[derive(Debug, Clone)]
pub struct ConnCtx {
    pub policy: Arc<Policy>,
    /// For opening server-initiated streams (`ForwardedTcp`).
    pub mux: Mux,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub client_key: PublicKey,
    pub sessions: Sessions,
    /// Live remote listeners, for `MAX_LISTENERS`.
    pub listeners: Arc<AtomicUsize>,
    next_listener: Arc<AtomicU32>,
}

impl ConnCtx {
    fn new(
        policy: Arc<Policy>,
        mux: Mux,
        peer: SocketAddr,
        local: SocketAddr,
        client_key: PublicKey,
    ) -> Self {
        Self {
            policy,
            mux,
            peer,
            local,
            client_key,
            sessions: Sessions::new(),
            listeners: Arc::new(AtomicUsize::new(0)),
            next_listener: Arc::new(AtomicU32::new(0)),
        }
    }

    /// A fresh context (no sessions, no listeners) for handler tests.
    #[cfg(test)]
    pub fn for_tests(
        policy: Arc<Policy>,
        mux: Mux,
        peer: SocketAddr,
        local: SocketAddr,
        client_key: PublicKey,
    ) -> Self {
        Self::new(policy, mux, peer, local, client_key)
    }

    /// Next listener id (starts at 1, never reused within a connection).
    pub fn next_listener_id(&self) -> u32 {
        self.next_listener.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// `MYSH_CONNECTION` value: `"<client ip> <client port> <server ip> <server port>"`.
    pub fn connection_env(&self) -> String {
        format!(
            "{} {} {} {}",
            self.peer.ip(),
            self.peer.port(),
            self.local.ip(),
            self.local.port()
        )
    }
}

/// Resolve a client-supplied path: `~` / `~/x` → home; relative → `cwd`
/// (itself resolved the same way) or home; absolute as-is. No sandboxing:
/// the server is single-user.
pub fn resolve_remote_path(path: &str, cwd: Option<&str>, home: &Path) -> PathBuf {
    if path == "~" || path.starts_with("~/") {
        return crate::config::expand_tilde(path, home);
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    let base = match cwd {
        Some(cwd) => resolve_remote_path(cwd, None, home),
        None => home.to_path_buf(),
    };
    if path.is_empty() { base } else { base.join(p) }
}

#[cfg(test)]
mod tests {
    use mysh_net::{
        handshake::client_handshake,
        keys::{KeyFormat, SecretKey},
        trust::AuthorizedKeys,
    };
    use mysh_proto::{
        handshake::ClientHello,
        session::{ExitStatus, SessionKind, SessionOut, SessionRequest},
    };
    use tokio::sync::oneshot;

    use super::*;

    #[test]
    fn resolve_remote_path_rules() {
        let home = Path::new("/home/u");
        assert_eq!(
            resolve_remote_path("~", None, home),
            PathBuf::from("/home/u")
        );
        assert_eq!(
            resolve_remote_path("~/x/y", None, home),
            PathBuf::from("/home/u/x/y")
        );
        assert_eq!(
            resolve_remote_path("rel", None, home),
            PathBuf::from("/home/u/rel")
        );
        assert_eq!(
            resolve_remote_path("rel", Some("/work"), home),
            PathBuf::from("/work/rel")
        );
        assert_eq!(
            resolve_remote_path("rel", Some("~/proj"), home),
            PathBuf::from("/home/u/proj/rel")
        );
        assert_eq!(
            resolve_remote_path("/abs", Some("/work"), home),
            PathBuf::from("/abs")
        );
        assert_eq!(
            resolve_remote_path("", Some("/work"), home),
            PathBuf::from("/work")
        );
        assert_eq!(
            resolve_remote_path("", None, home),
            PathBuf::from("/home/u")
        );
        // `~user` is not expanded.
        assert_eq!(
            resolve_remote_path("~bob/x", None, home),
            PathBuf::from("/home/u/~bob/x")
        );
    }

    #[test]
    fn parse_listen_requires_socket_addrs() {
        let ok = parse_listen(&["127.0.0.1:7722".to_owned(), "[::1]:1".to_owned()]).unwrap();
        assert_eq!(ok.len(), 2);
        assert!(parse_listen(&["7722".to_owned()]).is_err());
        assert!(parse_listen(&["localhost:7722".to_owned()]).is_err());
    }

    fn identity(secret: SecretKey) -> Identity {
        Identity {
            public: secret.public(),
            secret,
            format: KeyFormat::Native,
            comment: None,
            source: "test".to_owned(),
        }
    }

    fn test_policy() -> Policy {
        Policy {
            deny: HashSet::new(),
            accept_env: Vec::new(),
            shell: Some(PathBuf::from("/bin/sh")),
            name: "testhost".to_owned(),
            home: std::env::temp_dir(),
            user: "tester".to_owned(),
            path: mysh_pty::process::default_path().to_owned(),
        }
    }

    struct Running {
        addr: SocketAddr,
        stop: oneshot::Sender<()>,
        task: tokio::task::JoinHandle<Result<()>>,
    }

    async fn start_server(client_key: &PublicKey) -> Running {
        let trust = TrustSource {
            baked: AuthorizedKeys::new(),
            inline: AuthorizedKeys::parse(&client_key.to_line(Some("test")), "inline"),
            files: Vec::new(),
            ssh_ed25519_file: None,
        };
        let server = Server::bind(ServerConfig {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            identity: identity(SecretKey::generate()),
            trust,
            policy: test_policy(),
        })
        .await
        .unwrap();
        let addr = server.local_addrs()[0];
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run(async move {
            let _ = stop_rx.await;
        }));
        Running { addr, stop, task }
    }

    async fn connect(addr: SocketAddr, key: &SecretKey) -> Result<Mux, HandshakeError> {
        let tcp = TcpStream::connect(addr).await?;
        let (hs, hello) =
            client_handshake(tcp, key, ClientHello { caps: 0 }, |_, _| Ok(())).await?;
        assert_eq!(hello.name, "testhost");
        let (mux, _incoming) = Mux::new(hs.stream, Mode::Client);
        Ok(mux)
    }

    #[tokio::test]
    async fn exec_session_end_to_end() {
        let client_key = SecretKey::generate();
        let server = start_server(&client_key.public()).await;
        let mux = connect(server.addr, &client_key).await.unwrap();

        let _control = mux.open(&Open::Control).await.unwrap();
        let req = SessionRequest {
            kind: SessionKind::Exec {
                argv: vec!["sh".into(), "-c".into(), "echo hi; exit 3".into()],
            },
            env: Vec::new(),
            pty: None,
            cwd: None,
        };
        let mut session = mux.open(&Open::Session(req)).await.unwrap();

        let started: SessionOut = read_msg(&mut session).await.unwrap();
        assert!(
            matches!(
                started,
                SessionOut::Started {
                    session: 1,
                    cwd_fallback: false,
                    ..
                }
            ),
            "{started:?}"
        );
        let mut out = Vec::new();
        let exit = loop {
            match read_msg::<_, SessionOut>(&mut session).await.unwrap() {
                SessionOut::Stdout(chunk) => out.extend_from_slice(&chunk),
                SessionOut::Stderr(chunk) => panic!("unexpected stderr {chunk:?}"),
                SessionOut::Exited(status) => break status,
                other @ (SessionOut::Started { .. } | SessionOut::Attached { .. }) => {
                    panic!("unexpected {other:?}")
                }
            }
        };
        assert_eq!(out, b"hi\n");
        assert_eq!(exit, ExitStatus::Code(3));
        // The server half-closes after `Exited`.
        assert!(matches!(
            read_msg::<_, SessionOut>(&mut session).await,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
        ));

        drop(session);
        mux.close().await;
        let _ = server.stop.send(());
        server.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unauthorized_client_is_denied() {
        let authorized = SecretKey::generate();
        let server = start_server(&authorized.public()).await;
        let stranger = SecretKey::generate();
        match connect(server.addr, &stranger).await {
            Err(HandshakeError::Denied { code, .. }) => assert_eq!(code, ErrorCode::Unauthorized),
            other => panic!("unexpected: {other:?}"),
        }
        let _ = server.stop.send(());
        server.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn first_stream_must_be_control() {
        let client_key = SecretKey::generate();
        let server = start_server(&client_key.public()).await;
        let mux = connect(server.addr, &client_key).await.unwrap();
        let req = SessionRequest {
            kind: SessionKind::Shell,
            env: Vec::new(),
            pty: None,
            cwd: None,
        };
        match mux.open(&Open::Session(req)).await {
            Err(mysh_net::mux::OpenError::Rejected { code, .. }) => {
                assert_eq!(code, ErrorCode::Protocol);
            }
            other => panic!("unexpected: {other:?}"),
        }
        mux.closed().await;
        let _ = server.stop.send(());
        server.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_notifies_clients_and_answers_pings() {
        let client_key = SecretKey::generate();
        let server = start_server(&client_key.public()).await;
        let mux = connect(server.addr, &client_key).await.unwrap();
        let mut control = mux.open(&Open::Control).await.unwrap();

        write_msg(&mut control, &ControlMsg::Ping { nonce: 7 })
            .await
            .unwrap();
        assert_eq!(
            read_msg::<_, ControlMsg>(&mut control).await.unwrap(),
            ControlMsg::Pong { nonce: 7 }
        );

        let _ = server.stop.send(());
        match read_msg::<_, ControlMsg>(&mut control).await.unwrap() {
            ControlMsg::Shutdown { reason } => {
                assert!(reason.contains("shutting down"), "{reason}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        drop(control);
        mux.close().await;
        server.task.await.unwrap().unwrap();
    }
}
