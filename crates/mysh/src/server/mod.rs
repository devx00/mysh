//! Server: listen loop, per-connection authorization and dispatch, sessions,
//! files, forwards. Layout per `docs/01-architecture.md`.
//!
//! One task per TCP listener accepts connections; each connection runs the
//! Noise handshake (bounded by a semaphore of concurrent handshakes), checks
//! the client key against the trust set, then multiplexes streams. The first
//! stream must be `Open::Control`; every later stream is dispatched to the
//! handler for its `Open` kind (docs/03-protocol.md §5–§10).
//!
//! With `--connect-back` the server also dials accepting clients itself
//! ([`connect_back`]); after TCP the connection takes the same path
//! (`handle_connection`) as an accepted one. An authorized client may ask
//! the server to bind a listener (`ControlMsg::Bind`, `--allow-bind-request`).
//!
//! The server is single-user: it serves the OS user that runs it, with no
//! privilege separation and no path sandboxing beyond `~` expansion.

pub mod audit;
pub mod connect_back;
pub mod files;
pub mod forward;
pub mod info;
pub mod pair;
pub mod session;

use std::{
    collections::HashSet,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use mysh_net::{
    framing::{read_msg, write_msg, write_reply},
    handshake::{Accept, HandshakeError, Handshaken, Peer, server_handshake},
    keys::Identity,
    mux::{Incoming, Mode, Mux, Stream, accept_open},
    ratelimit::RateLimiter,
    trust::KeyOptions,
};
use mysh_proto::{
    DEFAULT_PORT, caps,
    control::ControlMsg,
    handshake::ServerHello,
    limits::{self, OPEN_REPLY_DEADLINE},
    open::{ErrorCode, Open, OpenReply},
};
use tokio::{
    net::{TcpListener, TcpStream},
    signal::unix::{Signal, SignalKind, signal},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::{
    cli::{Feature, ServeArgs},
    config::{Paths, parse_duration},
    identity::{TrustSource, baked, load_server_identity},
};
use session::{Registry, Sessions};

/// Concurrent handshakes per server; further connections are closed at once
/// (docs/02-security.md, "Limits and hardening").
const MAX_HANDSHAKES: usize = 64;

/// How long `Server::run` waits for connections to finish after shutdown,
/// and how long a connection keeps serving after `ControlMsg::Shutdown`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Pause after a failed `accept` (EMFILE and friends) before retrying.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Session policy derived from `mysh serve` options and the server's own
/// environment (docs/04-sessions.md, "Shell and home resolution"), narrowed
/// per connection by the matched key's options
/// ([`Policy::with_key_options`]).
#[derive(Debug, Clone)]
pub struct Policy {
    /// Features switched off with `--deny` or by the key's options.
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
    /// `command="…"` from the matched key: every session runs this instead
    /// of the requested command (docs/02-security.md, "Per-key options").
    pub forced_command: Option<String>,
    /// Handshakes accepted per minute per client address; 0 disables the
    /// limit (`--handshake-rate`).
    pub handshakes_per_minute: u32,
    /// A connection with no control traffic for this long is closed
    /// (`--idle-timeout`).
    pub idle_timeout: Duration,
    /// How long a detached PTY session is kept (`--detach-grace`).
    pub detach_grace: Duration,
    /// Accept ssh-ed25519 signature authentication (`--no-signature-auth`
    /// switches it off).
    pub signature_auth: bool,
    /// The `authorized_keys` file the client's `authorize` appends to:
    /// `<config dir>/authorized_keys` (`$MYSH_CONFIG_DIR`), the file the
    /// server always reads and pairing writes to; `--authorized-keys`
    /// files are read in addition but never written. Reported in `Info`.
    pub authorized_keys: PathBuf,
}

impl Policy {
    /// Whether `feature` was switched off with `--deny`.
    pub fn denies(&self, feature: Feature) -> bool {
        self.deny.contains(&feature)
    }

    /// Policy for `mysh serve`: `--deny`, `--accept-env`, `--shell`,
    /// `--name` (default: hostname), the hardening knobs, the server's
    /// home/user/`PATH`, and the `authorized_keys` path from `paths`.
    pub fn from_args(args: &ServeArgs, paths: &Paths) -> Self {
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
            forced_command: None,
            handshakes_per_minute: args.handshake_rate.unwrap_or(limits::HANDSHAKES_PER_MINUTE),
            idle_timeout: args
                .idle_timeout
                .map_or(limits::SERVER_IDLE, Duration::from_secs),
            detach_grace: args
                .detach_grace
                .map_or(limits::DETACH_GRACE, Duration::from_secs),
            signature_auth: !args.no_signature_auth,
            authorized_keys: paths.authorized_keys.clone(),
        }
    }

    /// The effective policy for one connection: this policy narrowed by the
    /// matched `authorized_keys` options (`no-pty`, `no-files`,
    /// `no-forward`, `command=`). Options only ever remove permissions.
    #[must_use]
    pub fn with_key_options(&self, options: &KeyOptions) -> Self {
        let mut effective = self.clone();
        if options.no_pty {
            effective.deny.insert(Feature::Pty);
        }
        if options.no_files {
            effective.deny.insert(Feature::Files);
        }
        if options.no_forward {
            effective.deny.insert(Feature::ForwardLocal);
            effective.deny.insert(Feature::ForwardRemote);
        }
        if let Some(command) = &options.command {
            effective.forced_command = Some(command.clone());
        }
        effective
    }
}

/// Everything a [`Server`] needs; built by [`serve`] or directly by tests.
#[derive(Debug)]
pub struct ServerConfig {
    /// Addresses to listen on; empty → `[::]:7722`, falling back to
    /// `0.0.0.0:7722` when IPv6 is unavailable — unless `connect_back` has
    /// addresses, in which case nothing is bound.
    pub listen: Vec<SocketAddr>,
    /// Clients to connect back to (`--connect-back`).
    pub connect_back: connect_back::ConnectBackConfig,
    /// Honour `ControlMsg::Bind` from authorized clients
    /// (`--allow-bind-request`).
    pub bind_requests: bool,
    /// Host identity.
    pub identity: Identity,
    /// Trusted client keys; re-read on every connection.
    pub trust: TrustSource,
    pub policy: Policy,
    /// Pairing support (`None`: `PAIR_REQUEST` clients take the normal path).
    pub pairing: Option<pair::PairConfig>,
    /// `--audit PATH` (`-` for stderr); `None` switches the audit log off.
    pub audit: Option<PathBuf>,
}

/// State shared by every connection of one server.
#[derive(Debug)]
pub(crate) struct Shared {
    identity: Identity,
    trust: TrustSource,
    policy: Arc<Policy>,
    pub(crate) handshakes: Arc<Semaphore>,
    /// `None` when `handshakes_per_minute` is 0.
    limiter: Option<Mutex<RateLimiter>>,
    /// Session ids and detached PTY sessions, which outlive connections.
    registry: Registry,
    /// Pairing windows; `None` when the server cannot pair at all.
    pairing: Option<Arc<pair::PairState>>,
    /// Audit log sink (disabled without `--audit`).
    audit: Arc<audit::Audit>,
    /// Every connection and requested listener; `Server::run` waits for it.
    tracker: TaskTracker,
    /// `--allow-bind-request`.
    bind_requests: bool,
    /// The listener bound on a client's request, if any (one per server
    /// process; it belongs to the process, not to the requesting
    /// connection).
    requested: Mutex<Option<RequestedListener>>,
}

/// A listener bound on `ControlMsg::Bind` (docs/03-protocol.md §6).
#[derive(Debug)]
struct RequestedListener {
    addr: SocketAddr,
    /// `true` tells the accept loop to stop (`Unbind`).
    stop: watch::Sender<bool>,
    /// `Some(reason)` once the accept loop has ended.
    ended: watch::Receiver<Option<String>>,
}

impl Shared {
    /// Admit or drop a fresh TCP connection from `peer` (before the
    /// handshake); logs a rejected address at most once per ten seconds.
    fn admit(&self, peer: SocketAddr) -> bool {
        let Some(limiter) = &self.limiter else {
            return true;
        };
        let now = Instant::now();
        let mut limiter = limiter.lock().unwrap_or_else(PoisonError::into_inner);
        if limiter.check(peer.ip(), now) {
            return true;
        }
        if limiter.should_warn(peer.ip(), now) {
            warn!(%peer, "handshake rate limit");
        }
        false
    }

    /// The address of the live requested listener, if there is one.
    fn requested_live(&self) -> Option<SocketAddr> {
        self.requested
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|r| r.ended.borrow().is_none())
            .map(|r| r.addr)
    }

    /// `ControlMsg::Bind`: bind `addr`, run an accept loop on it that
    /// closes after `idle_secs` without an accepted connection (0: never),
    /// and return the bound address plus a watch that carries the reason
    /// once the loop has ended. `Err(reason)` is sent back as `Unbound`.
    async fn bind_on_request(
        self: &Arc<Self>,
        addr: &str,
        idle_secs: u32,
        peer: SocketAddr,
        shutdown: watch::Receiver<Option<String>>,
    ) -> Result<(SocketAddr, watch::Receiver<Option<String>>), String> {
        let requested: SocketAddr = addr
            .parse()
            .map_err(|_| format!("bind {addr}: expected HOST:PORT"))?;
        if let Some(existing) = self.requested_live() {
            return Err(format!(
                "a requested listener is already bound at {existing}"
            ));
        }
        let listener = TcpListener::bind(requested)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let actual = listener
            .local_addr()
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let (ended_tx, ended_rx) = watch::channel(None::<String>);
        {
            let mut slot = self
                .requested
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(existing) = slot.as_ref().filter(|r| r.ended.borrow().is_none()) {
                // Lost the race against another connection's request.
                return Err(format!(
                    "a requested listener is already bound at {}",
                    existing.addr
                ));
            }
            *slot = Some(RequestedListener {
                addr: actual,
                stop: stop_tx,
                ended: ended_rx.clone(),
            });
        }
        let idle = (idle_secs != 0).then(|| Duration::from_secs(u64::from(idle_secs)));
        info!(%peer, addr = %actual, ?idle, "listener bound on request");
        tokio::spawn(self.tracker.track_future(requested_listener_loop(
            listener,
            idle,
            Arc::clone(self),
            stop_rx,
            ended_tx,
            shutdown,
        )));
        Ok((actual, ended_rx))
    }

    /// `ControlMsg::Unbind`: stop the requested listener; its address when
    /// there was a live one.
    fn unbind(&self, peer: SocketAddr) -> Option<SocketAddr> {
        let slot = self
            .requested
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let live = slot.as_ref().filter(|r| r.ended.borrow().is_none())?;
        info!(%peer, addr = %live.addr, "unbind requested");
        let _ = live.stop.send(true);
        Some(live.addr)
    }
}

/// A bound server; [`Server::run`] serves until the shutdown future resolves.
#[derive(Debug)]
pub struct Server {
    listeners: Vec<TcpListener>,
    connect_back: connect_back::ConnectBackConfig,
    shared: Arc<Shared>,
}

impl Server {
    /// Bind every listen address (all must succeed). With no addresses the
    /// default `[::]:7722` is tried first and `0.0.0.0:7722` second — unless
    /// the server only connects back, in which case nothing is bound.
    pub async fn bind(cfg: ServerConfig) -> Result<Self> {
        info::mark_started();
        let mut listeners = Vec::with_capacity(cfg.listen.len().max(1));
        if cfg.listen.is_empty() && !cfg.connect_back.addrs.is_empty() {
            // Connect-back only: no listener.
        } else if cfg.listen.is_empty() {
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
        let limiter = match cfg.policy.handshakes_per_minute {
            0 => None,
            rate => Some(Mutex::new(RateLimiter::new(rate))),
        };
        let audit = match &cfg.audit {
            Some(path) => audit::Audit::open(path)
                .await
                .with_context(|| format!("opening audit log {}", path.display()))?,
            None => audit::Audit::disabled(),
        };
        Ok(Self {
            listeners,
            connect_back: cfg.connect_back,
            shared: Arc::new(Shared {
                identity: cfg.identity,
                trust: cfg.trust,
                policy: Arc::new(cfg.policy),
                handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
                limiter,
                registry: Registry::default(),
                pairing: cfg
                    .pairing
                    .as_ref()
                    .map(|c| Arc::new(pair::PairState::new(c))),
                audit,
                tracker: TaskTracker::new(),
                bind_requests: cfg.bind_requests,
                requested: Mutex::new(None),
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

    /// The pairing state, when the server was configured with one.
    pub fn pairing(&self) -> Option<Arc<pair::PairState>> {
        self.shared.pairing.clone()
    }

    /// Addresses the server connects back to.
    pub fn connect_back_addrs(&self) -> &[connect_back::Addr] {
        &self.connect_back.addrs
    }

    /// Accept connections (and connect back) until `shutdown` resolves;
    /// then send `ControlMsg::Shutdown` to every connection, wait up to 5 s
    /// for them to finish, and return.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) -> Result<()> {
        let (shutdown_tx, shutdown_rx) = watch::channel(None::<String>);
        let tracker = self.shared.tracker.clone();
        let mut acceptors = JoinSet::new();
        for listener in self.listeners {
            acceptors.spawn(accept_loop(
                listener,
                Arc::clone(&self.shared),
                tracker.clone(),
                shutdown_rx.clone(),
            ));
        }
        // Connect-back loops are not aborted at shutdown: each finishes its
        // current connection (told to stop through the watch) and exits.
        let mut loops = JoinSet::new();
        for addr in &self.connect_back.addrs {
            loops.spawn(connect_back::run_loop(
                addr.clone(),
                Arc::clone(&self.shared),
                self.connect_back.clone(),
                tracker.clone(),
                shutdown_rx.clone(),
            ));
        }
        drop(shutdown_rx);

        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                ended = acceptors.join_next(), if !acceptors.is_empty() => match ended {
                    Some(Ok(())) | None => warn!("a listener stopped unexpectedly"),
                    Some(Err(e)) => warn!(error = %e, "a listener task failed"),
                },
                ended = loops.join_next(), if !loops.is_empty() => match ended {
                    Some(Ok(())) | None => warn!("a connect-back loop stopped unexpectedly"),
                    Some(Err(e)) => warn!(error = %e, "a connect-back loop failed"),
                },
            }
            if acceptors.is_empty() && loops.is_empty() {
                bail!("every listener and connect-back loop has stopped");
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
        loops.abort_all();
        // Detached sessions belong to no connection: hang them up now.
        let _ = timeout(SHUTDOWN_GRACE, self.shared.registry.close_detached()).await;
        Ok(())
    }
}

/// `mysh serve`: load identity and trust, bind, serve until SIGTERM/SIGINT.
#[allow(clippy::needless_pass_by_value)] // entry-point signature per the crate contract
pub async fn serve(args: ServeArgs, paths: Paths) -> Result<()> {
    let baked = baked()?;
    let identity = load_server_identity(&args, &paths, &baked)?;
    let trust = TrustSource::for_server(&args, &paths, &baked)?;
    if trust.load().is_empty() && args.pair.is_none() {
        bail!(
            "no authorized client keys: add one to {} or pass --authorized-key",
            paths.authorized_keys.display()
        );
    }
    let listen = parse_listen(&args.listen)?;
    let connect_back = connect_back::ConnectBackConfig::from_args(&args)?;
    let policy = Policy::from_args(&args, &paths);
    let fingerprint = identity.public.fingerprint();
    let source = identity.source.clone();
    let pair_duration = match &args.pair {
        None => None,
        Some(None) => Some(limits::PAIR_WINDOW),
        Some(Some(text)) => {
            Some(parse_duration(text).map_err(|e| anyhow::anyhow!("--pair {text}: {e}"))?)
        }
    };

    let server = Server::bind(ServerConfig {
        listen,
        connect_back,
        bind_requests: args.allow_bind_request,
        identity,
        trust,
        policy,
        pairing: Some(pair::PairConfig {
            authorized_keys: paths.authorized_keys.clone(),
            window: None,
        }),
        audit: args.audit.clone(),
    })
    .await?;
    // Installed before "listening" is announced: an operator (or a test)
    // may send SIGUSR1 as soon as the server is up, and the default
    // disposition would kill the process.
    let usr1 = match signal(SignalKind::user_defined1()) {
        Ok(usr1) => Some(usr1),
        Err(e) => {
            warn!(error = %e, "cannot listen for SIGUSR1");
            None
        }
    };
    for addr in server.local_addrs() {
        info!(%addr, "listening");
    }
    for addr in server.connect_back_addrs() {
        info!(%addr, period = ?server.connect_back.period, "connecting back");
    }
    // Up: tell a `--daemon` parent and write the pid file (removed at exit).
    let _pid_file = crate::daemon::ready(&args.detach)?;
    if args.allow_bind_request {
        info!("bind requests from authorized clients are allowed");
    }
    info!(%fingerprint, %source, "host identity");
    let pairing = server.pairing().expect("serve always configures pairing");
    if let Some(duration) = pair_duration {
        pairing.open_random(duration);
    }
    server.run(shutdown_signal(pairing, usr1)).await
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

/// Resolves on SIGTERM or SIGINT. Meanwhile each `SIGUSR1` on `usr1` opens
/// a fresh pairing window on `pairing` (docs/02-security.md "Pairing").
async fn shutdown_signal(pairing: Arc<pair::PairState>, mut usr1: Option<Signal>) {
    // A registered handler that is never read: SIGHUP (a closed terminal
    // after `--daemon` or `&`) must not end the server, whose default
    // disposition would.
    let _hangup = signal(SignalKind::hangup());
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
    let sigusr1 = async {
        if let Some(usr1) = usr1.as_mut() {
            while usr1.recv().await.is_some() {
                pairing.open_random(limits::PAIR_WINDOW);
            }
        }
        std::future::pending::<()>().await;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT received"),
        () = sigterm => info!("SIGTERM received"),
        () = sigusr1 => {}
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
        accept_one(&listener, &shared, &tracker, &shutdown).await;
    }
}

/// Accept one connection and hand it to its own task (or drop it: rate
/// limit, handshake cap). A failed `accept` is logged and followed by a
/// short pause. Returns once an accept has happened either way.
async fn accept_one(
    listener: &TcpListener,
    shared: &Arc<Shared>,
    tracker: &TaskTracker,
    shutdown: &watch::Receiver<Option<String>>,
) {
    let (stream, peer) = match listener.accept().await {
        Ok(accepted) => accepted,
        Err(e) => {
            warn!(error = %e, "accept failed");
            tokio::time::sleep(ACCEPT_RETRY).await;
            return;
        }
    };
    if !shared.admit(peer) {
        return;
    }
    let Ok(permit) = Arc::clone(&shared.handshakes).try_acquire_owned() else {
        debug!(%peer, "too many concurrent handshakes; closing");
        return;
    };
    let local = stream
        .local_addr()
        .or_else(|_| listener.local_addr())
        .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    tokio::spawn(tracker.track_future(handle_connection(
        stream,
        peer,
        local,
        Arc::clone(shared),
        permit,
        shutdown.clone(),
        audit::Direction::Inbound,
    )));
}

/// Accept loop for a listener bound on request (`Shared::bind_on_request`):
/// like [`accept_loop`], but it ends after `idle` without an accepted
/// connection, on `stop`, or at server shutdown, and reports why on
/// `ended`.
///
/// Boxed because it is reachable from the connections it spawns
/// (`control_loop` → `Bind` → here), which would otherwise make the
/// future types recursive.
fn requested_listener_loop(
    listener: TcpListener,
    idle: Option<Duration>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
    ended: watch::Sender<Option<String>>,
    shutdown: watch::Receiver<Option<String>>,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let addr = listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let mut server_shutdown = shutdown.clone();
        let reason = loop {
            // Recreated per iteration: every accepted connection restarts it.
            let idle_expired = async {
                match idle {
                    Some(idle) => tokio::time::sleep(idle).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = accept_one(&listener, &shared, &shared.tracker, &shutdown) => {}
                () = idle_expired => break "no connection within the idle time",
                _ = stop.changed() => break "unbind requested",
                _ = server_shutdown.changed() => break "server shutting down",
            }
        };
        info!(%addr, reason, "requested listener closed");
        let _ = ended.send(Some(reason.to_owned()));
    })
}

/// Run the handshake and authorize the client's key (`None` after a logged
/// and audited refusal). A `PAIR_REQUEST` client is admitted without
/// authorization while a pairing window is open (`Handshaken::pairing`).
async fn authenticate(
    stream: TcpStream,
    peer: SocketAddr,
    shared: &Shared,
) -> Option<(Handshaken<TcpStream>, KeyOptions)> {
    let mut hello_caps = 0;
    if !shared.policy.detach_grace.is_zero() {
        hello_caps |= caps::PERSIST;
    }
    if shared.policy.signature_auth {
        hello_caps |= caps::SIG_AUTH;
    }
    let hello = ServerHello {
        name: shared.policy.name.clone(),
        caps: hello_caps,
    };
    let trust = shared.trust.load();
    let mut offered: Option<Peer> = None;
    let mut options = KeyOptions::default();
    let result = server_handshake(stream, &shared.identity.secret, hello, |client, hello| {
        offered = Some(*client);
        if hello.caps & caps::PAIR_REQUEST != 0
            && shared.pairing.as_ref().is_some_and(|p| p.is_open())
        {
            info!(%peer, %client, "pairing-only connection admitted");
            return Ok(Accept::Pairing);
        }
        let entry = match client {
            Peer::Static(key) => trust.find(key),
            Peer::Ed25519(pk) => trust.find_ed25519(pk),
        };
        let Some(entry) = entry else {
            return Err((ErrorCode::Unauthorized, "key not authorized".to_owned()));
        };
        if !entry.options.allows_source(peer.ip()) {
            warn!(
                %peer,
                source = %entry.source,
                line = entry.line,
                from = ?entry.options.from,
                "client key is not allowed from this address"
            );
            return Err((
                ErrorCode::Unauthorized,
                "key not authorized from this address".to_owned(),
            ));
        }
        options = entry.options.clone();
        Ok(Accept::Normal)
    })
    .await;
    match result {
        Ok(hs) => Some((hs, options)),
        Err(HandshakeError::Denied { message, .. }) => {
            let client = offered.map_or_else(|| "?".to_owned(), |c| c.to_string());
            warn!(%peer, %client, "unauthorized client key");
            shared
                .audit
                .handle(peer, offered.as_ref())
                .denied("handshake", &message);
            None
        }
        Err(e) => {
            debug!(%peer, error = %e, "handshake failed");
            None
        }
    }
}

/// Handshake, authorize, take the control stream, then dispatch streams
/// until the connection ends. The single path for every connection, dialed
/// by the client or by the server (`direction`). `true` once the client was
/// authenticated (a refused or failed handshake returns `false` at once).
#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    shared: Arc<Shared>,
    permit: OwnedSemaphorePermit,
    shutdown: watch::Receiver<Option<String>>,
    direction: audit::Direction,
) -> bool {
    // TCP keepalive is not configurable through `tokio::net::TcpStream`
    // (that needs `socket2`); the control-stream idle timeout covers it.
    if let Err(e) = stream.set_nodelay(true) {
        debug!(%peer, error = %e, "set_nodelay failed");
    }
    let result = authenticate(stream, peer, &shared).await;
    drop(permit);
    let Some((hs, options)) = result else {
        return false;
    };
    let connected = std::time::Instant::now();
    let client = hs.peer;
    info!(
        %peer,
        fingerprint = %client.fingerprint(),
        auth = client.kind(),
        version = hs.version,
        "client connected"
    );
    let audit = shared
        .audit
        .handle(peer, Some(&client))
        .with_direction(direction);
    audit.emit(audit::Event::Connect, || {
        serde_json::json!({
            "version": hs.version,
            "pairing": hs.pairing,
        })
    });
    let policy = if options == KeyOptions::default() {
        Arc::clone(&shared.policy)
    } else {
        debug!(%peer, ?options, "applying per-key options");
        Arc::new(shared.policy.with_key_options(&options))
    };

    let (mux, mut incoming) = Mux::new(hs.stream, Mode::Server);
    let Some(control) = take_control(&mut incoming, peer).await else {
        mux.close().await;
        return true;
    };
    let control_task = tokio::spawn(control_loop(
        control,
        mux.clone(),
        shutdown,
        ControlCtx {
            peer,
            idle: policy.idle_timeout,
            shared: Arc::clone(&shared),
            // A pairing-only connection is not authorized for anything else.
            bind_allowed: shared.bind_requests && !hs.pairing,
        },
    ));

    if let (true, Some(state)) = (hs.pairing, shared.pairing.as_ref()) {
        // Pairing-only: `Control` and one `Pair` stream, nothing else.
        let ctx = pair::PairCtx {
            state: Arc::clone(state),
            peer,
            client,
            client_static: hs.remote,
            server_static: shared.identity.public,
            server_name: shared.policy.name.clone(),
            audit: audit.clone(),
        };
        while let Some(stream) = incoming.accept().await {
            tokio::spawn(pair::dispatch(stream, ctx.clone()));
        }
    } else {
        let ctx = ConnCtx::new(
            policy,
            mux.clone(),
            peer,
            local,
            client,
            shared.registry.clone(),
            audit.clone(),
        );
        while let Some(stream) = incoming.accept().await {
            tokio::spawn(dispatch(stream, ctx.clone()));
        }
    }
    let _ = control_task.await;
    let stats = mux.stats();
    audit.emit_with(
        audit::Event::Disconnect,
        audit::Extra::traffic(stats.bytes_in, stats.bytes_out, connected),
        || serde_json::json!({}),
    );
    info!(%peer, "client disconnected");
    true
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

/// What [`control_loop`] needs beyond the stream.
struct ControlCtx {
    peer: SocketAddr,
    /// Close after this long without a control message.
    idle: Duration,
    shared: Arc<Shared>,
    /// `--allow-bind-request` and the client is fully authorized.
    bind_allowed: bool,
}

/// Control stream (docs/03-protocol.md §6): answer pings, honour the
/// client's `Shutdown`, relay the server's, serve `Bind`/`Unbind`, and
/// enforce the idle timeout. Closes the mux when it ends.
#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
async fn control_loop(
    control: Stream,
    mux: Mux,
    mut shutdown: watch::Receiver<Option<String>>,
    ctx: ControlCtx,
) {
    use tokio::io::AsyncWriteExt as _;

    let ControlCtx {
        peer,
        idle,
        shared,
        bind_allowed,
    } = ctx;
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
    // The requested listener this connection is told about when it ends.
    let mut bound: BoundWatch = None;
    loop {
        let watching = bound.is_some();
        let bound_ended = async {
            match bound.as_mut() {
                Some((_, ended)) => ended.changed().await,
                None => std::future::pending().await,
            }
        };
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
                Some(ControlMsg::Bind { addr, idle_secs }) => {
                    let reply = bind_reply(&shared, bind_allowed, &mut bound, addr, idle_secs, peer, &shutdown).await;
                    if write_msg(&mut wr, &reply).await.is_err() {
                        break;
                    }
                }
                Some(ControlMsg::Unbind) => {
                    let reply = unbind_reply(&shared, bind_allowed, &mut bound, peer);
                    if write_msg(&mut wr, &reply).await.is_err() {
                        break;
                    }
                }
                Some(
                    ControlMsg::Pong { .. }
                    | ControlMsg::Notice(_)
                    | ControlMsg::Bound { .. }
                    | ControlMsg::Unbound { .. },
                ) => {}
            },
            _ = bound_ended, if watching => {
                let Some(unbound) = unbound_notice(&mut bound) else {
                    continue;
                };
                if write_msg(&mut wr, &unbound).await.is_err() {
                    break;
                }
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
            () = tokio::time::sleep(idle) => {
                warn!(%peer, "no control traffic for {:?}; closing", idle);
                break;
            },
        }
    }
    reader.abort();
    mux.close().await;
}

/// The requested listener a control loop reports on: its address and the
/// watch that carries the reason once it has closed.
type BoundWatch = Option<(SocketAddr, watch::Receiver<Option<String>>)>;

/// Answer `ControlMsg::Bind` with `Bound` or `Unbound`; on success `bound`
/// remembers the listener so its end is reported.
async fn bind_reply(
    shared: &Arc<Shared>,
    bind_allowed: bool,
    bound: &mut BoundWatch,
    addr: String,
    idle_secs: u32,
    peer: SocketAddr,
    shutdown: &watch::Receiver<Option<String>>,
) -> ControlMsg {
    if !bind_allowed {
        warn!(%peer, addr, "bind request refused: not allowed");
        return ControlMsg::Unbound {
            addr,
            reason: "bind requests are not allowed".to_owned(),
        };
    }
    match shared
        .bind_on_request(&addr, idle_secs, peer, shutdown.clone())
        .await
    {
        Ok((actual, ended)) => {
            *bound = Some((actual, ended));
            ControlMsg::Bound {
                addr: actual.to_string(),
            }
        }
        Err(reason) => {
            warn!(%peer, addr, reason, "bind request refused");
            ControlMsg::Unbound { addr, reason }
        }
    }
}

/// Answer `ControlMsg::Unbind`: stop the requested listener (if any) and
/// say so — once; `bound` is cleared so the listener's end is not reported
/// a second time.
fn unbind_reply(
    shared: &Shared,
    bind_allowed: bool,
    bound: &mut BoundWatch,
    peer: SocketAddr,
) -> ControlMsg {
    match bind_allowed.then(|| shared.unbind(peer)).flatten() {
        Some(addr) => {
            *bound = None;
            ControlMsg::Unbound {
                addr: addr.to_string(),
                reason: "unbind requested".to_owned(),
            }
        }
        None => ControlMsg::Unbound {
            addr: String::new(),
            reason: "no requested listener".to_owned(),
        },
    }
}

/// The `Unbound` to send once the watched requested listener has ended;
/// forgets it so it is reported once.
fn unbound_notice(bound: &mut BoundWatch) -> Option<ControlMsg> {
    let (addr, ended) = bound.take()?;
    let reason = ended
        .borrow()
        .clone()
        .unwrap_or_else(|| "listener closed".to_owned());
    Some(ControlMsg::Unbound {
        addr: addr.to_string(),
        reason,
    })
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
        Open::Attach { session } => session::handle_attach(stream, session, ctx).await,
        Open::ListSessions => session::handle_list_sessions(stream, ctx).await,
        Open::Info => info::handle_info(stream, ctx).await,
        Open::Read {
            session,
            offset,
            max,
            wait_ms,
        } => session::handle_read(stream, session, offset, max, wait_ms, ctx).await,
        Open::Write { session, eof } => session::handle_write(stream, session, eof, ctx).await,
        Open::Signal { session, signal } => {
            session::handle_signal(stream, session, signal, ctx).await;
        }
        Open::Pair => {
            files::send_error(
                &mut stream,
                ErrorCode::Denied,
                "pairing needs a pairing-only connection (mysh pair)",
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
    /// Who the client proved to be; owns the sessions it opens.
    pub client: Peer,
    pub sessions: Sessions,
    /// Server-wide session ids and detached sessions.
    pub registry: Registry,
    /// Live remote listeners, for `MAX_LISTENERS`.
    pub listeners: Arc<AtomicUsize>,
    /// Audit emitter for this connection (docs/02-security.md "Audit log").
    pub audit: audit::Handle,
    next_listener: Arc<AtomicU32>,
}

impl ConnCtx {
    fn new(
        policy: Arc<Policy>,
        mux: Mux,
        peer: SocketAddr,
        local: SocketAddr,
        client: Peer,
        registry: Registry,
        audit: audit::Handle,
    ) -> Self {
        Self {
            policy,
            mux,
            peer,
            local,
            client,
            sessions: Sessions::new(registry.clone()),
            registry,
            listeners: Arc::new(AtomicUsize::new(0)),
            audit,
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
        client: Peer,
    ) -> Self {
        let audit = audit::Handle::disabled(peer, &client);
        Self::new(policy, mux, peer, local, client, Registry::default(), audit)
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
        handshake::{ClientAuth, client_handshake},
        keys::{KeyFormat, PublicKey, SecretKey},
        trust::AuthorizedKeys,
    };
    use mysh_proto::session::{ExitStatus, SessionKind, SessionOut, SessionRequest};
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

    pub(crate) fn test_policy() -> Policy {
        Policy {
            deny: HashSet::new(),
            accept_env: Vec::new(),
            shell: Some(PathBuf::from("/bin/sh")),
            name: "testhost".to_owned(),
            home: std::env::temp_dir(),
            user: "tester".to_owned(),
            path: mysh_pty::process::default_path().to_owned(),
            forced_command: None,
            handshakes_per_minute: 0,
            idle_timeout: limits::SERVER_IDLE,
            detach_grace: limits::DETACH_GRACE,
            signature_auth: true,
            authorized_keys: PathBuf::from("/nonexistent/authorized_keys"),
        }
    }

    #[test]
    fn policy_from_args_maps_hardening_flags() {
        let paths = Paths::with_config_dir(PathBuf::from("/tmp/mysh-cfg"));
        let defaults = Policy::from_args(&ServeArgs::default(), &paths);
        assert_eq!(
            defaults.handshakes_per_minute,
            limits::HANDSHAKES_PER_MINUTE
        );
        assert_eq!(defaults.idle_timeout, limits::SERVER_IDLE);
        assert_eq!(defaults.detach_grace, limits::DETACH_GRACE);
        assert!(defaults.signature_auth);
        assert_eq!(defaults.forced_command, None);
        assert_eq!(
            defaults.authorized_keys,
            PathBuf::from("/tmp/mysh-cfg/authorized_keys")
        );

        let args = ServeArgs {
            handshake_rate: Some(0),
            idle_timeout: Some(7),
            detach_grace: Some(9),
            no_signature_auth: true,
            ..ServeArgs::default()
        };
        let custom = Policy::from_args(&args, &paths);
        assert_eq!(custom.handshakes_per_minute, 0);
        assert_eq!(custom.idle_timeout, Duration::from_secs(7));
        assert_eq!(custom.detach_grace, Duration::from_secs(9));
        assert!(!custom.signature_auth);
    }

    #[test]
    fn key_options_narrow_policy() {
        let base = test_policy();
        let same = base.with_key_options(&KeyOptions::default());
        assert!(same.deny.is_empty());
        assert_eq!(same.forced_command, None);

        let options = KeyOptions {
            command: Some("echo hi".to_owned()),
            no_pty: true,
            no_files: true,
            no_forward: true,
            from: vec!["10.0.0.0/8".to_owned()],
        };
        let narrowed = base.with_key_options(&options);
        for feature in [
            Feature::Pty,
            Feature::Files,
            Feature::ForwardLocal,
            Feature::ForwardRemote,
        ] {
            assert!(narrowed.denies(feature), "{feature:?}");
        }
        assert!(!narrowed.denies(Feature::Exec));
        assert_eq!(narrowed.forced_command.as_deref(), Some("echo hi"));
        // `--deny` entries survive.
        let mut denied = test_policy();
        denied.deny.insert(Feature::Exec);
        assert!(denied.with_key_options(&options).denies(Feature::Exec));
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
            connect_back: connect_back::ConnectBackConfig::default(),
            bind_requests: false,
            identity: identity(SecretKey::generate()),
            trust,
            policy: test_policy(),
            audit: None,
            pairing: None,
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
        let (hs, hello) = client_handshake(tcp, key, 0, |_, _| Ok(()), ClientAuth::Static).await?;
        assert_eq!(hello.name, "testhost");
        assert_eq!(hello.caps & caps::SIG_AUTH, caps::SIG_AUTH);
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
            persist: false,
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
            persist: false,
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
