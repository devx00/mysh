//! Shared harness for the integration tests: an in-process server on
//! loopback with a throwaway identity, a client identity on disk under a
//! temp config dir, and helpers to build `Target`s and connections.
//!
//! Nothing here touches the real home directory: `Paths::with_config_dir`
//! points every file at the temp dir, and `ServerConfig.trust` is built
//! inline so the server never reads `~/.ssh`.

#![allow(dead_code, unreachable_pub)] // each test binary uses a different subset

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use mysh::{
    cli::{ConnectOpts, Feature, ServeArgs},
    client::{conn::Connection, console::Console},
    config::{Config, Paths, Target, resolve_target},
    identity::{Baked, TrustSource},
    server::{Policy, Server, ServerConfig},
};
use mysh_net::{
    keys::{Identity, KeyFormat, PublicKey, SecretKey, write_public_key, write_secret_key},
    trust::AuthorizedKeys,
};
use tokio::{sync::oneshot, task::JoinHandle};

/// Unique temp directory, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        Self::under(&std::env::temp_dir(), tag)
    }

    /// A directory with a short absolute path (`/tmp` when it exists) for
    /// unix sockets, whose path length is capped at ~100 bytes; the macOS
    /// `$TMPDIR` is too deep for that.
    pub fn short(tag: &str) -> Self {
        let tmp = Path::new("/tmp");
        if tmp.is_dir() {
            Self::under(tmp, tag)
        } else {
            Self::new(tag)
        }
    }

    fn under(base: &Path, tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!(
            "mysh-it-{tag}-{}-{n}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Knobs for [`start_server`].
#[derive(Default)]
pub struct ServerOpts {
    pub deny: Vec<Feature>,
    pub shell: Option<PathBuf>,
    pub accept_env: Vec<String>,
    /// Extra trusted client keys beyond the harness client identity.
    pub extra_authorized: Vec<PublicKey>,
    /// Raw `authorized_keys` lines (with options), appended verbatim, e.g.
    /// `format!("no-pty {}", key.to_line(None))`.
    pub authorized_lines: Vec<String>,
    /// Do not trust the harness client identity (for unauthorized tests).
    pub untrusted_client: bool,
    /// `Policy.handshakes_per_minute`; `None` keeps the harness default (off).
    pub handshakes_per_minute: Option<u32>,
    /// `Policy.idle_timeout`; `None` keeps the protocol default.
    pub idle_timeout: Option<Duration>,
    /// `Policy.detach_grace`; `None` keeps the protocol default (10 min),
    /// `Some(ZERO)` switches persistence off.
    pub detach_grace: Option<Duration>,
    /// `Policy.signature_auth`; `None` keeps the default (on).
    pub signature_auth: Option<bool>,
    /// Also listen on `[::1]:0` (see [`TestServer::addr_v6`]).
    pub listen_v6: bool,
    /// Open a pairing window at start: `(code, duration)`.
    pub pair_window: Option<(String, Duration)>,
    /// `--audit PATH`: the audit log file (`None`: off).
    pub audit: Option<PathBuf>,
}

/// A running server plus the client-side material needed to reach it.
pub struct TestServer {
    pub addr: SocketAddr,
    /// The `[::1]` listener when `listen_v6` was set and IPv6 loopback is
    /// available on this host.
    pub addr_v6: Option<SocketAddr>,
    pub dir: TempDir,
    /// `<dir>/client`: identity (`id`, `id.pub`), `known_hosts`, history.
    pub client_dir: PathBuf,
    /// `<dir>/home`: the server's HOME for sessions and `~` expansion.
    pub home: PathBuf,
    pub client_identity: Identity,
    pub server_key: PublicKey,
    /// `<dir>/server/authorized_keys`: where paired client keys land.
    pub server_authorized_keys: PathBuf,
    /// The server's pairing windows.
    pub pairing: std::sync::Arc<mysh::server::pair::PairState>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl TestServer {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn host_arg(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    /// Whether a pairing window is open right now.
    pub fn pairing_open(&self) -> bool {
        self.pairing.is_open()
    }

    /// Client `Paths` rooted at the temp client dir. The agent socket is
    /// cleared so an in-process client never consults the developer's real
    /// `ssh-agent`; tests that need one set `agent_socket` themselves.
    pub fn client_paths(&self) -> Paths {
        let mut paths = Paths::with_config_dir(self.client_dir.clone());
        paths.agent_socket = None;
        paths
    }

    /// Connect with an explicit `Paths` (for an agent socket of the test's
    /// own) and the harness trust settings.
    pub async fn connect_with_paths(
        &self,
        opts: ConnectOpts,
        paths: &Paths,
    ) -> anyhow::Result<Connection> {
        let console = Console::new();
        mysh::client::connect(&self.target(opts), paths, &Baked::default(), &console).await
    }

    /// A `Target` for this server with `--accept-new` plus `opts` overrides.
    pub fn target(&self, mut opts: ConnectOpts) -> Target {
        if !opts.strict && opts.pin.is_none() {
            opts.accept_new = true;
        }
        resolve_target(&self.host_arg(), &opts, &Config::default()).expect("resolve target")
    }

    /// Connect with the harness identity.
    pub async fn connect(&self, opts: ConnectOpts) -> anyhow::Result<Connection> {
        self.connect_with_paths(opts, &self.client_paths()).await
    }

    /// Stop the server and wait for it.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), task).await;
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn identity_from(secret: SecretKey, source: &str) -> Identity {
    let public = secret.public();
    Identity {
        secret,
        public,
        format: KeyFormat::Native,
        comment: None,
        source: source.to_owned(),
    }
}

/// Start a server on `127.0.0.1:0` with a fresh identity and a fresh client
/// identity written to `<dir>/client/id`.
pub async fn start_server(opts: ServerOpts) -> TestServer {
    let dir = TempDir::new("srv");
    let client_dir = dir.join("client");
    let home = dir.join("home");
    std::fs::create_dir_all(&client_dir).expect("client dir");
    std::fs::create_dir_all(&home).expect("home dir");

    let client_secret = SecretKey::generate();
    let id_path = client_dir.join("id");
    write_secret_key(&id_path, &client_secret).expect("write client key");
    write_public_key(
        &client_dir.join("id.pub"),
        &client_secret.public(),
        Some("it"),
    )
    .expect("write client pub");
    let client_identity = identity_from(client_secret, &id_path.display().to_string());

    let server_identity = identity_from(SecretKey::generate(), "test");
    let server_key = server_identity.public;

    let mut text = String::new();
    if !opts.untrusted_client {
        text.push_str(&client_identity.public.to_line(Some("client")));
    }
    for k in &opts.extra_authorized {
        text.push_str(&k.to_line(Some("extra")));
    }
    for line in &opts.authorized_lines {
        text.push_str(line);
        if !line.ends_with('\n') {
            text.push('\n');
        }
    }
    let inline = AuthorizedKeys::parse(&text, "test-inline");
    // Paired keys land here; the server re-reads it on every connection.
    let server_authorized_keys = dir.join("server").join("authorized_keys");
    let trust = TrustSource {
        baked: AuthorizedKeys::new(),
        inline,
        files: vec![server_authorized_keys.clone()],
        ssh_ed25519_file: None,
    };

    let mut policy = Policy::from_args(&ServeArgs::default());
    policy.deny = opts.deny.into_iter().collect();
    policy.accept_env = opts.accept_env;
    policy.shell = opts.shell;
    "test-server".clone_into(&mut policy.name);
    policy.home = home.clone();
    // Tests open many connections from loopback; only the rate-limit tests
    // switch the limiter on.
    policy.handshakes_per_minute = opts.handshakes_per_minute.unwrap_or(0);
    if let Some(idle) = opts.idle_timeout {
        policy.idle_timeout = idle;
    }
    if let Some(grace) = opts.detach_grace {
        policy.detach_grace = grace;
    }
    if let Some(sig) = opts.signature_auth {
        policy.signature_auth = sig;
    }

    let mut listen: Vec<SocketAddr> = vec!["127.0.0.1:0".parse().expect("addr")];
    let v6: SocketAddr = "[::1]:0".parse().expect("addr");
    if opts.listen_v6 && std::net::TcpListener::bind(v6).is_ok() {
        listen.push(v6);
    }
    let server = Server::bind(ServerConfig {
        listen,
        identity: server_identity,
        trust,
        policy,
        pairing: Some(mysh::server::pair::PairConfig {
            authorized_keys: server_authorized_keys.clone(),
            window: opts.pair_window,
        }),
        audit: opts.audit,
    })
    .await
    .expect("bind server");
    let addrs = server.local_addrs();
    let addr = addrs[0];
    let addr_v6 = addrs.get(1).copied();
    let pairing = server.pairing().expect("harness configures pairing");
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));

    TestServer {
        addr,
        addr_v6,
        dir,
        client_dir,
        home,
        client_identity,
        server_key,
        server_authorized_keys,
        pairing,
        shutdown: Some(tx),
        task: Some(task),
    }
}

/// Path of the built `mysh` binary for black-box tests.
pub fn mysh_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mysh"))
}

/// Environment for a child `mysh` client: config dir, HOME and the runtime
/// dir (control sockets) under the temp tree so nothing in the real home or
/// `$XDG_RUNTIME_DIR` is read or written. `SSH_AUTH_SOCK` is cleared (an
/// empty value means "no agent") so the child never talks to a real
/// `ssh-agent`; agent tests override it.
pub fn client_env(server: &TestServer) -> Vec<(String, String)> {
    vec![
        (
            "MYSH_CONFIG_DIR".into(),
            server.client_dir.display().to_string(),
        ),
        ("HOME".into(), server.home.display().to_string()),
        (
            "XDG_RUNTIME_DIR".into(),
            server.dir.join("run").display().to_string(),
        ),
        ("TERM".into(), "xterm".into()),
        ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
        ("SSH_AUTH_SOCK".into(), String::new()),
    ]
}
