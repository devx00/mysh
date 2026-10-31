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
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
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
    /// Do not trust the harness client identity (for unauthorized tests).
    pub untrusted_client: bool,
}

/// A running server plus the client-side material needed to reach it.
pub struct TestServer {
    pub addr: SocketAddr,
    pub dir: TempDir,
    /// `<dir>/client`: identity (`id`, `id.pub`), `known_hosts`, history.
    pub client_dir: PathBuf,
    /// `<dir>/home`: the server's HOME for sessions and `~` expansion.
    pub home: PathBuf,
    pub client_identity: Identity,
    pub server_key: PublicKey,
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

    /// Client `Paths` rooted at the temp client dir.
    pub fn client_paths(&self) -> Paths {
        Paths::with_config_dir(self.client_dir.clone())
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
        let console = Console::new();
        mysh::client::conn::connect(
            &self.target(opts),
            &self.client_paths(),
            &Baked::default(),
            &console,
        )
        .await
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
    let inline = AuthorizedKeys::parse(&text, "test-inline");
    let trust = TrustSource {
        baked: AuthorizedKeys::new(),
        inline,
        files: Vec::new(),
        ssh_ed25519_file: None,
    };

    let mut policy = Policy::from_args(&ServeArgs::default());
    policy.deny = opts.deny.into_iter().collect();
    policy.accept_env = opts.accept_env;
    policy.shell = opts.shell;
    "test-server".clone_into(&mut policy.name);
    policy.home = home.clone();

    let server = Server::bind(ServerConfig {
        listen: vec!["127.0.0.1:0".parse().expect("addr")],
        identity: server_identity,
        trust,
        policy,
    })
    .await
    .expect("bind server");
    let addr = server.local_addrs()[0];
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));

    TestServer {
        addr,
        dir,
        client_dir,
        home,
        client_identity,
        server_key,
        shutdown: Some(tx),
        task: Some(task),
    }
}

/// Path of the built `mysh` binary for black-box tests.
pub fn mysh_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mysh"))
}

/// Environment for a child `mysh` client: config dir and HOME under the
/// temp tree so nothing in the real home is read or written.
pub fn client_env(server: &TestServer) -> Vec<(String, String)> {
    vec![
        (
            "MYSH_CONFIG_DIR".into(),
            server.client_dir.display().to_string(),
        ),
        ("HOME".into(), server.home.display().to_string()),
        ("TERM".into(), "xterm".into()),
        ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
    ]
}
