//! Signature authentication with `ssh-agent`-held ed25519 keys
//! (docs/02-security.md "Signature authentication", docs/03-protocol.md §2):
//! the binary logs in with a key that exists only in a throwaway agent, is
//! refused when that key is not authorized or when the server has
//! `--no-signature-auth`, picks the key named by `-i key.pub`, tries a key
//! file before the agent, and the server treats the ed25519 key as the
//! owner of persistent sessions.
//!
//! Every test spawns its own `ssh-agent -a <tmp>/sock` and skips when
//! `ssh-agent`, `ssh-add` or `ssh-keygen` is missing. The real home and the
//! real `$SSH_AUTH_SOCK` are never read: children get an explicit
//! environment and in-process clients an explicit `Paths.agent_socket`.

mod common;

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};

use common::{ServerOpts, TempDir, TestServer};
use mysh::{cli::ConnectOpts, client::conn::Connection, identity::ClientIdentity};
use mysh_net::{
    framing::{read_msg, write_msg},
    keys::Fingerprint,
    mux::{OpenError, Stream},
};
use mysh_proto::{
    open::{ErrorCode, Open},
    session::{
        DetachedSession, ExitStatus, PtyRequest, SessionIn, SessionKind, SessionOut,
        SessionRequest, WinSize,
    },
};

const WAIT: Duration = Duration::from_secs(5);

fn on_path(tool: &str) -> bool {
    Command::new(tool)
        .arg("-V")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// `true` when the OpenSSH tools are available; otherwise prints why the
/// caller skips.
fn tools_available(test: &str) -> bool {
    for tool in ["ssh-agent", "ssh-add", "ssh-keygen"] {
        if !on_path(tool) {
            eprintln!("skipping {test}: {tool} not on PATH");
            return false;
        }
    }
    true
}

/// One `ssh-keygen`-made ed25519 key.
struct AgentTestKey {
    /// Private key file (what `ssh-add` consumed).
    path: PathBuf,
    /// The `ssh-ed25519 … comment` line from `<path>.pub`.
    pub_line: String,
}

impl AgentTestKey {
    fn pub_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".pub");
        PathBuf::from(name)
    }

    /// Raw ed25519 public key bytes decoded from the `.pub` line.
    fn public(&self) -> [u8; 32] {
        use base64::Engine as _;
        let b64 = self
            .pub_line
            .split_whitespace()
            .nth(1)
            .expect("pub line field");
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("base64");
        mysh_net::agent::parse_ed25519_blob(&blob).expect("ssh-ed25519 blob")
    }

    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_ssh_ed25519(&self.public())
    }
}

/// A throwaway `ssh-agent` on a short socket path with `n` fresh ed25519
/// keys added in order. Killed on drop.
struct AgentFixture {
    dir: TempDir,
    sock: PathBuf,
    pid: u32,
    keys: Vec<AgentTestKey>,
}

impl AgentFixture {
    fn spawn(n: usize) -> Self {
        let dir = TempDir::short("sigauth");
        let sock = dir.join("sock");
        let out = Command::new("ssh-agent")
            .arg("-a")
            .arg(&sock)
            .output()
            .expect("ssh-agent spawn");
        assert!(
            out.status.success(),
            "ssh-agent: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let pid = stdout
            .split("SSH_AGENT_PID=")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .expect("SSH_AGENT_PID in ssh-agent output");
        let mut fixture = Self {
            dir,
            sock,
            pid,
            keys: Vec::new(),
        };
        for i in 0..n {
            fixture.add_key(&format!("agentkey{i}"), &format!("it{i}"));
        }
        fixture
    }

    fn add_key(&mut self, name: &str, comment: &str) {
        let path = self.dir.join(name);
        let st = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("ssh-keygen");
        assert!(st.success(), "ssh-keygen failed");
        let out = Command::new("ssh-add")
            .arg(&path)
            .env("SSH_AUTH_SOCK", &self.sock)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-add");
        assert!(
            out.status.success(),
            "ssh-add: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut pub_path = path.as_os_str().to_owned();
        pub_path.push(".pub");
        let pub_line = std::fs::read_to_string(pub_path)
            .expect("read .pub")
            .trim()
            .to_owned();
        self.keys.push(AgentTestKey { path, pub_line });
    }

    /// Client `Paths` for in-process connections: the harness config dir
    /// plus this agent's socket.
    fn paths_for(&self, server: &TestServer) -> mysh::config::Paths {
        let mut paths = server.client_paths();
        paths.agent_socket = Some(self.sock.clone());
        paths
    }
}

impl Drop for AgentFixture {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.pid.to_string())
            .status();
    }
}

/// Environment for a child `mysh`: the harness environment with
/// `MYSH_CONFIG_DIR` pointed at `config_dir` and this agent's socket.
fn child_env(
    server: &TestServer,
    config_dir: &Path,
    agent: &AgentFixture,
) -> Vec<(String, String)> {
    let mut env = common::client_env(server);
    env.retain(|(k, _)| k != "MYSH_CONFIG_DIR" && k != "SSH_AUTH_SOCK");
    env.push(("MYSH_CONFIG_DIR".into(), config_dir.display().to_string()));
    env.push(("SSH_AUTH_SOCK".into(), agent.sock.display().to_string()));
    env
}

/// Run `mysh --accept-new [extra…] HOST 'echo agent-ok'` with `env`.
fn run_echo(server: &TestServer, env: &[(String, String)], extra: &[&str]) -> Output {
    Command::new(common::mysh_bin())
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .arg("--accept-new")
        .args(extra)
        .arg(server.host_arg())
        .arg("echo agent-ok")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run mysh")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// An empty config dir: no `id`, so the agent is the only identity source.
fn empty_config_dir(server: &TestServer) -> PathBuf {
    let dir = server.dir.join("agent-client");
    std::fs::create_dir_all(&dir).expect("config dir");
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_key_logs_in_without_a_key_file() {
    if !tools_available("agent_key_logs_in_without_a_key_file") {
        return;
    }
    let agent = AgentFixture::spawn(1);
    let server = common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![agent.keys[0].pub_line.clone()],
        ..ServerOpts::default()
    })
    .await;
    let cfg = empty_config_dir(&server);
    let env = child_env(&server, &cfg, &agent);

    let out = run_echo(&server, &env, &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "agent-ok\n");
    assert!(!cfg.join("id").exists(), "no key file was created");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_agent_key_is_refused() {
    if !tools_available("unauthorized_agent_key_is_refused") {
        return;
    }
    let agent = AgentFixture::spawn(1);
    // The server trusts only the harness key file, which this client does
    // not have.
    let server = common::start_server(ServerOpts::default()).await;
    let cfg = empty_config_dir(&server);
    let env = child_env(&server, &cfg, &agent);

    let out = run_echo(&server, &env, &[]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("not authorized"), "stderr: {err}");
    assert!(
        err.contains(agent.keys[0].fingerprint().as_str()),
        "names the agent key: {err}"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn server_without_signature_auth_is_explained() {
    if !tools_available("server_without_signature_auth_is_explained") {
        return;
    }
    let agent = AgentFixture::spawn(1);
    let server = common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![agent.keys[0].pub_line.clone()],
        signature_auth: Some(false),
        ..ServerOpts::default()
    })
    .await;
    let cfg = empty_config_dir(&server);
    let env = child_env(&server, &cfg, &agent);

    let out = run_echo(&server, &env, &[]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("does not support agent keys"), "stderr: {err}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dash_i_pub_selects_the_agent_key() {
    if !tools_available("dash_i_pub_selects_the_agent_key") {
        return;
    }
    let agent = AgentFixture::spawn(2);
    // Only the second agent key is authorized.
    let server = common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![agent.keys[1].pub_line.clone()],
        ..ServerOpts::default()
    })
    .await;
    let cfg = empty_config_dir(&server);
    let env = child_env(&server, &cfg, &agent);

    // Without -i the client walks the agent in order and lands on the
    // second key.
    let out = run_echo(&server, &env, &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "agent-ok\n");

    // `-i key.pub` names exactly that key.
    let second = agent.keys[1].pub_path();
    let out = run_echo(&server, &env, &["-i", &second.display().to_string()]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "agent-ok\n");

    // …and no other: the first key alone is refused.
    let first = agent.keys[0].pub_path();
    let out = run_echo(&server, &env, &["-i", &first.display().to_string()]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("not authorized"), "stderr: {err}");
    assert!(
        err.contains(agent.keys[0].fingerprint().as_str()),
        "names the key: {err}"
    );

    // A `.pub` the agent does not hold is an error before any connection.
    let other = AgentTestKey {
        path: server.dir.join("stranger"),
        pub_line: String::new(),
    };
    let st = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "stranger", "-f"])
        .arg(&other.path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("ssh-keygen");
    assert!(st.success());
    let out = run_echo(
        &server,
        &env,
        &["-i", &other.pub_path().display().to_string()],
    );
    assert_eq!(out.status.code(), Some(2), "stderr: {}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("not in agent"),
        "stderr: {}",
        text(&out.stderr)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_file_is_tried_before_the_agent() {
    if !tools_available("key_file_is_tried_before_the_agent") {
        return;
    }
    let agent = AgentFixture::spawn(1);

    // The server trusts only the harness key file: the static identity
    // wins and the agent is never asked.
    let server = common::start_server(ServerOpts::default()).await;
    let conn = server
        .connect_with_paths(ConnectOpts::default(), &agent.paths_for(&server))
        .await
        .expect("connect with the key file");
    assert!(
        matches!(conn.identity(), ClientIdentity::Static(_)),
        "expected the key file, got {:?}",
        conn.identity()
    );
    assert_eq!(
        conn.identity_fingerprint(),
        server.client_identity.public.fingerprint()
    );
    conn.close().await;
    server.stop().await;

    // Only the agent key is authorized: the key file is refused and the
    // client falls through to the agent.
    let server = common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![agent.keys[0].pub_line.clone()],
        ..ServerOpts::default()
    })
    .await;
    let conn = server
        .connect_with_paths(ConnectOpts::default(), &agent.paths_for(&server))
        .await
        .expect("fall through to the agent");
    let ClientIdentity::Agent { key, .. } = conn.identity() else {
        panic!("expected the agent key, got {:?}", conn.identity());
    };
    assert_eq!(key.public, agent.keys[0].public());
    assert_eq!(conn.identity_fingerprint(), agent.keys[0].fingerprint());
    assert_eq!(
        conn.identity_line().trim(),
        agent.keys[0].pub_line,
        "authorize installs the agent's own line"
    );
    conn.close().await;

    // The same through the binary: the harness `id` is on disk and the
    // agent socket is set.
    let env = child_env(&server, &server.client_dir, &agent);
    let out = run_echo(&server, &env, &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "agent-ok\n");
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Persistence ownership by the ed25519 peer (library level)

fn size() -> WinSize {
    WinSize {
        cols: 80,
        rows: 24,
        xpixel: 0,
        ypixel: 0,
    }
}

/// `sh -c SCRIPT` under a pty; returns the stream and session id.
async fn open_pty(conn: &Connection, script: &str) -> (Stream, u32) {
    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: vec!["sh".into(), "-c".into(), script.into()],
        },
        env: Vec::new(),
        pty: Some(PtyRequest {
            term: "xterm".to_owned(),
            size: size(),
        }),
        cwd: None,
    };
    let mut stream = conn
        .open(&Open::Session(req))
        .await
        .expect("open pty session");
    let started: SessionOut = read_msg(&mut stream).await.expect("read Started");
    let SessionOut::Started { session, .. } = started else {
        panic!("expected Started, got {started:?}");
    };
    (stream, session)
}

/// Read `Stdout` until the transcript contains `needle`.
async fn read_until(stream: &mut Stream, needle: &str) {
    let mut out = Vec::new();
    let fut = async {
        loop {
            match read_msg::<_, SessionOut>(stream).await.expect("read") {
                SessionOut::Stdout(chunk) => {
                    out.extend_from_slice(&chunk);
                    if String::from_utf8_lossy(&out).contains(needle) {
                        return;
                    }
                }
                other => panic!("waiting for {needle:?}, got {other:?}"),
            }
        }
    };
    tokio::time::timeout(WAIT, fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"));
}

async fn read_to_exit(stream: &mut Stream) -> ExitStatus {
    let fut = async {
        loop {
            match read_msg::<_, SessionOut>(stream).await.expect("read") {
                SessionOut::Stdout(_) => {}
                SessionOut::Exited(status) => return status,
                other => panic!("unexpected {other:?}"),
            }
        }
    };
    tokio::time::timeout(WAIT, fut)
        .await
        .expect("timed out waiting for Exited")
}

async fn list(conn: &Connection) -> Vec<DetachedSession> {
    let mut stream = conn.open(&Open::ListSessions).await.expect("ListSessions");
    read_msg(&mut stream).await.expect("session list")
}

#[tokio::test(flavor = "multi_thread")]
async fn ed25519_peer_owns_its_detached_sessions() {
    if !tools_available("ed25519_peer_owns_its_detached_sessions") {
        return;
    }
    let agent = AgentFixture::spawn(2);
    // Both agent keys are authorized; the harness key file is not, so every
    // connection below authenticates by signature (`Peer::Ed25519`).
    let server = common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![
            agent.keys[0].pub_line.clone(),
            agent.keys[1].pub_line.clone(),
        ],
        detach_grace: Some(Duration::from_secs(30)),
        ..ServerOpts::default()
    })
    .await;
    let paths = agent.paths_for(&server);
    let as_key = |i: usize| ConnectOpts {
        identity: Some(agent.keys[i].pub_path()),
        ..ConnectOpts::default()
    };

    let first = server
        .connect_with_paths(as_key(0), &paths)
        .await
        .expect("first agent connection");
    assert!(matches!(first.identity(), ClientIdentity::Agent { .. }));
    let (mut stream, id) = open_pty(&first, "echo A; read x; echo B").await;
    read_until(&mut stream, "A").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;
    first.close().await;

    // A different ed25519 key sees nothing.
    let stranger = server
        .connect_with_paths(as_key(1), &paths)
        .await
        .expect("stranger agent connection");
    assert_eq!(list(&stranger).await, Vec::new());
    match stranger.open(&Open::Attach { session: id }).await {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("expected NotFound, got {other:?}"),
    }
    stranger.close().await;

    // The same agent key, on a fresh connection with a fresh Noise static,
    // is the owner: it lists and reattaches the session.
    let second = server
        .connect_with_paths(as_key(0), &paths)
        .await
        .expect("second agent connection");
    let rows = list(&second).await;
    assert_eq!(rows.len(), 1, "rows: {rows:?}");
    assert_eq!(rows[0].id, id);
    assert!(rows[0].detached.is_some());
    let mut stream = second
        .open(&Open::Attach { session: id })
        .await
        .expect("Attach");
    let attached: SessionOut = read_msg(&mut stream).await.expect("read Attached");
    assert!(
        matches!(attached, SessionOut::Attached { .. }),
        "expected Attached, got {attached:?}"
    );
    write_msg(&mut stream, &SessionIn::Stdin(b"\n".to_vec()))
        .await
        .expect("stdin");
    assert_eq!(read_to_exit(&mut stream).await, ExitStatus::Code(0));
    second.close().await;
    server.stop().await;
}
