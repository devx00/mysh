//! The accepting client (docs/02-security.md "Callers",
//! docs/05-meta-shell.md "Accepting connections", docs/06-roadmap.md M12):
//! `mysh_client::Acceptor` against real `mysh serve --connect-back`
//! processes, the `mysh accept` command with its per-connection `@NAME`
//! control socket, and the client's `bind` command.

mod common;

use std::{
    io::{BufRead as _, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use mysh_client::{
    AcceptOpts, Acceptor, ExecRequest, Inbound, NullReporter, Reporter,
    identity::{Callers, ClientIdentity},
    types::Event,
};
use mysh_net::keys::{Identity, KeyFormat, SecretKey, write_public_key, write_secret_key};

/// Generous bound for anything that should happen "promptly".
const SOON: Duration = Duration::from_secs(15);

/// Kills and reaps a spawned child however the test ends.
struct Child {
    child: std::process::Child,
    /// Its stderr (or stdout, for `mysh accept --json`), line by line.
    lines: mpsc::Receiver<String>,
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Child {
    /// Wait (bounded) for a line containing `needle`.
    fn expect_line(&self, needle: &str) -> String {
        let deadline = Instant::now() + SOON;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(e) => panic!("output ended or stalled waiting for {needle:?}: {e}"),
            }
        }
    }
}

/// Read `pipe` into a channel of lines.
fn lines_of(pipe: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// A `mysh serve --connect-back` process with a known host key. Both
/// fields only exist to live as long as the test: dropping it kills the
/// server and removes its config dir.
struct Serve {
    _child: Child,
    _dir: common::TempDir,
}

/// Spawn `mysh serve --connect-back 127.0.0.1:PORT --connect-period 1s
/// --connect-jitter 0` with `key` as its host identity (so the test knows
/// the fingerprint it will present) and `authorized` as the only trusted
/// client key.
fn spawn_serve(port: u16, key: &SecretKey, authorized: &SecretKey, extra: &[&str]) -> Serve {
    let dir = common::TempDir::new("accept-srv");
    let server_dir = dir.join("server");
    let home = dir.join("home");
    for d in [&server_dir, &home] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    write_secret_key(&server_dir.join("host_key"), key).expect("host key");
    let line = authorized.public().to_line(Some("acceptor"));
    let mut child = Command::new(common::mysh_bin())
        .env_clear()
        .env("MYSH_CONFIG_DIR", &server_dir)
        .env("HOME", &home)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .args([
            "serve",
            "-v",
            "--name",
            "caller-host",
            "--connect-back",
            &format!("127.0.0.1:{port}"),
            "--connect-period",
            "1s",
            "--connect-jitter",
            "0",
            "--authorized-key",
            line.trim_end(),
        ])
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mysh serve");
    let lines = lines_of(child.stderr.take().expect("stderr"));
    Serve {
        _child: Child { child, lines },
        _dir: dir,
    }
}

fn identity_of(secret: &SecretKey) -> Identity {
    Identity {
        public: secret.public(),
        secret: secret.clone(),
        format: KeyFormat::Native,
        comment: None,
        source: "test".to_owned(),
    }
}

/// An acceptor bound on loopback with `callers` as its only trust source.
async fn acceptor_with(
    key: &SecretKey,
    callers: Callers,
    reporter: Arc<dyn Reporter>,
    accept_new: bool,
) -> Acceptor {
    Acceptor::bind(
        "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        ClientIdentity::Static(identity_of(key)),
        callers,
        reporter,
        AcceptOpts {
            accept_new,
            handshakes_per_minute: 0,
        },
    )
    .await
    .expect("bind acceptor")
}

fn callers_file(dir: &common::TempDir, name: &str) -> PathBuf {
    dir.join(name)
}

async fn next_inbound(acceptor: &mut Acceptor) -> Inbound {
    tokio::time::timeout(SOON, acceptor.next())
        .await
        .expect("an inbound connection in time")
        .expect("the acceptor is still listening")
}

/// Collects every reported event.
#[derive(Debug, Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
}

impl Recorder {
    fn events(&self) -> Vec<Event> {
        self.events.lock().expect("lock").clone()
    }

    /// Wait (bounded) for an event matching `want`.
    async fn wait_for(&self, want: impl Fn(&Event) -> bool) -> Event {
        let deadline = Instant::now() + SOON;
        loop {
            if let Some(ev) = self.events().into_iter().find(&want) {
                return ev;
            }
            assert!(
                Instant::now() < deadline,
                "no matching event: {:?}",
                self.events()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Reporter for Recorder {
    fn event(&self, ev: &Event) {
        self.events.lock().expect("lock").push(ev.clone());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_connection_per_period_and_exec_works() {
    let dir = common::TempDir::new("accept-period");
    let client_key = SecretKey::generate();
    let server_key = SecretKey::generate();
    let callers = Callers::parse(
        &server_key.public().to_line(Some("alpha")),
        "callers",
        callers_file(&dir, "callers"),
    );
    let mut acceptor = acceptor_with(&client_key, callers, Arc::new(NullReporter), false).await;
    let serve = spawn_serve(acceptor.local_addr().port(), &server_key, &client_key, &[]);

    let first = next_inbound(&mut acceptor).await;
    assert_eq!(first.caller.name.as_deref(), Some("alpha"));
    assert_eq!(first.caller.fingerprint, server_key.public().fingerprint());
    assert_eq!(first.name, "caller-host", "ServerHello.name");
    assert_eq!(first.peer.ip().to_string(), "127.0.0.1");

    let result = first
        .client
        .exec(ExecRequest {
            argv: vec!["echo ok".to_owned()],
            ..ExecRequest::default()
        })
        .await
        .expect("exec on the accepted connection");
    assert_eq!(result.exit, Some(0));
    assert_eq!(result.stdout.as_bytes(), b"ok\n");

    // While this connection is held, the server opens no second one.
    assert!(
        tokio::time::timeout(Duration::from_secs(3), acceptor.next())
            .await
            .is_err(),
        "a second connection arrived while the first was open"
    );

    let released = Instant::now();
    first.client.close().await;
    let second = next_inbound(&mut acceptor).await;
    assert_eq!(second.caller.name.as_deref(), Some("alpha"));
    assert!(
        released.elapsed() < SOON,
        "the next connection took {:?}",
        released.elapsed()
    );
    second.client.close().await;
    drop(serve);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_callers_are_queued_and_consumed() {
    let dir = common::TempDir::new("accept-two");
    let client_key = SecretKey::generate();
    let key_a = SecretKey::generate();
    let key_b = SecretKey::generate();
    let text = format!(
        "{}{}",
        key_a.public().to_line(Some("alpha")),
        key_b.public().to_line(Some("beta"))
    );
    let callers = Callers::parse(&text, "callers", callers_file(&dir, "callers"));
    let mut acceptor = acceptor_with(&client_key, callers, Arc::new(NullReporter), false).await;
    let port = acceptor.local_addr().port();
    let serve_a = spawn_serve(port, &key_a, &client_key, &[]);
    let serve_b = spawn_serve(port, &key_b, &client_key, &[]);

    let first = next_inbound(&mut acceptor).await;
    let second = next_inbound(&mut acceptor).await;
    let mut names = vec![first.caller.label(), second.caller.label()];
    names.sort();
    assert_eq!(names, vec!["alpha".to_owned(), "beta".to_owned()]);
    // Both are usable connections, not just handshakes.
    for inbound in [first, second] {
        let out = inbound
            .client
            .exec(ExecRequest {
                argv: vec!["echo hi".to_owned()],
                ..ExecRequest::default()
            })
            .await
            .expect("exec");
        assert_eq!(out.stdout.as_bytes(), b"hi\n");
        inbound.client.close().await;
    }
    drop((serve_a, serve_b));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_caller_is_refused_and_accept_new_records_it() {
    let dir = common::TempDir::new("accept-unknown");
    let client_key = SecretKey::generate();
    let server_key = SecretKey::generate();
    let path = callers_file(&dir, "callers");
    let recorder = Arc::new(Recorder::default());
    let mut acceptor = acceptor_with(
        &client_key,
        Callers::parse("", "callers", path.clone()),
        recorder.clone(),
        false,
    )
    .await;
    let serve = spawn_serve(acceptor.local_addr().port(), &server_key, &client_key, &[]);

    let refused = recorder
        .wait_for(|ev| matches!(ev, Event::Refused { .. }))
        .await;
    match refused {
        Event::Refused {
            fingerprint,
            reason,
            ..
        } => {
            assert_eq!(fingerprint, server_key.public().fingerprint().to_string());
            assert!(reason.contains("not a caller"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(2), acceptor.next())
            .await
            .is_err(),
        "a refused connection reached next()"
    );
    assert!(!path.exists(), "a refusal must not record the key");
    drop(acceptor);
    drop(serve);

    // The same server against an acceptor with `--accept-new`.
    let mut acceptor = acceptor_with(
        &client_key,
        Callers::parse("", "callers", path.clone()),
        Arc::new(NullReporter),
        true,
    )
    .await;
    let serve = spawn_serve(acceptor.local_addr().port(), &server_key, &client_key, &[]);
    let inbound = next_inbound(&mut acceptor).await;
    assert_eq!(inbound.caller.name, None, "a recorded caller has no name");
    assert_eq!(inbound.caller.label().len(), 12);
    let text = std::fs::read_to_string(&path).expect("callers file");
    assert!(
        text.contains(server_key.public().to_line(None).trim_end()),
        "{text}"
    );
    inbound.client.close().await;
    drop(serve);
}

/// `mysh accept --json` with a client config dir of its own.
struct AcceptCli {
    child: Child,
    addr: String,
    env: Vec<(String, String)>,
    runtime_dir: PathBuf,
    _dir: common::TempDir,
}

/// Spawn `mysh accept 127.0.0.1:0 --json --callers PATH` whose identity is
/// `client_key`, and wait for its "accepting connections" notice.
fn spawn_accept(client_key: &SecretKey, callers_text: &str, extra: &[&str]) -> AcceptCli {
    let dir = common::TempDir::short("accept-cli");
    let client_dir = dir.join("client");
    let home = dir.join("home");
    let runtime_dir = dir.join("run");
    for d in [&client_dir, &home, &runtime_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    write_secret_key(&client_dir.join("id"), client_key).expect("client key");
    write_public_key(&client_dir.join("id.pub"), &client_key.public(), Some("it")).expect("pub");
    let callers = client_dir.join("callers");
    std::fs::write(&callers, callers_text).expect("callers");
    let env = vec![
        (
            "MYSH_CONFIG_DIR".to_owned(),
            client_dir.display().to_string(),
        ),
        ("HOME".to_owned(), home.display().to_string()),
        (
            "XDG_RUNTIME_DIR".to_owned(),
            runtime_dir.display().to_string(),
        ),
        ("PATH".to_owned(), std::env::var("PATH").unwrap_or_default()),
        ("SSH_AUTH_SOCK".to_owned(), String::new()),
    ];
    let mut child = Command::new(common::mysh_bin())
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .args(["accept", "127.0.0.1:0", "--json"])
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mysh accept");
    let lines = lines_of(child.stdout.take().expect("stdout"));
    let child = Child { child, lines };
    let notice = child.expect_line("accepting connections on");
    let value: serde_json::Value = serde_json::from_str(&notice).expect("notice json");
    let text = value["text"].as_str().expect("notice text").to_owned();
    let addr = text
        .split("on ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("the bound address")
        .to_owned();
    AcceptCli {
        child,
        addr,
        env,
        runtime_dir: runtime_dir.join("mysh"),
        _dir: dir,
    }
}

impl AcceptCli {
    fn port(&self) -> u16 {
        self.addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .expect("port")
    }

    /// `mysh …` with this client's environment.
    fn mysh(&self, args: &[&str]) -> std::process::Output {
        Command::new(common::mysh_bin())
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run mysh")
    }
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + SOON;
    while !path.exists() {
        assert!(Instant::now() < deadline, "no socket at {}", path.display());
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_cli_serves_named_sockets_and_binds_on_request() {
    let client_key = SecretKey::generate();
    let server_key = SecretKey::generate();
    let accept = spawn_accept(
        &client_key,
        &server_key.public().to_line(Some("alpha")),
        &[],
    );
    let serve = spawn_serve(
        accept.port(),
        &server_key,
        &client_key,
        &["--allow-bind-request"],
    );

    let line = accept.child.expect_line("\"event\":\"accepted\"");
    let ev: serde_json::Value = serde_json::from_str(&line).expect("accepted json");
    assert_eq!(ev["name"], "alpha");
    assert_eq!(
        ev["fingerprint"],
        server_key.public().fingerprint().to_string()
    );
    assert!(
        ev["addr"].as_str().expect("addr").starts_with("127.0.0.1:"),
        "{ev}"
    );
    assert_eq!(ev["server"]["name"], "caller-host");

    let socket = accept.runtime_dir.join("@alpha.sock");
    wait_for_socket(&socket);

    // The rest of the CLI reaches the accepted connection as `@alpha`.
    let out = accept.mysh(&["--json", "@alpha", "echo ok"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("exec result json");
    assert_eq!(doc["stdout"], "ok\n");

    // An unknown name never dials.
    let out = accept.mysh(&["--json", "@missing", "true"]);
    assert_ne!(out.status.code(), Some(0));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).expect("error json on stderr");
    assert_eq!(err["error"]["code"], "connect_failed");
    assert!(
        err["error"]["message"]
            .as_str()
            .expect("message")
            .contains("missing"),
        "{err}"
    );

    // `bind` over the accepted connection's socket: the server opens a
    // listener a plain dialed client can use.
    let out = accept.mysh(&["bind", "--json", "@alpha", "127.0.0.1:0"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("bind json");
    let bound = doc["bound"].as_str().expect("bound address").to_owned();
    assert!(bound.starts_with("127.0.0.1:"), "{bound}");
    assert_ne!(bound, "127.0.0.1:0", "port 0 must be resolved");

    let out = accept.mysh(&["--accept-new", &bound, "echo dialed"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"dialed\n");

    drop(serve);
    drop(accept);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_is_denied_without_the_server_flag() {
    let dir = common::TempDir::new("accept-bind");
    let client_key = SecretKey::generate();
    let server_key = SecretKey::generate();
    let callers = Callers::parse(
        &server_key.public().to_line(Some("alpha")),
        "callers",
        callers_file(&dir, "callers"),
    );
    let mut acceptor = acceptor_with(&client_key, callers, Arc::new(NullReporter), false).await;
    let serve = spawn_serve(acceptor.local_addr().port(), &server_key, &client_key, &[]);
    let inbound = next_inbound(&mut acceptor).await;
    let err = inbound
        .client
        .connection()
        .bind("127.0.0.1:0", Duration::ZERO)
        .await
        .expect_err("bind must be refused");
    assert_eq!(mysh_client::types::code_for(&err), "denied", "{err:#}");
    assert!(
        format!("{err:#}").contains("bind requests are not allowed"),
        "{err:#}"
    );
    // The connection still works afterwards.
    let out = inbound
        .client
        .exec(ExecRequest {
            argv: vec!["echo still".to_owned()],
            ..ExecRequest::default()
        })
        .await
        .expect("exec");
    assert_eq!(out.stdout.as_bytes(), b"still\n");
    inbound.client.close().await;
    drop(serve);
}
