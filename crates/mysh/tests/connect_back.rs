//! `mysh serve --connect-back` through the real binary (docs/03-protocol.md
//! §1 and §6, docs/06-roadmap.md M12): the server dials an accepting client
//! once per period and never has two connections to one address open;
//! the accepted connection serves sessions like any other; `--connect-max`
//! ends it from the server side; a refused handshake is retried with
//! backoff; `Bind` is refused without `--allow-bind-request` and binds a
//! real listener with it.
//!
//! The accepting side here is a minimal in-test acceptor: a `TcpListener`,
//! the Noise initiator handshake, a client-mode mux and the control stream.

mod common;

use std::{
    io::{BufRead as _, BufReader},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use mysh_client::{
    AcceptOpts, Acceptor, ExecRequest, NullReporter,
    identity::{Callers, ClientIdentity},
};
use mysh_net::{
    framing::{read_msg, write_msg},
    handshake::{ClientAuth, HandshakeError, client_handshake},
    keys::{Identity, KeyFormat, SecretKey, write_public_key, write_secret_key},
    mux::{Mode, Mux, Stream},
};
use mysh_proto::{
    control::ControlMsg,
    handshake::ServerHello,
    open::{ErrorCode, Open},
    session::{ExitStatus, SessionKind, SessionOut, SessionRequest},
};
use tokio::net::TcpListener;

/// Generous bound for anything that should happen "promptly".
const SOON: Duration = Duration::from_secs(10);

/// Kills and reaps the spawned `mysh serve` however the test ends.
struct Serve {
    child: std::process::Child,
    /// Its stderr, line by line.
    lines: mpsc::Receiver<String>,
    /// Temp tree (config dirs, home, runtime dir); removed on drop.
    dir: common::TempDir,
    /// Config dir of a client whose identity is the acceptor's key.
    client_dir: std::path::PathBuf,
    home: std::path::PathBuf,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Serve {
    /// Wait (bounded) for a stderr line containing `needle`.
    fn expect_line(&self, needle: &str) -> String {
        let deadline = Instant::now() + SOON;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(e) => panic!("server stderr ended or stalled waiting for {needle:?}: {e}"),
            }
        }
    }

    /// Environment for a `mysh` client child using the acceptor's identity.
    fn client_env(&self) -> Vec<(String, String)> {
        vec![
            (
                "MYSH_CONFIG_DIR".into(),
                self.client_dir.display().to_string(),
            ),
            ("HOME".into(), self.home.display().to_string()),
            (
                "XDG_RUNTIME_DIR".into(),
                self.dir.join("run").display().to_string(),
            ),
            ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
            ("SSH_AUTH_SOCK".into(), String::new()),
        ]
    }
}

/// Spawn `mysh serve -vv --connect-back 127.0.0.1:PORT --connect-period 1s
/// --connect-jitter 0 <extra>` trusting `authorized` with a throwaway
/// config dir; the acceptor's `client_key` is also written as the identity
/// of a client under `<dir>/client` (for dialing a requested listener).
fn spawn_serve(port: u16, authorized: &SecretKey, client_key: &SecretKey, extra: &[&str]) -> Serve {
    let dir = common::TempDir::new("connect-back");
    let server_dir = dir.join("server");
    let client_dir = dir.join("client");
    let home = dir.join("home");
    for d in [&server_dir, &client_dir, &home] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    write_secret_key(&client_dir.join("id"), client_key).expect("client key");
    write_public_key(&client_dir.join("id.pub"), &client_key.public(), Some("it")).expect("pub");
    let line = authorized.public().to_line(Some("acceptor"));

    let mut child = Command::new(common::mysh_bin())
        .env_clear()
        .env("MYSH_CONFIG_DIR", &server_dir)
        .env("HOME", &home)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .args([
            "serve",
            "-vv",
            "--name",
            "caller",
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
    let (tx, lines) = mpsc::channel::<String>();
    let stderr = child.stderr.take().expect("stderr");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    Serve {
        child,
        lines,
        dir,
        client_dir,
        home,
    }
}

/// One accepted, handshaken connection.
struct Inbound {
    mux: Mux,
    control: Stream,
    hello: ServerHello,
    /// When the TCP connection arrived.
    at: Instant,
}

/// The in-test accepting client (wire level, so refusals and raw control
/// messages are observable).
struct TestAcceptor {
    listener: TcpListener,
    key: SecretKey,
}

impl TestAcceptor {
    async fn bind(key: SecretKey) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        Self { listener, key }
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().expect("local addr").port()
    }

    /// Accept the next TCP connection and run the handshake as the Noise
    /// initiator; `Err` for a refused handshake.
    async fn next(&self) -> Result<Inbound, HandshakeError> {
        let (tcp, _peer) = self.listener.accept().await?;
        let at = Instant::now();
        let (hs, hello) =
            client_handshake(tcp, &self.key, 0, |_, _| Ok(()), ClientAuth::Static).await?;
        let (mux, _incoming) = Mux::new(hs.stream, Mode::Client);
        let control = mux.open(&Open::Control).await.expect("open control");
        Ok(Inbound {
            mux,
            control,
            hello,
            at,
        })
    }

    /// [`TestAcceptor::next`] that must succeed within `SOON`.
    async fn next_ok(&self) -> Inbound {
        tokio::time::timeout(SOON, self.next())
            .await
            .expect("an inbound connection in time")
            .expect("handshake")
    }

    /// Whether a TCP connection arrives within `window` (it is accepted and
    /// dropped, so only use this when none is expected).
    async fn tcp_within(&self, window: Duration) -> bool {
        tokio::time::timeout(window, self.listener.accept())
            .await
            .is_ok()
    }
}

/// Run `sh -c CMD` over `inbound` and return its stdout and status.
async fn exec(inbound: &Inbound, cmd: &str) -> (Vec<u8>, ExitStatus) {
    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: vec!["sh".into(), "-c".into(), cmd.into()],
        },
        env: Vec::new(),
        pty: None,
        cwd: None,
        persist: false,
    };
    let mut session = inbound
        .mux
        .open(&Open::Session(req))
        .await
        .expect("open session");
    let mut out = Vec::new();
    loop {
        match read_msg::<_, SessionOut>(&mut session)
            .await
            .expect("SessionOut")
        {
            SessionOut::Stdout(chunk) => out.extend_from_slice(&chunk),
            SessionOut::Exited(status) => return (out, status),
            SessionOut::Started { .. } | SessionOut::Stderr(_) | SessionOut::Attached { .. } => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_connection_per_period_and_never_two_at_once() {
    let key = SecretKey::generate();
    let acceptor = TestAcceptor::bind(key.clone()).await;
    let serve = spawn_serve(acceptor.port(), &key, &key, &[]);
    serve.expect_line("connecting back");

    let first = acceptor.next_ok().await;
    assert_eq!(first.hello.name, "caller");
    // The invariant: while this connection is open no second one is dialed,
    // even though three periods elapse.
    assert!(
        !acceptor.tcp_within(Duration::from_secs(3)).await,
        "a second connection arrived while the first was still open"
    );
    first.mux.close().await;
    drop(first.control);

    // The period boundary has long passed: the next attempt is immediate.
    let second = acceptor.next_ok().await;
    assert!(
        second.at.duration_since(first.at) < Duration::from_secs(5),
        "next connection took {:?} after the close",
        second.at.duration_since(first.at)
    );
    let second_at = second.at;
    second.mux.close().await;
    drop(second.control);

    // Closed at once: the third arrives one period after the second *started*.
    let third = acceptor.next_ok().await;
    let gap = third.at.duration_since(second_at);
    assert!(
        gap >= Duration::from_millis(900) && gap < Duration::from_millis(2500),
        "period gap {gap:?}"
    );
    third.mux.close().await;
    drop(serve);
}

/// The library's `Acceptor` (`mysh accept`) against the same server: the
/// queued `Inbound` carries a `Client` whose `exec` works.
#[tokio::test(flavor = "multi_thread")]
async fn the_library_acceptor_yields_a_working_client() {
    let key = SecretKey::generate();
    let identity = ClientIdentity::Static(Identity {
        public: key.public(),
        secret: key.clone(),
        format: KeyFormat::Native,
        comment: None,
        source: "test".to_owned(),
    });
    let callers_dir = common::TempDir::new("callers");
    // The server's key is unknown: `accept_new` records it.
    let callers = Callers::parse("", "callers", callers_dir.join("callers"));
    let mut acceptor = Acceptor::bind(
        "127.0.0.1:0".parse().expect("addr"),
        identity,
        callers,
        std::sync::Arc::new(NullReporter),
        AcceptOpts {
            accept_new: true,
            handshakes_per_minute: 0,
        },
    )
    .await
    .expect("bind acceptor");
    let serve = spawn_serve(acceptor.local_addr().port(), &key, &key, &[]);

    let inbound = tokio::time::timeout(SOON, acceptor.next())
        .await
        .expect("an inbound connection in time")
        .expect("acceptor open");
    assert_eq!(inbound.name, "caller");
    let out = inbound
        .client
        .exec(ExecRequest::argv(["sh", "-c", "echo via-acceptor"]))
        .await
        .expect("exec");
    assert_eq!(out.stdout.as_bytes(), b"via-acceptor\n");
    assert_eq!(out.exit, Some(0));
    inbound.client.close().await;
    drop(serve);
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_works_on_a_connection_the_server_dialed() {
    let key = SecretKey::generate();
    let acceptor = TestAcceptor::bind(key.clone()).await;
    let serve = spawn_serve(acceptor.port(), &key, &key, &[]);
    let inbound = acceptor.next_ok().await;

    let (out, status) = exec(&inbound, "echo ok; exit 3").await;
    assert_eq!(out, b"ok\n");
    assert_eq!(status, ExitStatus::Code(3));

    // Pings are answered on the control stream as usual.
    let mut control = inbound.control;
    write_msg(&mut control, &ControlMsg::Ping { nonce: 9 })
        .await
        .expect("ping");
    assert_eq!(
        read_msg::<_, ControlMsg>(&mut control).await.expect("pong"),
        ControlMsg::Pong { nonce: 9 }
    );
    inbound.mux.close().await;
    drop(serve);
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_max_ends_the_connection_from_the_server_side() {
    let key = SecretKey::generate();
    let acceptor = TestAcceptor::bind(key.clone()).await;
    let serve = spawn_serve(acceptor.port(), &key, &key, &["--connect-max", "1s"]);
    let mut inbound = acceptor.next_ok().await;

    let notice = tokio::time::timeout(SOON, read_msg::<_, ControlMsg>(&mut inbound.control))
        .await
        .expect("a control message in time")
        .expect("read control");
    let after = inbound.at.elapsed();
    assert_eq!(
        notice,
        ControlMsg::Shutdown {
            reason: "connect-back: max connection time".to_owned()
        }
    );
    assert!(
        after >= Duration::from_millis(800) && after < Duration::from_secs(4),
        "shutdown notice after {after:?}"
    );
    serve.expect_line("maximum connection time");
    inbound.mux.close().await;

    // The loop goes on: the next connection comes one period after the
    // previous start.
    let next = acceptor.next_ok().await;
    next.mux.close().await;
    drop(serve);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_handshake_is_retried_with_backoff() {
    let acceptor_key = SecretKey::generate();
    let authorized = SecretKey::generate();
    let acceptor = TestAcceptor::bind(acceptor_key).await;
    let serve = spawn_serve(acceptor.port(), &authorized, &authorized, &[]);

    let mut arrivals = Vec::new();
    for _ in 0..3 {
        match tokio::time::timeout(SOON, acceptor.next()).await {
            Ok(Err(HandshakeError::Denied { code, .. })) => {
                assert_eq!(code, ErrorCode::Unauthorized);
            }
            Ok(Err(other)) => panic!("expected a refused handshake, got {other:?}"),
            Ok(Ok(_)) => panic!("the handshake succeeded with an unauthorized key"),
            Err(elapsed) => panic!("no connection attempt in time: {elapsed}"),
        }
        arrivals.push(Instant::now());
    }
    // Retries are one period apart (the backoff is capped at the period).
    for pair in arrivals.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap >= Duration::from_millis(800) && gap < Duration::from_millis(3000),
            "retry gap {gap:?}"
        );
    }
    serve.expect_line("unauthorized client key");
    let first = serve.expect_line("connect-back failed");
    assert!(first.contains("WARN"), "{first}");
    let again = serve.expect_line("connect-back failed again");
    assert!(again.contains("DEBUG"), "{again}");
    drop(serve);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_is_refused_without_allow_bind_request() {
    let key = SecretKey::generate();
    let acceptor = TestAcceptor::bind(key.clone()).await;
    let serve = spawn_serve(acceptor.port(), &key, &key, &[]);
    let mut inbound = acceptor.next_ok().await;

    write_msg(
        &mut inbound.control,
        &ControlMsg::Bind {
            addr: "127.0.0.1:0".to_owned(),
            idle_secs: 5,
        },
    )
    .await
    .expect("send Bind");
    let reply = tokio::time::timeout(SOON, read_msg::<_, ControlMsg>(&mut inbound.control))
        .await
        .expect("a reply in time")
        .expect("read reply");
    assert_eq!(
        reply,
        ControlMsg::Unbound {
            addr: "127.0.0.1:0".to_owned(),
            reason: "bind requests are not allowed".to_owned()
        }
    );
    // Pings still work afterwards.
    write_msg(&mut inbound.control, &ControlMsg::Ping { nonce: 1 })
        .await
        .expect("ping");
    assert_eq!(
        read_msg::<_, ControlMsg>(&mut inbound.control)
            .await
            .expect("pong"),
        ControlMsg::Pong { nonce: 1 }
    );
    inbound.mux.close().await;
    drop(serve);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_with_allow_bind_request_serves_dialed_clients_until_idle() {
    let key = SecretKey::generate();
    let acceptor = TestAcceptor::bind(key.clone()).await;
    let serve = spawn_serve(acceptor.port(), &key, &key, &["--allow-bind-request"]);
    let mut inbound = acceptor.next_ok().await;

    write_msg(
        &mut inbound.control,
        &ControlMsg::Bind {
            addr: "127.0.0.1:0".to_owned(),
            idle_secs: 2,
        },
    )
    .await
    .expect("send Bind");
    let bound = match tokio::time::timeout(SOON, read_msg::<_, ControlMsg>(&mut inbound.control))
        .await
        .expect("a reply in time")
        .expect("read reply")
    {
        ControlMsg::Bound { addr } => addr,
        other => panic!("expected Bound, got {other:?}"),
    };
    assert!(bound.starts_with("127.0.0.1:"), "{bound}");
    assert_ne!(bound, "127.0.0.1:0", "port 0 must be resolved");
    serve.expect_line("listener bound on request");

    // A plain dialed client works through the requested listener.
    let out = Command::new(common::mysh_bin())
        .env_clear()
        .envs(serve.client_env())
        .args(["--accept-new", &bound, "echo ok"])
        .stdin(Stdio::null())
        .output()
        .expect("run mysh HOST 'echo ok'");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"ok\n");

    // Idle for 2 s without a connection: the listener goes away and the
    // requesting connection is told.
    let unbound = tokio::time::timeout(SOON, read_msg::<_, ControlMsg>(&mut inbound.control))
        .await
        .expect("Unbound in time")
        .expect("read Unbound");
    match unbound {
        ControlMsg::Unbound { addr, reason } => {
            assert_eq!(addr, bound);
            assert!(reason.contains("idle"), "{reason}");
        }
        other => panic!("expected Unbound, got {other:?}"),
    }
    serve.expect_line("requested listener closed");
    let refused = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(&bound),
    )
    .await;
    assert!(
        matches!(refused, Ok(Err(_))),
        "listener still accepting: {refused:?}"
    );

    // A second request on the same connection works again, and `Unbind`
    // closes it at once.
    write_msg(
        &mut inbound.control,
        &ControlMsg::Bind {
            addr: "127.0.0.1:0".to_owned(),
            idle_secs: 0,
        },
    )
    .await
    .expect("send Bind");
    let second = tokio::time::timeout(SOON, read_msg::<_, ControlMsg>(&mut inbound.control))
        .await
        .expect("a reply in time")
        .expect("read reply");
    let ControlMsg::Bound { addr: second_addr } = second else {
        panic!("expected Bound, got {second:?}");
    };
    write_msg(&mut inbound.control, &ControlMsg::Unbind)
        .await
        .expect("send Unbind");
    let reply = tokio::time::timeout(SOON, read_msg::<_, ControlMsg>(&mut inbound.control))
        .await
        .expect("a reply in time")
        .expect("read reply");
    assert_eq!(
        reply,
        ControlMsg::Unbound {
            addr: second_addr,
            reason: "unbind requested".to_owned()
        }
    );
    // No second `Unbound` follows for the same listener.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            read_msg::<_, ControlMsg>(&mut inbound.control)
        )
        .await
        .is_err(),
        "an extra control message arrived"
    );
    inbound.mux.close().await;
    drop(serve);
}
