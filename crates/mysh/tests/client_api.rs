//! `mysh_client::Client` against the in-process harness server: every
//! facade method, no binary spawn (docs/07-embedding.md "Library").

mod common;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use common::{ServerOpts, TestServer};
use mysh::cli::ConnectOpts;
use mysh_client::{
    Client, Error, ExecRequest, NullReporter, RefuseUnknown, Reporter, TrustPrompt,
    args::SyncArgs,
    config::{ForwardSpec, Target},
    fleet,
    identity::Baked,
    session_api::NewArgs,
    sync::SyncOutcome,
    types::{Event, codes},
};
use mysh_net::keys::Fingerprint;
use mysh_proto::session::{Signal, WinSize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

/// Collects every event, for assertions on what the library reports.
#[derive(Default)]
struct Collect(Mutex<Vec<Event>>);

impl Reporter for Collect {
    fn event(&self, ev: &Event) {
        self.0.lock().expect("lock").push(ev.clone());
    }
}

impl Collect {
    fn events(&self) -> Vec<Event> {
        self.0.lock().expect("lock").clone()
    }
}

/// Answers the TOFU question with a fixed verdict and counts the asks.
struct Answer {
    yes: bool,
    asked: Mutex<Vec<(String, u16, String)>>,
}

impl Answer {
    fn new(yes: bool) -> Arc<Self> {
        Arc::new(Self {
            yes,
            asked: Mutex::new(Vec::new()),
        })
    }
}

impl TrustPrompt for Answer {
    fn confirm_unknown(&self, host: &str, port: u16, fp: &Fingerprint) -> bool {
        self.asked
            .lock()
            .expect("lock")
            .push((host.to_owned(), port, fp.to_string()));
        self.yes
    }
}

async fn client(server: &TestServer) -> Client {
    Client::connect(
        &server.target(ConnectOpts::default()),
        &server.client_paths(),
        &Baked::default(),
        Arc::new(NullReporter),
        Arc::new(RefuseUnknown),
    )
    .await
    .expect("connect")
}

fn argv(words: &[&str]) -> ExecRequest {
    ExecRequest::argv(words.iter().copied())
}

#[tokio::test]
async fn exec_collects_output_exit_and_streams_events() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;

    let out = client
        .exec(argv(&["sh", "-c", "echo out; echo err >&2; exit 3"]))
        .await
        .expect("exec");
    assert_eq!(out.stdout.as_bytes(), b"out\n");
    assert_eq!(out.stderr.as_bytes(), b"err\n");
    assert_eq!(out.exit, Some(3));
    assert_eq!(out.code(), 3);
    assert!(!out.timed_out);

    // A single word runs through the shell; stdin is delivered then closed.
    let mut req = argv(&["cat"]);
    req.stdin = Some(b"fed\n".to_vec());
    let events = Mutex::new(Vec::new());
    let out = client
        .exec_stream(req, |ev| events.lock().expect("lock").push(ev))
        .await
        .expect("exec_stream");
    assert_eq!(out.stdout.as_bytes(), b"fed\n");
    assert_eq!(out.exit, Some(0));
    let events = events.into_inner().expect("lock");
    assert!(matches!(events.first(), Some(Event::Started { .. })));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Stdout { data } if data.as_bytes() == b"fed\n"))
    );
    assert!(matches!(
        events.last(),
        Some(Event::Exit {
            exit: Some(0),
            timed_out: false,
            ..
        })
    ));

    // `cwd` and `env` reach the process (the harness accepts no env by
    // default, so only `cwd` is checked here).
    let mut req = argv(&["pwd"]);
    req.cwd = Some("/".to_owned());
    let out = client.exec(req).await.expect("exec cwd");
    assert_eq!(out.stdout.as_bytes(), b"/\n");

    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn exec_timeout_terminates_and_flags() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let mut req = argv(&["sleep", "30"]);
    req.timeout = Some(Duration::from_millis(300));
    let started = std::time::Instant::now();
    let out = client.exec(req).await.expect("exec");
    assert!(out.timed_out);
    assert_eq!(out.code(), 124);
    assert!(out.exit.is_none());
    assert!(out.signal.is_some(), "killed by a signal: {out:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn exec_with_pty_merges_streams() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let mut req = argv(&["sh", "-c", "stty size; echo err >&2"]);
    req.pty = Some(WinSize {
        cols: 100,
        rows: 30,
        xpixel: 0,
        ypixel: 0,
    });
    let out = client.exec(req).await.expect("exec");
    let text = String::from_utf8_lossy(out.stdout.as_bytes()).replace("\r\n", "\n");
    assert!(text.contains("30 100"), "pty size seen: {text:?}");
    assert!(text.contains("err"), "stderr merged into the pty: {text:?}");
    assert_eq!(out.stderr.as_bytes(), b"");
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn info_reports_server_and_connection() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let info = client.info().await.expect("info");
    let srv = info.server.expect("server info");
    assert_ne!(srv.platform.os, "");
    assert_eq!(info.connection.port, server.port());
    assert_eq!(
        info.connection.peer_fingerprint,
        server.server_key.fingerprint().to_string()
    );
    assert_eq!(info.sessions.len(), 0);
    assert_eq!(info.forwards.len(), 0);
    assert_eq!(client.connection().remote_key(), server.server_key);
    assert!(client.is_connected());
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn sessions_round_trip() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let sessions = client.sessions();

    let s = sessions
        .new(&NewArgs {
            command: vec!["cat".to_owned()],
            ..NewArgs::default()
        })
        .await
        .expect("new");
    assert!(s.id > 0 && s.pid > 0);

    let listed = sessions.list().await.expect("list");
    assert!(listed.iter().any(|r| r.id == s.id));

    sessions.send(s.id, b"ping\n", false).await.expect("send");
    let read = sessions
        .read(s.id, 0, 1024, Duration::from_secs(5))
        .await
        .expect("read");
    let text: Vec<u8> = read
        .chunks
        .iter()
        .flat_map(|c| c.data.as_bytes().to_vec())
        .collect();
    assert_eq!(text, b"ping\n");
    assert!(read.exited.is_none());

    // Re-reading the same offset is idempotent.
    let again = sessions
        .read(s.id, 0, 1024, Duration::ZERO)
        .await
        .expect("read again");
    assert_eq!(again.next, read.next);

    // `wait` with a timeout gives up without ending the session.
    let w = sessions
        .wait(s.id, Some(Duration::from_millis(200)))
        .await
        .expect("wait");
    assert!(w.is_none());

    sessions.kill(s.id, Signal::Term).await.expect("kill");
    let exit = sessions
        .wait(s.id, Some(Duration::from_secs(10)))
        .await
        .expect("wait")
        .expect("exited");
    assert!(exit.signal.is_some() || exit.exit.is_some());

    // EOF ends a session on its own.
    let s = sessions
        .new(&NewArgs {
            command: vec!["cat".to_owned()],
            ..NewArgs::default()
        })
        .await
        .expect("new");
    sessions.send(s.id, b"", true).await.expect("eof");
    let exit = sessions
        .wait(s.id, Some(Duration::from_secs(10)))
        .await
        .expect("wait")
        .expect("exited");
    assert_eq!(exit.exit, Some(0));

    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn files_round_trip() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let files = client.files();

    assert!(files.stat("nope").await.expect("stat").is_none());
    files.mkdir("d", None).await.expect("mkdir");
    files.mkdir("d", None).await.expect("mkdir again is fine");
    let written = files
        .write("d/a.txt", b"hello\n", Some(0o640), false)
        .await
        .expect("write");
    assert_eq!(written, 6);
    let appended = files
        .write("d/a.txt", b"more\n", None, true)
        .await
        .expect("append");
    assert_eq!(appended, 5);

    let st = files.stat("d/a.txt").await.expect("stat").expect("exists");
    assert_eq!(st.kind, "file");
    assert_eq!(st.size, 11);
    assert_eq!(st.mode, "0640");

    let (attrs, bytes) = files.read("d/a.txt", 0, None).await.expect("read");
    assert_eq!(bytes, b"hello\nmore\n");
    assert_eq!(attrs.size, 11);
    let (_, part) = files.read("d/a.txt", 6, Some(2)).await.expect("read range");
    assert_eq!(part, b"mo");
    let mut sink = Vec::new();
    let (_, n) = files
        .read_to("d/a.txt", 0, &mut sink)
        .await
        .expect("read_to");
    assert_eq!(n, 11);
    assert_eq!(sink, b"hello\nmore\n");

    let tail = files.tail("d/a.txt", 1).await.expect("tail");
    assert_eq!(tail, b"more\n");

    let h = files.hash("d/a.txt").await.expect("hash");
    assert_eq!(h.size, 11);
    assert_eq!(h.algo, "blake2s256");
    assert_eq!(h.digest.len(), 64);

    files
        .write("d/.hidden", b"", None, false)
        .await
        .expect("write hidden");
    let listed = files.list("d", false).await.expect("list");
    assert_eq!(
        listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        vec!["a.txt"]
    );
    let all = files.list("d", true).await.expect("list all");
    assert_eq!(all.len(), 2);

    let real = files.realpath("d/a.txt").await.expect("realpath");
    assert_eq!(
        PathBuf::from(&real),
        server
            .home
            .join("d/a.txt")
            .canonicalize()
            .expect("canonical")
    );

    files.rename("d/a.txt", "d/b.txt").await.expect("rename");
    assert!(files.stat("d/a.txt").await.expect("stat").is_none());

    // put / get of one file, with progress reaching the reporter.
    let local = server.dir.join("local");
    std::fs::create_dir_all(&local).expect("mkdir local");
    let src = local.join("up.bin");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &payload).expect("write local");
    let up = files.put(&src, "d/up.bin", false).await.expect("put");
    assert_eq!(up.files, 1);
    assert_eq!(up.bytes, payload.len() as u64);
    let skipped = files
        .put(&src, "d/up.bin", true)
        .await
        .expect("put checksum");
    assert_eq!(skipped.skipped, 1);
    assert_eq!(skipped.bytes, 0);
    let dst = local.join("down.bin");
    let down = files.get("d/up.bin", &dst, false).await.expect("get");
    assert_eq!(down.files, 1);
    assert_eq!(std::fs::read(&dst).expect("read local"), payload);

    files.remove("d/up.bin", false).await.expect("rm");
    let err = files.remove("d", false).await.expect_err("dir needs -r");
    assert!(
        !err.code.is_empty() && err.code != codes::INTERNAL,
        "classified: {} ({err})",
        err.code
    );
    files.remove("d", true).await.expect("rm -r");
    assert!(files.stat("d").await.expect("stat").is_none());

    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn files_sync_plan_and_run() {
    let server = common::start_server(ServerOpts::default()).await;
    let reporter = Arc::new(Collect::default());
    let client = Client::connect(
        &server.target(ConnectOpts::default()),
        &server.client_paths(),
        &Baked::default(),
        reporter.clone(),
        Arc::new(RefuseUnknown),
    )
    .await
    .expect("connect");
    let local = server.dir.join("tree");
    std::fs::create_dir_all(local.join("sub")).expect("mkdir");
    std::fs::write(local.join("one.txt"), b"1").expect("write");
    std::fs::write(local.join("sub/two.txt"), b"22").expect("write");

    let args = SyncArgs {
        src: local.display().to_string(),
        dst: "synced".to_owned(),
        dry_run: true,
        ..SyncArgs::default()
    };
    match client
        .files()
        .sync(&args, &server.dir.0)
        .await
        .expect("sync --dry-run")
    {
        SyncOutcome::Plan(plan) => {
            assert_eq!(plan.copies.len(), 2);
            assert_eq!(plan.bytes, 3);
        }
        SyncOutcome::Summary(s) => panic!("expected a plan, got {s:?}"),
    }
    let args = SyncArgs {
        dry_run: false,
        ..args
    };
    match client
        .files()
        .sync(&args, &server.dir.0)
        .await
        .expect("sync")
    {
        SyncOutcome::Summary(s) => {
            assert_eq!(s.copied, 2);
            assert_eq!(s.bytes, 3);
        }
        SyncOutcome::Plan(p) => panic!("expected a summary, got {p:?}"),
    }
    assert_eq!(
        std::fs::read(server.home.join("synced/sub/two.txt")).expect("synced file"),
        b"22"
    );
    // Progress of the transfer reached the reporter as events.
    assert!(
        reporter
            .events()
            .iter()
            .any(|e| matches!(e, Event::Progress { .. })),
        "events: {:?}",
        reporter.events()
    );
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn forwards_add_list_remove() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo.local_addr().expect("addr").port();
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = s.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    let spec =
        ForwardSpec::parse_local(&format!("127.0.0.1:0:127.0.0.1:{echo_port}")).expect("spec");
    let id = client.forwards().add_local(&spec).await.expect("add -L");
    let bind = client
        .forwards()
        .list()
        .into_iter()
        .find(|f| f.id == id)
        .expect("listed")
        .bind;
    let mut stream = TcpStream::connect(bind).await.expect("connect -L");
    stream.write_all(b"ping").await.expect("write");
    stream.shutdown().await.expect("shutdown");
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.expect("read");
    assert_eq!(got, b"ping");
    assert_eq!(client.info().await.expect("info").forwards.len(), 1);
    assert!(client.forwards().remove(id).await);
    assert_eq!(client.forwards().list().len(), 0);
    echo_task.abort();
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn trust_prompt_decides_unknown_keys() {
    let server = common::start_server(ServerOpts::default()).await;
    let paths = server.client_paths();
    // The harness `target()` sets `accept_new`; a plain target asks.
    let target = Target {
        accept_new: false,
        ..server.target(ConnectOpts::default())
    };
    let refuse = Answer::new(false);
    let err = Client::connect(
        &target,
        &paths,
        &Baked::default(),
        Arc::new(NullReporter),
        refuse.clone(),
    )
    .await
    .expect_err("refused");
    assert_eq!(err.code, codes::TRUST_UNKNOWN);
    assert!(err.to_string().contains("not in known_hosts"), "{err}");
    assert_eq!(refuse.asked.lock().expect("lock").len(), 1);
    assert!(!paths.known_hosts.exists());

    let accept = Answer::new(true);
    let client = Client::connect(
        &target,
        &paths,
        &Baked::default(),
        Arc::new(NullReporter),
        accept.clone(),
    )
    .await
    .expect("accepted");
    let asked = accept.asked.lock().expect("lock").clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].1, server.port());
    assert_eq!(asked[0].2, server.server_key.fingerprint().to_string());
    assert!(paths.known_hosts.exists());
    assert!(client.connection().trusted_via().contains("known_hosts"));
    client.close().await;

    // Now known: no prompt at all, even with the refusing prompt.
    let client = Client::connect(
        &target,
        &paths,
        &Baked::default(),
        Arc::new(NullReporter),
        Arc::new(RefuseUnknown),
    )
    .await
    .expect("known host");
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn errors_carry_stable_codes() {
    let server = common::start_server(ServerOpts::default()).await;
    let client = client(&server).await;
    let err: Error = client
        .files()
        .read("missing.txt", 0, None)
        .await
        .expect_err("missing file");
    assert_eq!(err.code, codes::NOT_FOUND);
    assert!(std::error::Error::source(&err).is_some() || !err.message().is_empty());

    let dead = Target {
        port: 1,
        ..server.target(ConnectOpts::default())
    };
    let err = Client::connect(
        &dead,
        &server.client_paths(),
        &Baked::default(),
        Arc::new(NullReporter),
        Arc::new(RefuseUnknown),
    )
    .await
    .expect_err("unreachable");
    assert_eq!(err.code, codes::CONNECT_FAILED);
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn reconnect_after_loss() {
    let server = common::start_server(ServerOpts::default()).await;
    let mut client = client(&server).await;
    client.connection().close().await;
    assert!(!client.is_connected());
    let err = client.exec(argv(&["true"])).await.expect_err("closed");
    assert_ne!(err.code, "");
    client.reconnect().await.expect("reconnect");
    assert!(client.is_connected());
    let out = client.exec(argv(&["echo", "back"])).await.expect("exec");
    assert_eq!(out.stdout.as_bytes(), b"back\n");
    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn fleet_run_fans_out_in_order() {
    let a = common::start_server(ServerOpts::default()).await;
    let b = common::start_server(ServerOpts {
        extra_authorized: vec![a.client_identity.public],
        ..ServerOpts::default()
    })
    .await;
    let paths = a.client_paths();
    let dead = Target {
        display: "dead".to_owned(),
        port: 1,
        ..a.target(ConnectOpts::default())
    };
    let targets = vec![
        Target {
            display: "a".to_owned(),
            ..a.target(ConnectOpts::default())
        },
        dead,
        Target {
            display: "b".to_owned(),
            ..b.target(ConnectOpts::default())
        },
    ];
    let reporter = Arc::new(Collect::default());
    let results = fleet::run(
        &targets,
        argv(&["sh", "-c", "echo hi; exit 1"]),
        2,
        &paths,
        &Baked::default(),
        reporter.clone(),
        Arc::new(RefuseUnknown),
    )
    .await;
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].host, "a");
    assert_eq!(results[0].exit, Some(1));
    assert!(!results[0].ok);
    assert_eq!(results[0].stdout.as_bytes(), b"hi\n");
    assert_eq!(results[1].host, "dead");
    assert_eq!(
        results[1].error.as_ref().map(|e| e.code.as_str()),
        Some(codes::CONNECT_FAILED)
    );
    assert_eq!(results[2].host, "b");
    assert_eq!(results[2].exit, Some(1));
    assert!(
        reporter
            .events()
            .iter()
            .any(|e| matches!(e, Event::Host { host, data } if host == "b" && matches!(**data, Event::Stdout { .. }))),
        "host-attributed events: {:?}",
        reporter.events()
    );
    a.stop().await;
    b.stop().await;
}
