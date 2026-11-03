//! Structured output through the real binary (docs/05-meta-shell.md "Agent
//! interface", docs/06-roadmap.md M6): every `--json` document parses into
//! the typed structs of `mysh::output`, the `--json-stream` events arrive in
//! order with `exit` last and base64 for non-UTF-8 bytes, error codes are
//! stable per failure class, `--timeout` escalates TERM → KILL and exits
//! 124, `--cwd` is honoured, `Open::Info` matches the host, and `help
//! --json` lists the command tree.

mod common;

use std::{
    io::Write as _,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use mysh::output::{
    Bytes, CwdOut, ErrorOut, Event, ExecResult, ForwardRow, HelpTree, InfoOut, JobRow, LsEntry,
    OkOut, PingOut, SessionsOut, StatOut, TransferOut,
};
use mysh_net::keys::SecretKey;

/// A `mysh` client command against `server` with the harness environment,
/// `--accept-new`, and all three stdio pipes.
fn mysh(server: &common::TestServer) -> Command {
    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .envs(common::client_env(server))
        .arg("--accept-new")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// `mysh SUB --accept-new …` with the harness environment and piped stdio.
fn sub(server: &common::TestServer, name: &str) -> Command {
    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .envs(common::client_env(server))
        .arg(name)
        .arg("--accept-new")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run_with_stdin(cmd: &mut Command, stdin: &[u8]) -> Output {
    let mut child = cmd.spawn().expect("spawn mysh");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn run(cmd: &mut Command) -> Output {
    run_with_stdin(cmd, b"")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Parse stdout as exactly one JSON document of type `T`.
fn one<T: serde::de::DeserializeOwned>(out: &Output) -> T {
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("no JSON on stdout; stderr: {}", text(&out.stderr)));
    assert!(
        lines.next().is_none(),
        "more than one document on stdout: {stdout}"
    );
    serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"))
}

/// Parse stdout as a sequence of JSON documents, one per line.
fn many<T: serde::de::DeserializeOwned>(out: &Output) -> Vec<T> {
    text(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

/// The `ErrorOut` line on stderr.
fn error_of(out: &Output) -> ErrorOut {
    let stderr = text(&out.stderr);
    let line = stderr
        .lines()
        .find(|l| l.starts_with("{\"error\""))
        .unwrap_or_else(|| panic!("no error document on stderr: {stderr}"));
    serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"))
}

/// A script of prompt commands run with `--json`: one document per line.
fn script(server: &common::TestServer, lines: &str) -> Output {
    run_with_stdin(
        mysh(server).arg("--json").arg(server.host_arg()),
        lines.as_bytes(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_json_document() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = run(mysh(&server)
        .arg("--json")
        .arg(server.host_arg())
        .arg("echo out; echo err >&2; exit 3"));
    assert_eq!(out.status.code(), Some(3), "stderr: {}", text(&out.stderr));
    let result: ExecResult = one(&out);
    assert_eq!(result.stdout, Bytes::Text("out\n".into()));
    assert_eq!(result.stderr, Bytes::Text("err\n".into()));
    assert_eq!(result.exit, Some(3));
    assert_eq!(result.signal, None);
    assert!(!result.timed_out);
    // Nothing but the document on stdout.
    assert_eq!(text(&out.stdout).lines().count(), 1);

    // Non-UTF-8 output is base64.
    let out = run(mysh(&server)
        .arg("--json")
        .arg(server.host_arg())
        .arg("printf '\\377\\001'"));
    let result: ExecResult = one(&out);
    assert_eq!(result.stdout, Bytes::Binary(vec![0xff, 0x01]));

    // A signal death reports `signal`, no `exit`.
    let out = run(mysh(&server)
        .arg("--json")
        .arg(server.host_arg())
        .arg("kill -9 $$"));
    assert_eq!(out.status.code(), Some(137));
    let result: ExecResult = one(&out);
    assert_eq!(result.exit, None);
    assert_eq!(result.signal, Some(9));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_json_stream_events() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = run(mysh(&server)
        .arg("--json-stream")
        .arg(server.host_arg())
        .arg("echo one; printf '\\377' >&2; echo two"));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let events: Vec<Event> = many(&out);
    assert!(
        matches!(events.first(), Some(Event::Started { .. })),
        "{events:?}"
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for ev in &events {
        match ev {
            Event::Stdout { data } => stdout.extend_from_slice(data.as_bytes()),
            Event::Stderr { data } => {
                assert_eq!(*data, Bytes::Binary(vec![0xff]));
                stderr.extend_from_slice(data.as_bytes());
            }
            _ => {}
        }
    }
    assert_eq!(stdout, b"one\ntwo\n");
    assert_eq!(stderr, b"\xff");
    match events.last() {
        Some(Event::Exit {
            exit: Some(0),
            signal: None,
            timed_out: false,
            ..
        }) => {}
        other => panic!("exit must be last: {other:?}"),
    }
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Exit { .. }))
            .count(),
        1
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_kills_and_exits_124() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let started = Instant::now();
    // `sleep` inherits the shell's TERM disposition; the shell forwards
    // nothing, so TERM alone ends the `sh -c` and `sleep` is reparented.
    let out = run(mysh(&server)
        .arg("--json")
        .arg("--timeout")
        .arg("1s")
        .arg(server.host_arg())
        .arg("sleep 30"));
    let elapsed = started.elapsed();
    assert_eq!(
        out.status.code(),
        Some(124),
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(
        elapsed < Duration::from_millis(3500),
        "took {elapsed:?}; TERM then KILL after 2 s expected"
    );
    let result: ExecResult = one(&out);
    assert!(result.timed_out, "{result:?}");

    // A command that ignores TERM is KILLed after two more seconds.
    let started = Instant::now();
    let out = run(mysh(&server)
        .arg("--json")
        .arg("--timeout")
        .arg("500ms")
        .arg(server.host_arg())
        .arg("trap '' TERM; exec sleep 30"));
    let elapsed = started.elapsed();
    assert_eq!(
        out.status.code(),
        Some(124),
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(6),
        "took {elapsed:?}"
    );
    let result: ExecResult = one(&out);
    assert!(result.timed_out);
    assert_eq!(result.signal, Some(9), "{result:?}");

    // Without JSON the exit code is the same and stderr explains.
    let out = run(mysh(&server)
        .arg("--timeout")
        .arg("300ms")
        .arg(server.host_arg())
        .arg("sleep 30"));
    assert_eq!(out.status.code(), Some(124));
    assert!(
        text(&out.stderr).contains("timed out"),
        "{}",
        text(&out.stderr)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cwd_flag_sets_working_directory() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let dir = server.home.join("sub dir");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let out = run(mysh(&server)
        .arg("--json")
        .arg("--cwd")
        .arg(&dir)
        .arg(server.host_arg())
        .arg("pwd"));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let result: ExecResult = one(&out);
    let printed = String::from_utf8(result.stdout.into_bytes()).expect("utf8");
    assert_eq!(
        std::fs::canonicalize(printed.trim()).expect("canonical"),
        std::fs::canonicalize(&dir).expect("canonical")
    );

    // `~`-relative, and the prompt command's own `--cwd`.
    let out = script(&server, "exec --cwd ~/sub\\ dir pwd\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let result: ExecResult = one(&out);
    let printed = String::from_utf8(result.stdout.into_bytes()).expect("utf8");
    assert!(printed.trim().ends_with("sub dir"), "{printed}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn info_json_reports_server_and_connection() {
    let server = common::start_server(common::ServerOpts {
        deny: vec![mysh::cli::Feature::ForwardRemote],
        ..common::ServerOpts::default()
    })
    .await;
    let out = script(&server, "info\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let info: InfoOut = one(&out);
    let remote = info.server.expect("server info");
    assert_eq!(remote.platform.os, std::env::consts::OS);
    assert_eq!(remote.platform.arch, std::env::consts::ARCH);
    let uname = Command::new("uname").arg("-r").output().expect("uname -r");
    assert_eq!(
        remote.platform.kernel,
        String::from_utf8_lossy(&uname.stdout).trim()
    );
    assert_eq!(remote.name, "test-server");
    assert_eq!(remote.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(remote.home, server.home.display().to_string());
    assert_eq!(remote.limits.denied, vec!["forward-remote".to_owned()]);
    assert_eq!(remote.limits.max_sessions, 32);
    assert_eq!(info.connection.port, server.port());
    assert_eq!(
        info.connection.peer_fingerprint,
        server.server_key.fingerprint().to_string()
    );
    assert_eq!(info.connection.protocol, 1);
    assert!(info.connection.bytes_in > 0);
    assert_eq!(info.sessions.len(), 0);
    assert_eq!(info.forwards.len(), 0);

    // The human listing carries the new facts too.
    let out = run_with_stdin(mysh(&server).arg(server.host_arg()), b"info\n");
    let stdout = text(&out.stdout);
    assert!(stdout.contains("protocol:  v1"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "remote:    mysh {} on {}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        )),
        "{stdout}"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn listing_commands_parse() {
    let server = common::start_server(common::ServerOpts::default()).await;
    std::fs::write(server.home.join("a.txt"), b"hello").expect("write");
    std::fs::create_dir_all(server.home.join("d")).expect("mkdir");
    std::os::unix::fs::symlink("a.txt", server.home.join("link")).expect("symlink");

    let out = script(&server, "ls -a ~\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let entries: Vec<LsEntry> = one(&out);
    let a = entries.iter().find(|e| e.name == "a.txt").expect("a.txt");
    assert_eq!(a.kind, "file");
    assert_eq!(a.size, 5);
    assert_eq!(a.mode.len(), 4, "{}", a.mode);
    assert!(
        a.mtime.ends_with('Z') && a.mtime.contains('T'),
        "{}",
        a.mtime
    );
    let d = entries.iter().find(|e| e.name == "d").expect("d");
    assert_eq!(d.kind, "dir");
    let link = entries.iter().find(|e| e.name == "link").expect("link");
    assert_eq!(link.kind, "symlink");
    assert_eq!(link.target.as_deref(), Some("a.txt"));

    let out = script(&server, "stat ~/a.txt\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let st: StatOut = one(&out);
    assert_eq!(st.kind, "file");
    assert_eq!(st.size, 5);
    assert_eq!(st.path, "~/a.txt");

    let out = script(&server, "stat ~/nope\n");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(error_of(&out).error.code, "not_found");

    let out = script(&server, "sessions\nsessions -a\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let docs: Vec<SessionsOut> = many(&out);
    assert_eq!(docs.len(), 2);
    assert!(docs[0].sessions.is_empty() && docs[0].server.is_none());
    assert_eq!(docs[1].server.as_deref(), Some(&[][..]));

    let out = script(&server, "jobs\n");
    let rows: Vec<JobRow> = one(&out);
    assert_eq!(rows.len(), 0);

    let out = script(&server, "forward ls\n");
    let rows: Vec<ForwardRow> = one(&out);
    assert_eq!(rows.len(), 0);

    let out = script(
        &server,
        "forward -L 127.0.0.1:0:127.0.0.1:1\nforward ls\nforward rm 1\n",
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    let added: Vec<ForwardRow> = serde_json::from_str(lines.next().expect("add")).expect("rows");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].kind, "local");
    assert_eq!(added[0].target.as_deref(), Some("127.0.0.1:1"));
    let listed: Vec<ForwardRow> = serde_json::from_str(lines.next().expect("ls")).expect("rows");
    assert_eq!(listed, added);
    let removed: OkOut = serde_json::from_str(lines.next().expect("rm")).expect("ok");
    assert!(removed.ok);

    let out = script(&server, "ping -c 2\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let ping: PingOut = one(&out);
    assert_eq!(ping.rtts_ms.len(), 2);
    assert!(ping.min <= ping.avg && ping.avg <= ping.max);

    let out = script(&server, "cwd\n");
    let cwd: CwdOut = one(&out);
    assert!(cwd.remote.is_none() && cwd.session.is_none());
    assert_ne!(cwd.local.len(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn transfers_and_jobs_report_json() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let local = server.dir.join("local");
    std::fs::create_dir_all(&local).expect("mkdir");
    std::fs::write(local.join("f.bin"), vec![7u8; 3000]).expect("write");

    let out = run(sub(&server, "put")
        .arg("--json")
        .arg(server.host_arg())
        .arg(local.join("f.bin"))
        .arg("~/f.bin"));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let t: TransferOut = one(&out);
    assert_eq!((t.files, t.bytes), (1, 3000));

    let out = run(sub(&server, "get")
        .arg("--json-stream")
        .arg(server.host_arg())
        .arg("~/f.bin")
        .arg(local.join("back.bin")));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let events: Vec<Event> = many(&out);
    assert!(
        events.iter().any(|e| matches!(e, Event::Progress { .. })),
        "{events:?}"
    );
    match events.last() {
        Some(Event::Result { value }) => {
            let t: TransferOut = serde_json::from_value(value.clone()).expect("transfer");
            assert_eq!(t.bytes, 3000);
        }
        other => panic!("result must be last: {other:?}"),
    }
    assert_eq!(
        std::fs::read(local.join("back.bin")).expect("read").len(),
        3000
    );

    // A background job, then its row and output as JSON.
    let out = script(&server, "exec echo hi &\njobs -w 1\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let job: serde_json::Value =
        serde_json::from_str(stdout.lines().last().expect("job")).expect("json");
    assert_eq!(job["state"], "done");
    assert_eq!(job["exit"], 0);
    assert!(
        job["output"]
            .as_str()
            .is_some_and(|o| o.starts_with("hi\n")),
        "{job}"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn error_codes_are_stable() {
    // unauthorized
    let server = common::start_server(common::ServerOpts {
        untrusted_client: true,
        ..common::ServerOpts::default()
    })
    .await;
    let out = run(mysh(&server)
        .arg("--json")
        .arg(server.host_arg())
        .arg("true"));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(error_of(&out).error.code, "unauthorized");
    assert_eq!(text(&out.stdout), "");
    server.stop().await;

    let server = common::start_server(common::ServerOpts::default()).await;
    // trust_unknown: no tty, no --accept-new.
    let out = run(Command::new(common::mysh_bin())
        .env_clear()
        .envs(common::client_env(&server))
        .arg("--json")
        .arg(server.host_arg())
        .arg("true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(error_of(&out).error.code, "trust_unknown");
    let out = run(Command::new(common::mysh_bin())
        .env_clear()
        .envs(common::client_env(&server))
        .args(["--json", "--strict"])
        .arg(server.host_arg())
        .arg("true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()));
    assert_eq!(error_of(&out).error.code, "trust_unknown");

    // trust_mismatch: a stale known_hosts line.
    let other = SecretKey::generate().public();
    std::fs::write(
        server.client_dir.join("known_hosts"),
        format!("{} {}\n", server.host_arg(), other.to_line(Some("stale"))),
    )
    .expect("write known_hosts");
    let out = run(mysh(&server)
        .arg("--json")
        .arg(server.host_arg())
        .arg("true"));
    assert_eq!(out.status.code(), Some(2));
    let err = error_of(&out);
    assert_eq!(err.error.code, "trust_mismatch");
    assert!(
        err.error.message.contains("does not match"),
        "{}",
        err.error.message
    );
    std::fs::remove_file(server.client_dir.join("known_hosts")).expect("rm");

    server.stop().await;

    // denied: a feature switched off by policy.

    let server = common::start_server(common::ServerOpts {
        deny: vec![mysh::cli::Feature::Exec],
        ..common::ServerOpts::default()
    })
    .await;
    let out = run(mysh(&server)
        .arg("--json")
        .arg(server.host_arg())
        .arg("true"));
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(error_of(&out).error.code, "denied");

    // usage: a bogus flag, and a bogus prompt command.
    let out = run(mysh(&server)
        .arg("--json")
        .arg("--no-such-flag")
        .arg(server.host_arg()));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(error_of(&out).error.code, "usage");
    let out = script(&server, "bogus\n");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(error_of(&out).error.code, "usage");
    // ... and in stream mode the error is an event on stdout.
    let out = run_with_stdin(
        mysh(&server).arg("--json-stream").arg(server.host_arg()),
        b"bogus\n",
    );
    let events: Vec<Event> = many(&out);
    assert!(
        matches!(events.last(), Some(Event::Error { code, .. }) if code == "usage"),
        "{events:?}"
    );

    // connect_failed: a closed port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let out = run(Command::new(common::mysh_bin())
        .env_clear()
        .envs(common::client_env(&server))
        .args(["--json", "--accept-new"])
        .arg(format!("127.0.0.1:{port}"))
        .arg("true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(error_of(&out).error.code, "connect_failed");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn help_json_lists_the_command_tree() {
    let out = run(Command::new(common::mysh_bin())
        .env_clear()
        .args(["help", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let tree: HelpTree = one(&out);
    assert_eq!(tree.command, "mysh");
    for name in [
        "connect",
        "serve",
        "keygen",
        "fingerprint",
        "put",
        "get",
        "forward",
        "authorize",
        "help",
    ] {
        assert!(tree.subcommand(name).is_some(), "missing {name}");
    }
    let json_flag = tree
        .args
        .iter()
        .find(|a| a.long.as_deref() == Some("json"))
        .expect("--json");
    assert!(!json_flag.takes_value);
    let timeout = tree
        .args
        .iter()
        .find(|a| a.long.as_deref() == Some("timeout"))
        .expect("--timeout");
    assert!(timeout.takes_value);
    assert_eq!(timeout.value_name.as_deref(), Some("DURATION"));

    // One subcommand only.
    let out = run(Command::new(common::mysh_bin())
        .env_clear()
        .args(["help", "--json", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()));
    let serve: HelpTree = one(&out);
    assert_eq!(serve.command, "serve");
    assert!(
        serve
            .args
            .iter()
            .any(|a| a.long.as_deref() == Some("listen"))
    );

    // Text help still works.
    let out = run(Command::new(common::mysh_bin())
        .env_clear()
        .args(["help", "put"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()));
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("--recursive") || text(&out.stdout).contains("-r"));

    // The prompt grammar.
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = script(&server, "help\nhelp exec\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let docs: Vec<HelpTree> = many(&out);
    assert_eq!(docs.len(), 2);
    for name in [
        "shell", "exec", "put", "get", "ls", "stat", "sessions", "info", "ping", "help",
    ] {
        assert!(docs[0].subcommand(name).is_some(), "missing {name}");
    }
    assert_eq!(docs[1].command, "exec");
    assert!(
        docs[1]
            .args
            .iter()
            .any(|a| a.long.as_deref() == Some("timeout"))
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_mode_has_no_banner_or_ansi() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = run_with_stdin(
        mysh(&server).arg("--plain").arg(server.host_arg()),
        b"ping -c 1\nexit\n",
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("pong 1"), "{stdout}");
    assert!(!stdout.contains("connected to"), "{stdout}");
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
    server.stop().await;
}
