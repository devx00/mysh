//! Remote process API and master mode (docs/03-protocol.md §10ter,
//! docs/05-meta-shell.md "Session command family" / "Master mode",
//! docs/06-roadmap.md M7).
//!
//! The protocol half runs over the library API on a loopback server; the
//! command half spawns the real binary with `client_env` so the control
//! socket, the master daemon and the `session` subcommands are exercised
//! end to end. Nothing touches the real home: every path is under the
//! harness temp tree.

mod common;

use std::{
    path::Path,
    time::{Duration, Instant},
};

use common::TempDir;
use mysh::{
    cli::ConnectOpts,
    client::{
        conn::Connection,
        session_api::{self, NewArgs, NewSessionOut},
    },
};
use mysh_proto::{
    limits::{DETACHED_RING, READ_MAX},
    session::{ExitStatus, OutStream, ReadReply, Signal},
};

const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(25);

/// A server with persistence on (the API needs the registry).
async fn start() -> common::TestServer {
    common::start_server(common::ServerOpts {
        detach_grace: Some(Duration::from_secs(60)),
        ..common::ServerOpts::default()
    })
    .await
}

async fn connect(server: &common::TestServer) -> Connection {
    server
        .connect(ConnectOpts::default())
        .await
        .expect("connect")
}

/// `session new -- sh -c SCRIPT`.
async fn new_session(conn: &Connection, script: &str) -> NewSessionOut {
    session_api::session_new(
        conn,
        &NewArgs {
            command: vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            ..NewArgs::default()
        },
    )
    .await
    .expect("session new")
}

async fn read_at(conn: &Connection, id: u32, offset: u64, wait: Duration) -> ReadReply {
    session_api::session_read(conn, id, offset, READ_MAX, wait)
        .await
        .expect("session read")
}

/// Read from `offset` until the session has exited and no bytes are left;
/// returns the stdout and stderr bytes separately plus the final status.
async fn drain(conn: &Connection, id: u32, mut offset: u64) -> (Vec<u8>, Vec<u8>, ExitStatus) {
    let deadline = Instant::now() + WAIT;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        assert!(Instant::now() < deadline, "session {id} never finished");
        let reply = read_at(conn, id, offset, Duration::from_millis(500)).await;
        assert_eq!(reply.offset, offset, "no bytes were dropped");
        let empty = reply.chunks.is_empty();
        for chunk in reply.chunks {
            match chunk.stream {
                OutStream::Stdout => out.extend_from_slice(&chunk.bytes),
                OutStream::Stderr => err.extend_from_slice(&chunk.bytes),
            }
        }
        offset = reply.next;
        if let Some(status) = reply.exited
            && empty
        {
            return (out, err, status);
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol

#[tokio::test]
async fn incremental_reads_reassemble_the_output_exactly_once() {
    let server = start().await;
    let conn = connect(&server).await;
    let s = new_session(&conn, "for i in 1 2 3 4 5; do echo $i; sleep 0.2; done").await;
    assert!(s.id > 0 && s.pid > 0);

    // Several short reads over the session's lifetime: no gaps, no repeats.
    let (out, err, status) = drain(&conn, s.id, 0).await;
    assert_eq!(String::from_utf8_lossy(&out), "1\n2\n3\n4\n5\n");
    assert!(err.is_empty(), "{err:?}");
    assert_eq!(status, ExitStatus::Code(0));

    // Reads are idempotent: the same offset returns the same bytes.
    let again = read_at(&conn, s.id, 0, Duration::ZERO).await;
    let bytes: Vec<u8> = again.chunks.iter().flat_map(|c| c.bytes.clone()).collect();
    assert_eq!(bytes, out);
    assert_eq!(again.offset, 0);
    assert_eq!(again.oldest, 0);
    assert_eq!(again.exited, Some(ExitStatus::Code(0)));

    // The exited session stays listed for the grace window with its
    // offsets and status.
    let rows = session_api::session_list(&conn).await.expect("list");
    let row = rows.iter().find(|r| r.id == s.id).expect("listed");
    assert_eq!(row.pid, s.pid);
    assert!(!row.pty);
    assert_eq!(row.next, out.len() as u64);
    assert_eq!(row.exited, Some(ExitStatus::Code(0)));

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn reads_past_the_ring_report_the_oldest_offset() {
    let server = start().await;
    let conn = connect(&server).await;
    // 2 MiB in 1 KiB pieces: twice the 1 MiB ring.
    let s = new_session(
        &conn,
        "i=0; while [ $i -lt 2048 ]; do printf '%01024d' $i; i=$((i+1)); done",
    )
    .await;
    let status = session_api::session_wait(&conn, s.id, Some(WAIT))
        .await
        .expect("wait")
        .expect("exited");
    assert_eq!(status, ExitStatus::Code(0));

    let reply = read_at(&conn, s.id, 0, Duration::ZERO).await;
    let returned: usize = reply.chunks.iter().map(|c| c.bytes.len()).sum();
    assert_eq!(reply.next - reply.offset, returned as u64);
    assert!(reply.oldest > 0, "the start aged out: {reply:?}");
    assert_eq!(reply.offset, reply.oldest, "the reply says where it starts");
    assert_eq!(
        reply.oldest,
        2 * 1024 * 1024 - DETACHED_RING as u64,
        "the ring keeps its last {DETACHED_RING} bytes"
    );
    // One reply fits in a control frame; the rest follows from `next`.
    assert!(returned <= 256 * 1024, "{returned} bytes in one reply");
    let next = read_at(&conn, s.id, reply.next, Duration::ZERO).await;
    assert_eq!(next.offset, reply.next, "reads continue where they stopped");

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn writes_reach_stdin_and_eof_ends_the_session() {
    let server = start().await;
    let conn = connect(&server).await;
    let s = new_session(&conn, "cat").await;

    session_api::session_send(&conn, s.id, b"hello\n", false)
        .await
        .expect("send");
    let mut offset = 0;
    let mut echoed = Vec::new();
    let deadline = Instant::now() + WAIT;
    while !String::from_utf8_lossy(&echoed).contains("hello") {
        assert!(Instant::now() < deadline, "cat never echoed: {echoed:?}");
        let reply = read_at(&conn, s.id, offset, Duration::from_millis(500)).await;
        offset = reply.next;
        for chunk in reply.chunks {
            echoed.extend_from_slice(&chunk.bytes);
        }
    }
    assert!(
        session_api::session_wait(&conn, s.id, Some(Duration::from_millis(200)))
            .await
            .expect("wait")
            .is_none(),
        "cat keeps running until its stdin closes"
    );

    // A write with `eof` closes the child's stdin.
    session_api::session_send(&conn, s.id, b"bye\n", true)
        .await
        .expect("send eof");
    let (out, _, status) = drain(&conn, s.id, 0).await;
    assert_eq!(String::from_utf8_lossy(&out), "hello\nbye\n");
    assert_eq!(status, ExitStatus::Code(0));

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn stdout_and_stderr_stay_separate_without_a_pty() {
    let server = start().await;
    let conn = connect(&server).await;
    let s = new_session(&conn, "echo o; echo e >&2").await;
    let (out, err, status) = drain(&conn, s.id, 0).await;
    assert_eq!(String::from_utf8_lossy(&out), "o\n");
    assert_eq!(String::from_utf8_lossy(&err), "e\n");
    assert_eq!(status, ExitStatus::Code(0));

    // A pty session merges them, as a terminal does.
    let pty = session_api::session_new(
        &conn,
        &NewArgs {
            command: vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "echo o; echo e >&2".to_owned(),
            ],
            pty: true,
            ..NewArgs::default()
        },
    )
    .await
    .expect("pty session");
    let (out, err, _) = drain(&conn, pty.id, 0).await;
    assert!(err.is_empty(), "a pty has no second stream: {err:?}");
    let text = String::from_utf8_lossy(&out).replace("\r\n", "\n");
    assert!(text.contains('o') && text.contains('e'), "{text:?}");

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn kill_and_wait_report_the_status() {
    let server = start().await;
    let conn = connect(&server).await;
    let s = new_session(&conn, "sleep 30").await;

    // `wait --timeout` gives up without ending the session.
    assert!(
        session_api::session_wait(&conn, s.id, Some(Duration::from_millis(300)))
            .await
            .expect("wait")
            .is_none()
    );

    session_api::session_kill(&conn, s.id, Signal::Term)
        .await
        .expect("kill");
    let status = session_api::session_wait(&conn, s.id, Some(WAIT))
        .await
        .expect("wait")
        .expect("exited");
    assert_eq!(
        status,
        ExitStatus::Signal {
            signal: 15,
            core_dumped: false
        }
    );

    // Unknown ids and other peers' sessions do not exist.
    let err = session_api::session_kill(&conn, s.id + 1000, Signal::Term)
        .await
        .expect_err("no such session");
    assert!(format!("{err:#}").contains("not found"), "{err:#}");

    conn.close().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Commands (the binary)

/// `client_env` with the runtime dir under a short path (unix socket paths
/// are capped at ~100 bytes) and a config file of our own.
fn env_with_runtime(server: &common::TestServer, run: &Path) -> Vec<(String, String)> {
    let mut env = common::client_env(server);
    env.retain(|(k, _)| k != "XDG_RUNTIME_DIR");
    env.push(("XDG_RUNTIME_DIR".into(), run.display().to_string()));
    env.push(("SHELL".into(), "/bin/sh".into()));
    env
}

fn socket_of(run: &Path, server: &common::TestServer) -> std::path::PathBuf {
    run.join("mysh")
        .join(format!("127.0.0.1_{}.sock", server.port()))
}

/// `mysh --accept-new HOST args…`; returns `(code, stdout, stderr)`.
async fn run_cli(
    server: &common::TestServer,
    env: &[(String, String)],
    args: &[&str],
) -> (i32, String, String) {
    let mut cmd = tokio::process::Command::new(common::mysh_bin());
    cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    cmd.arg("--accept-new").arg(server.host_arg()).args(args);
    cmd.stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(WAIT, cmd.output())
        .await
        .expect("cli timed out")
        .expect("spawn cli");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `mysh session [pre…] --accept-new HOST SUB [args…]`: connection flags
/// such as `--json` belong before HOST.
async fn run_session_cli(
    server: &common::TestServer,
    env: &[(String, String)],
    pre: &[&str],
    args: &[&str],
) -> (i32, String, String) {
    let mut cmd = tokio::process::Command::new(common::mysh_bin());
    cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    cmd.arg("session")
        .args(pre)
        .arg("--accept-new")
        .arg(server.host_arg())
        .args(args);
    cmd.stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(WAIT, cmd.output())
        .await
        .expect("cli timed out")
        .expect("spawn cli");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn wait_for_socket(path: &Path, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

#[tokio::test]
async fn session_commands_drive_a_session_end_to_end() {
    let server = start().await;
    let run = TempDir::short("api");
    let env = env_with_runtime(&server, run.path());

    let (code, out, err) = run_session_cli(
        &server,
        &env,
        &[],
        &[
            "new",
            "--",
            "sh",
            "-c",
            "for i in 1 2 3; do echo $i; sleep 0.1; done",
        ],
    )
    .await;
    assert_eq!(code, 0, "new failed: {out}{err}");
    let id: u32 = out
        .split_whitespace()
        .nth(1)
        .and_then(|w| w.parse().ok())
        .unwrap_or_else(|| panic!("no id in {out:?}"));

    // `--follow` streams until the session exits.
    let (code, out, err) =
        run_session_cli(&server, &env, &[], &["read", "--follow", &id.to_string()]).await;
    assert_eq!(code, 0, "read failed: {err}");
    assert_eq!(out, "1\n2\n3\n");

    let (code, out, _) = run_session_cli(&server, &env, &[], &["list"]).await;
    assert_eq!(code, 0);
    assert!(out.contains(&id.to_string()), "{out}");

    // `wait --json` reports the status; the session already exited.
    let (code, out, err) =
        run_session_cli(&server, &env, &["--json"], &["wait", &id.to_string()]).await;
    assert_eq!(code, 0, "wait failed: {err}");
    let value: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(value["exit"], 0);
    assert_eq!(value["timed_out"], false);

    // A fresh `cat` session takes text, then `--eof`.
    let (code, out, err) = run_session_cli(&server, &env, &["--json"], &["new", "--", "cat"]).await;
    assert_eq!(code, 0, "new cat failed: {err}");
    let value: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    let cat = u32::try_from(value["id"].as_u64().expect("id")).expect("id fits");
    let (code, _, err) = run_session_cli(
        &server,
        &env,
        &[],
        &["send", &cat.to_string(), "--", "ping"],
    )
    .await;
    assert_eq!(code, 0, "send failed: {err}");
    let (code, _, err) =
        run_session_cli(&server, &env, &[], &["send", "--eof", &cat.to_string()]).await;
    assert_eq!(code, 0, "eof failed: {err}");
    let (code, out, err) =
        run_session_cli(&server, &env, &[], &["read", "--follow", &cat.to_string()]).await;
    assert_eq!(code, 0, "read failed: {err}");
    assert_eq!(out, "ping\n");

    // `kill` on a long-running session, then `wait` sees the signal.
    let (code, out, _) =
        run_session_cli(&server, &env, &["--json"], &["new", "--", "sleep 30"]).await;
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    let sleeper = u32::try_from(value["id"].as_u64().expect("id")).expect("id fits");
    let (code, _, err) = run_session_cli(
        &server,
        &env,
        &[],
        &["kill", "-s", "KILL", &sleeper.to_string()],
    )
    .await;
    assert_eq!(code, 0, "kill failed: {err}");
    let (code, out, _) =
        run_session_cli(&server, &env, &["--json"], &["wait", &sleeper.to_string()]).await;
    let value: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(value["signal"], 9);
    assert_eq!(code, 128 + 9);

    server.stop().await;
}

#[tokio::test]
async fn exec_calls_reuse_one_master() {
    // One handshake per minute: every call after the master's own would be
    // dropped before the handshake, so 200 successes prove one connection.
    let server = common::start_server(common::ServerOpts {
        detach_grace: Some(Duration::from_secs(60)),
        handshakes_per_minute: Some(1),
        ..common::ServerOpts::default()
    })
    .await;
    let run = TempDir::short("master");
    let env = env_with_runtime(&server, run.path());
    let sock = socket_of(run.path(), &server);

    let mut master = tokio::process::Command::new(common::mysh_bin());
    master.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    master
        .arg("master")
        .arg("--idle")
        .arg("60s")
        .arg("--accept-new")
        .arg(server.host_arg())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut master = master.spawn().expect("spawn master");
    assert!(
        wait_for_socket(&sock, Duration::from_secs(10)).await,
        "the master never served {}",
        sock.display()
    );

    let started = Instant::now();
    for batch in 0..20 {
        let mut calls = Vec::new();
        for i in 0..10 {
            let n = batch * 10 + i;
            let env = env.clone();
            let host = server.host_arg();
            calls.push(tokio::spawn(async move {
                let mut cmd = tokio::process::Command::new(common::mysh_bin());
                cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
                cmd.arg("--accept-new")
                    .arg(host)
                    .arg("--")
                    .arg("echo")
                    .arg(n.to_string());
                cmd.stdin(std::process::Stdio::null());
                cmd.output().await.expect("spawn call")
            }));
        }
        for (i, call) in calls.into_iter().enumerate() {
            let out = call.await.expect("call");
            let n = batch * 10 + i;
            assert_eq!(
                out.status.code(),
                Some(0),
                "call {n} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), n.to_string());
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(120),
        "200 calls took {elapsed:?}"
    );

    // The master leaves when its connection does, and removes its socket.
    server.stop().await;
    let _ = tokio::time::timeout(Duration::from_secs(10), master.wait()).await;
    assert!(!sock.exists(), "socket left behind");
}

#[tokio::test]
async fn master_exits_when_idle() {
    let server = start().await;
    let run = TempDir::short("idle");
    let env = env_with_runtime(&server, run.path());
    let sock = socket_of(run.path(), &server);

    let mut cmd = tokio::process::Command::new(common::mysh_bin());
    cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    cmd.arg("master")
        .arg("--idle")
        .arg("500ms")
        .arg("--accept-new")
        .arg(server.host_arg())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().expect("spawn master");
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("master still running after its idle window")
        .expect("wait");
    assert!(status.success(), "{status:?}");
    assert!(!sock.exists(), "socket left behind");

    server.stop().await;
}

#[tokio::test]
async fn auto_master_is_spawned_once_and_reused() {
    let server = common::start_server(common::ServerOpts {
        detach_grace: Some(Duration::from_secs(60)),
        handshakes_per_minute: Some(1),
        ..common::ServerOpts::default()
    })
    .await;
    let run = TempDir::short("auto");
    let env = env_with_runtime(&server, run.path());
    std::fs::write(
        server.client_dir.join("config.toml"),
        "[defaults]\nmaster = \"auto\"\n",
    )
    .expect("write config");
    let sock = socket_of(run.path(), &server);

    // No socket yet: the call starts a master, then runs through it.
    let (code, out, err) = run_cli(&server, &env, &["--", "echo", "first"]).await;
    assert_eq!(code, 0, "first call failed: {err}");
    assert_eq!(out.trim(), "first");
    assert!(sock.exists(), "no master socket at {}", sock.display());

    // The second call reuses it; a second handshake would be dropped by
    // the 1/min limiter.
    let (code, out, err) = run_cli(&server, &env, &["--", "echo", "second"]).await;
    assert_eq!(code, 0, "second call failed: {err}");
    assert_eq!(out.trim(), "second");

    // Session commands take the same route.
    let (code, out, err) =
        run_session_cli(&server, &env, &["--json"], &["new", "--", "true"]).await;
    assert_eq!(code, 0, "session new failed: {err}");
    let value: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    assert!(value["id"].as_u64().is_some(), "{out}");

    server.stop().await;
    // The master exits with its connection and takes the socket with it.
    let deadline = Instant::now() + Duration::from_secs(10);
    while sock.exists() && Instant::now() < deadline {
        tokio::time::sleep(POLL).await;
    }
    assert!(!sock.exists(), "socket left behind");
}
