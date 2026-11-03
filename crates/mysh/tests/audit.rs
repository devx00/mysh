//! The server audit log (docs/02-security.md "Audit log", docs/06-roadmap.md
//! M9): a server started with `--audit` writes one JSON line per event,
//! every line validates against a strict schema, timestamps never go
//! backwards, and the file is created 0600.

mod common;

use std::{
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use mysh_net::keys::{SecretKey, write_secret_key};
use serde::Deserialize;

/// The documented line shape; any extra key is a schema drift.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditLine {
    ts: String,
    peer: String,
    key: String,
    kind: String,
    event: String,
    detail: serde_json::Map<String, serde_json::Value>,
    exit: Option<i32>,
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
    duration_ms: Option<u64>,
}

fn mysh(server: &common::TestServer) -> Command {
    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .envs(common::client_env(server))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run(cmd: &mut Command) -> Output {
    let mut child = cmd.spawn().expect("spawn mysh");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"")
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn lines(path: &std::path::Path) -> Vec<AuditLine> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

/// Wait until the writer has flushed `n` lines of `event`.
async fn wait_for(path: &std::path::Path, event: &str, n: usize) -> Vec<AuditLine> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let all = lines(path);
        if all.iter().filter(|l| l.event == event).count() >= n {
            return all;
        }
        assert!(
            Instant::now() < deadline,
            "no {n} `{event}` lines in time; have: {all:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Drive one of every audited event against `server`: an exec, a PTY
/// session, a put, a remote forward, and a connection with an unknown key.
fn produce_events(server: &common::TestServer) {
    let host = server.host_arg();

    // exec: `mysh HOST CMD` (connect + session + exec + disconnect).
    let out = run(mysh(server).args(["--accept-new", &host, "--", "sh", "-c", "exit 7"]));
    assert_eq!(out.status.code(), Some(7), "stderr: {}", text(&out.stderr));

    // pty session: a persistent PTY session through the session API.
    let out = run(mysh(server).args([
        "session",
        "--accept-new",
        &host,
        "new",
        "--pty",
        "--",
        "true",
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));

    // file: put one file.
    let src = server.dir.join("audited.txt");
    std::fs::write(&src, b"audit me\n").expect("write");
    let out = run(mysh(server).args([
        "put",
        "--accept-new",
        &host,
        &src.display().to_string(),
        "~/audited.txt",
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));

    // forward: a remote listener for the duration of one command.
    let out = run(mysh(server).args(["--accept-new", "-R", "0:127.0.0.1:9", &host, "--", "true"]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));

    // denied: a key the server does not know.
    let stranger = server.dir.join("stranger");
    write_secret_key(&stranger, &SecretKey::generate()).expect("stranger key");
    let out = run(mysh(server).args([
        "--accept-new",
        "-i",
        &stranger.display().to_string(),
        &host,
        "--",
        "true",
    ]));
    assert!(!out.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_log_records_every_event_kind_with_a_stable_schema() {
    let log_dir = common::TempDir::new("audit");
    let log = log_dir.join("audit.log");
    let server = common::start_server(common::ServerOpts {
        audit: Some(log.clone()),
        ..Default::default()
    })
    .await;
    produce_events(&server);

    // Four authorized connections disconnect; the stranger never connects.
    let all = wait_for(&log, "disconnect", 4).await;

    let count = |event: &str| all.iter().filter(|l| l.event == event).count();
    for event in [
        "connect",
        "disconnect",
        "session",
        "exec",
        "file",
        "forward",
        "denied",
    ] {
        assert!(count(event) >= 1, "no `{event}` line in {all:?}");
    }
    assert_eq!(count("connect"), 4);
    assert_eq!(count("disconnect"), 4);

    // Timestamps never go backwards (fixed-width RFC 3339 compares as text).
    assert!(
        all.windows(2).all(|w| w[0].ts <= w[1].ts),
        "timestamps not monotonic: {all:?}"
    );
    for line in &all {
        assert_eq!(line.ts.len(), 24, "{}", line.ts);
        assert!(line.ts.ends_with('Z'));
        assert!(line.peer.starts_with("127.0.0.1:"), "{}", line.peer);
    }

    // Per-event facts.
    let exec = all.iter().find(|l| l.event == "exec").expect("exec line");
    assert_eq!(exec.exit, Some(7));
    assert_eq!(exec.detail["pty"], false);
    assert!(exec.duration_ms.is_some());
    assert_eq!(exec.kind, "x25519");
    assert_eq!(
        exec.key,
        server.client_identity.public.fingerprint().to_string()
    );

    let sessions: Vec<&AuditLine> = all.iter().filter(|l| l.event == "session").collect();
    assert!(sessions.iter().any(|l| l.detail["pty"] == false));
    assert!(sessions.iter().any(|l| l.detail["pty"] == true));
    assert!(
        sessions
            .iter()
            .all(|l| l.detail["argv"].is_array() && l.detail["pid"].is_number())
    );

    let file = all
        .iter()
        .find(|l| l.event == "file" && l.detail["op"] == "put")
        .expect("put line");
    assert_eq!(file.detail["path"], "~/audited.txt");
    assert_eq!(file.bytes_in, Some(9));

    let forward = all
        .iter()
        .find(|l| l.event == "forward")
        .expect("forward line");
    assert_eq!(forward.detail["kind"], "listen");
    assert!(forward.detail["port"].as_u64().is_some_and(|p| p > 0));

    let denied = all
        .iter()
        .find(|l| l.event == "denied")
        .expect("denied line");
    assert_eq!(denied.detail["what"], "handshake");
    assert_ne!(
        denied.key,
        server.client_identity.public.fingerprint().to_string()
    );
    assert!(denied.key.starts_with("SHA256:"), "{}", denied.key);

    let disconnect = all
        .iter()
        .find(|l| l.event == "disconnect")
        .expect("disconnect line");
    assert!(disconnect.bytes_in.is_some_and(|b| b > 0));
    assert!(disconnect.bytes_out.is_some_and(|b| b > 0));
    assert!(disconnect.duration_ms.is_some());

    let mode = std::fs::metadata(&log)
        .expect("log metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_lines_are_appended_across_server_restarts() {
    let log_dir = common::TempDir::new("audit2");
    let log = log_dir.join("audit.log");
    for round in 1..=2 {
        let server = common::start_server(common::ServerOpts {
            audit: Some(log.clone()),
            ..Default::default()
        })
        .await;
        let out = run(mysh(&server).args(["--accept-new", &server.host_arg(), "--", "true"]));
        assert!(out.status.success(), "stderr: {}", text(&out.stderr));
        let all = wait_for(&log, "disconnect", round).await;
        assert_eq!(all.iter().filter(|l| l.event == "connect").count(), round);
        server.stop().await;
    }
}
