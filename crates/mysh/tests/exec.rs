//! Exec sessions through the real binary: exit codes, stdio, environment,
//! policy, scripted prompt input and `-N`, per docs/04-sessions.md (exec
//! session) and docs/05-meta-shell.md ("Modes and exit").
//!
//! Every test uses the multi-thread runtime: the in-process server must keep
//! serving while the test thread blocks on the child.

mod common;

use std::{
    io::Write as _,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use mysh::cli::Feature;

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

/// Run `cmd`, feeding `stdin` then EOF.
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

#[tokio::test(flavor = "multi_thread")]
async fn exit_code_propagates() {
    let server = common::start_server(common::ServerOpts::default()).await;

    let out = run(mysh(&server).arg(server.host_arg()).arg("exit 7"));
    assert_eq!(out.status.code(), Some(7), "stderr: {}", text(&out.stderr));

    let out = run(mysh(&server)
        .arg(server.host_arg())
        .arg("echo out; echo err >&2"));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "out\n");
    assert!(
        text(&out.stderr).contains("err"),
        "stderr: {}",
        text(&out.stderr)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_is_forwarded_until_eof() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = run_with_stdin(
        mysh(&server).arg(server.host_arg()).arg("wc -l"),
        b"a\nb\nc\n",
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "3");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_arg_command_runs_directly() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = run(mysh(&server)
        .arg(server.host_arg())
        .args(["--", "printf", "%s-%s", "a", "b"]));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "a-b");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn signal_exit_maps_to_128_plus_n() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let out = run(mysh(&server).arg(server.host_arg()).arg("kill -TERM $$"));
    assert_eq!(
        out.status.code(),
        Some(143),
        "stderr: {}",
        text(&out.stderr)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn env_allow_list() {
    let server = common::start_server(common::ServerOpts {
        accept_env: vec!["MYVAR".to_owned()],
        ..common::ServerOpts::default()
    })
    .await;

    let out = run(mysh(&server)
        .args(["--env", "MYVAR=hello", "--env", "SECRET=x"])
        .arg(server.host_arg())
        .arg("echo $MYVAR:$SECRET"));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "hello:");

    // `LANG` is always accepted.
    let out = run(mysh(&server)
        .args(["--env", "LANG=C.UTF-8"])
        .arg(server.host_arg())
        .arg("echo $LANG"));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "C.UTF-8");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_denied_by_policy() {
    let server = common::start_server(common::ServerOpts {
        deny: vec![Feature::Exec],
        ..common::ServerOpts::default()
    })
    .await;
    let out = run(mysh(&server).arg(server.host_arg()).arg("true"));
    assert_ne!(out.status.code(), Some(0));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("denied"), "stderr: {stderr}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn scripted_stdin_runs_prompt_commands() {
    let server = common::start_server(common::ServerOpts::default()).await;

    let out = run_with_stdin(
        mysh(&server).arg(server.host_arg()),
        b"ping -c 1\ninfo\nexit\n",
    );
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert!(stdout.contains("pong 1"), "stdout: {stdout}");
    assert!(stdout.contains("protocol:  v1"), "stdout: {stdout}");

    let out = run_with_stdin(mysh(&server).arg(server.host_arg()), b"bogus\n");
    assert_eq!(out.status.code(), Some(1));
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(all.contains("bogus"), "output: {all}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_session_mode_waits_and_handles_sigterm() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let mut child = mysh(&server)
        .arg("-N")
        .arg(server.host_arg())
        .spawn()
        .expect("spawn mysh -N");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "-N must keep waiting"
    );

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(killed.success());

    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "mysh -N did not exit after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0));
    server.stop().await;
}
