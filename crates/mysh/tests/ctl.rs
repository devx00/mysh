//! Control socket, background jobs and parallel recursive transfers
//! (docs/05-meta-shell.md "Control socket" / "Background jobs",
//! docs/04-sessions.md "File transfer"; docs/06-roadmap.md M5).
//!
//! The interactive client runs under a real pty (as in `interactive.rs`);
//! CLI subcommands are spawned as plain child processes with the same
//! `MYSH_CONFIG_DIR`/`HOME`/`XDG_RUNTIME_DIR` so they find its socket.

mod common;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use common::TempDir;
use mysh::{
    cli::{ConnectOpts, GetArgs, PutArgs},
    client::{console::Console, files},
};
use mysh_proto::session::{Signal, WinSize};
use mysh_pty::{
    process,
    pty::{AsyncPtyMaster, open_pty},
    spawn::{Command, spawn_with_pty},
};
use tokio::{io::AsyncReadExt as _, io::AsyncWriteExt as _, task::JoinHandle};

const WAIT: Duration = Duration::from_secs(10);

fn size(cols: u16, rows: u16) -> WinSize {
    WinSize {
        cols,
        rows,
        xpixel: 0,
        ypixel: 0,
    }
}

/// `client_env` with the runtime dir pointed at `run` (a short path: unix
/// socket paths are capped at ~100 bytes).
fn env_with_runtime(server: &common::TestServer, run: &Path) -> Vec<(String, String)> {
    let mut env = common::client_env(server);
    env.retain(|(k, _)| k != "XDG_RUNTIME_DIR");
    env.push(("XDG_RUNTIME_DIR".into(), run.display().to_string()));
    env.push(("SHELL".into(), "/bin/sh".into()));
    env
}

/// The interactive `mysh` binary under a pty, with a reader task collecting
/// everything it writes. Killed with `SIGKILL` on drop unless it was reaped.
struct Driver {
    master: Arc<AsyncPtyMaster>,
    buf: Arc<Mutex<Vec<u8>>>,
    child: tokio::process::Child,
    pid: u32,
    reaped: bool,
    pos: usize,
    reader: JoinHandle<()>,
}

impl Driver {
    fn spawn(server: &common::TestServer, env: &[(String, String)], cwd: PathBuf) -> Self {
        let (master, slave) = open_pty(size(120, 40)).expect("open pty");
        let argv: Vec<OsString> = vec![
            "mysh".into(),
            "--accept-new".into(),
            server.host_arg().into(),
        ];
        let env: Vec<(OsString, OsString)> = env
            .iter()
            .map(|(k, v)| (k.clone().into(), v.clone().into()))
            .collect();
        let cmd = Command {
            program: common::mysh_bin(),
            argv,
            env,
            cwd,
        };
        let spawned = spawn_with_pty(slave, &cmd).expect("spawn mysh");
        let master = Arc::new(master.into_async().expect("async master"));
        let buf = Arc::new(Mutex::new(Vec::new()));
        let reader = {
            let master = Arc::clone(&master);
            let buf = Arc::clone(&buf);
            tokio::spawn(async move {
                let mut rd: &AsyncPtyMaster = &master;
                let mut chunk = [0u8; 8192];
                loop {
                    match rd.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf
                            .lock()
                            .expect("buffer lock")
                            .extend_from_slice(&chunk[..n]),
                    }
                }
            })
        };
        Self {
            master,
            buf,
            child: spawned.child,
            pid: spawned.pid,
            reaped: false,
            pos: 0,
            reader,
        }
    }

    async fn send(&self, text: &str) {
        let mut wr: &AsyncPtyMaster = &self.master;
        wr.write_all(text.as_bytes()).await.expect("write to pty");
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().expect("buffer lock")).into_owned()
    }

    /// Wait until `pattern` appears after the previous match; consumes it.
    async fn wait_for(&mut self, pattern: &str) {
        let deadline = Instant::now() + WAIT;
        loop {
            let found = {
                let buf = self.buf.lock().expect("buffer lock");
                find(&buf[self.pos..], pattern.as_bytes()).map(|i| self.pos + i + pattern.len())
            };
            if let Some(end) = found {
                self.pos = end;
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {pattern:?}; transcript after position {}:\n{}",
                self.pos,
                self.transcript()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_prompt(&mut self, server: &common::TestServer) {
        self.wait_for(&format!("mysh {}> ", server.host_arg()))
            .await;
    }

    async fn wait_exit(&mut self) -> i32 {
        let status = tokio::time::timeout(WAIT, self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("mysh did not exit; transcript:\n{}", self.transcript()))
            .expect("wait child");
        self.reaped = true;
        status
            .code()
            .unwrap_or_else(|| panic!("mysh killed by signal: {status}"))
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.reader.abort();
        if !self.reaped {
            let _ = process::kill(self.pid, Signal::Kill);
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Run `mysh SUB [pre…] --accept-new HOST [post…]` as a child process;
/// returns `(code, stdout, stderr)`.
async fn run_cli(
    server: &common::TestServer,
    env: &[(String, String)],
    cwd: &Path,
    sub: &str,
    pre: &[&str],
    post: &[&str],
) -> (i32, String, String) {
    let mut cmd = tokio::process::Command::new(common::mysh_bin());
    cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    cmd.current_dir(cwd);
    cmd.arg(sub).args(pre).arg("--accept-new");
    cmd.arg(server.host_arg());
    cmd.args(post);
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

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let bytes = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        let take = bytes.len().min(len - out.len());
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

/// Sorted `(relative path, contents)` of every regular file under `root`.
fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).expect("under root").to_path_buf();
                out.push((rel, std::fs::read(&path).expect("read file")));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// A 50-file tree with nested directories and sizes from 0 to past the
/// 64 KiB chunk.
fn make_tree(root: &Path) {
    for i in 0..50u64 {
        let dir = match i % 4 {
            0 => root.to_path_buf(),
            1 => root.join("a"),
            2 => root.join("a").join("deep"),
            _ => root.join("b"),
        };
        std::fs::create_dir_all(&dir).expect("mkdir");
        let len = match i % 5 {
            0 => 0,
            1 => 7,
            2 => 65_536,
            3 => 70_001,
            _ => 200_000,
        };
        std::fs::write(dir.join(format!("f{i}")), random_bytes(len, i + 1)).expect("write");
    }
    std::fs::create_dir_all(root.join("empty")).expect("empty dir");
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_subcommands_reuse_the_interactive_connection() {
    // One handshake per minute: a second connection would be dropped, so a
    // successful `put`/`get`/`authorize` proves the socket was used.
    let server = common::start_server(common::ServerOpts {
        shell: Some(PathBuf::from("/bin/sh")),
        handshakes_per_minute: Some(1),
        ..common::ServerOpts::default()
    })
    .await;
    let run = TempDir::short("ctl");
    let env = env_with_runtime(&server, run.path());
    let lcwd = server.dir.join("lcwd");
    std::fs::create_dir_all(&lcwd).expect("lcwd");
    let payload = random_bytes(300_000, 7);
    std::fs::write(lcwd.join("file"), &payload).expect("write payload");

    let mut m = Driver::spawn(&server, &env, lcwd.clone());
    m.wait_prompt(&server).await;
    let sock = run
        .path()
        .join("mysh")
        .join(format!("127.0.0.1_{}.sock", server.port()));
    assert!(sock.exists(), "socket {} not created", sock.display());

    // put: relative local path resolved against the requester's cwd.
    let (code, out, err) = run_cli(&server, &env, &lcwd, "put", &[], &["file", "~/dest"]).await;
    assert_eq!(code, 0, "put failed:\nstdout:{out}\nstderr:{err}");
    assert!(out.contains("1 file"), "summary missing: {out}");
    assert_eq!(
        std::fs::read(server.home.join("dest")).expect("dest landed"),
        payload
    );
    m.wait_for("[mysh] ctl: put").await;

    // get through the socket.
    let (code, out, err) = run_cli(&server, &env, &lcwd, "get", &[], &["~/dest", "copy"]).await;
    assert_eq!(code, 0, "get failed:\nstdout:{out}\nstderr:{err}");
    assert_eq!(std::fs::read(lcwd.join("copy")).expect("copy"), payload);

    // authorize through the socket.
    let (code, out, err) = run_cli(&server, &env, &lcwd, "authorize", &[], &[]).await;
    assert_eq!(code, 0, "authorize failed:\nstdout:{out}\nstderr:{err}");
    let keys =
        std::fs::read_to_string(&server.server_authorized_keys).expect("authorized_keys written");
    assert!(keys.contains("mysh-x25519"), "{keys}");

    // A failing request reports the error and exits 1 (no fallback).
    let (code, _, err) = run_cli(&server, &env, &lcwd, "get", &[], &["~/nope", "x"]).await;
    assert_eq!(code, 1, "stderr:{err}");
    assert!(err.contains("not found"), "{err}");

    // --no-ctl bypasses the socket; the rate limiter drops the handshake.
    let (code, _, _) = run_cli(
        &server,
        &env,
        &lcwd,
        "put",
        &["--no-ctl"],
        &["file", "~/dest2"],
    )
    .await;
    assert_ne!(code, 0, "--no-ctl must open its own connection");
    assert!(!server.home.join("dest2").exists());

    // The socket goes away with the client.
    m.send("exit\r").await;
    assert_eq!(m.wait_exit().await, 0);
    assert!(!sock.exists(), "socket {} not removed", sock.display());
    server.stop().await;
}

#[tokio::test]
async fn cli_falls_back_without_a_socket() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let run = TempDir::short("ctlfb");
    let env = env_with_runtime(&server, run.path());
    let lcwd = server.dir.join("lcwd");
    std::fs::create_dir_all(&lcwd).expect("lcwd");
    std::fs::write(lcwd.join("f"), b"plain").expect("write");

    let (code, out, err) = run_cli(&server, &env, &lcwd, "put", &[], &["f", "~/one"]).await;
    assert_eq!(code, 0, "stdout:{out}\nstderr:{err}");
    assert_eq!(
        std::fs::read(server.home.join("one")).expect("one"),
        b"plain"
    );

    let (code, out, err) =
        run_cli(&server, &env, &lcwd, "put", &["--no-ctl"], &["f", "~/two"]).await;
    assert_eq!(code, 0, "stdout:{out}\nstderr:{err}");
    assert_eq!(
        std::fs::read(server.home.join("two")).expect("two"),
        b"plain"
    );
    server.stop().await;
}

#[tokio::test]
async fn background_jobs_at_the_prompt() {
    let server = common::start_server(common::ServerOpts {
        shell: Some(PathBuf::from("/bin/sh")),
        ..common::ServerOpts::default()
    })
    .await;
    let run = TempDir::short("jobs");
    let env = env_with_runtime(&server, run.path());
    let lcwd = server.dir.join("lcwd");
    std::fs::create_dir_all(&lcwd).expect("lcwd");
    let payload = random_bytes(8 * 1024 * 1024, 3);
    std::fs::write(lcwd.join("bigfile"), &payload).expect("write payload");

    let mut m = Driver::spawn(&server, &env, lcwd.clone());
    m.wait_prompt(&server).await;

    // A slow job: the prompt returns at once and `jobs` shows it running.
    m.send("exec sleep 1 &\r").await;
    m.wait_for("[1] started").await;
    m.wait_prompt(&server).await;
    m.send("jobs\r").await;
    m.wait_for("exec sleep 1").await;
    let listing = m.transcript();
    assert!(
        listing.contains("running"),
        "job should still be running:\n{listing}"
    );
    m.wait_prompt(&server).await;
    m.send("jobs -w 1\r").await;
    m.wait_for("job 1 done").await;
    m.wait_prompt(&server).await;

    // A transfer job lands the file and announces completion with its size.
    m.send("put bigfile ~/bg &\r").await;
    m.wait_for("[2] started").await;
    m.wait_prompt(&server).await;
    m.wait_for("[mysh] job 2 done: put bigfile ~/bg (8.0 MiB")
        .await;
    assert_eq!(std::fs::read(server.home.join("bg")).expect("bg"), payload);
    m.send("jobs 2\r").await;
    m.wait_for("job 2 done").await;
    m.wait_for("1 file, 8.0 MiB").await;
    m.wait_prompt(&server).await;

    // Terminal-bound commands cannot be backgrounded; a lone `&` is an error.
    m.send("shell &\r").await;
    m.wait_for("only put, get, ls, exec and authorize").await;
    m.wait_prompt(&server).await;
    m.send("&\r").await;
    m.wait_for("nothing to run in the background").await;
    m.wait_prompt(&server).await;

    // `kill %ID` cancels a running job.
    m.send("exec sleep 30 &\r").await;
    m.wait_for("[3] started").await;
    m.wait_prompt(&server).await;
    m.send("kill %3\r").await;
    m.wait_for("job 3 cancelled").await;
    m.wait_prompt(&server).await;
    m.send("jobs -w 3\r").await;
    m.wait_for("job 3 cancelled:").await;
    m.wait_prompt(&server).await;

    m.send("exit\r").await;
    assert_eq!(m.wait_exit().await, 0);
    server.stop().await;
}

#[tokio::test]
async fn parallel_recursive_transfers_are_byte_identical() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let console = Console::new();
    let local = server.dir.join("local");
    let tree = local.join("tree");
    make_tree(&tree);
    let expected = snapshot(&tree);
    assert_eq!(expected.len(), 50);

    files::put(
        &conn,
        Arc::new(console.clone()),
        &PutArgs {
            recursive: true,
            preserve: true,
            jobs: 4,
            paths: vec![tree.display().to_string(), "~/up".to_owned()],
            ..PutArgs::default()
        },
        None,
        &local,
    )
    .await
    .expect("put -r -j 4");
    assert_eq!(snapshot(&server.home.join("up")), expected);
    assert!(server.home.join("up/empty").is_dir());

    let down = local.join("down");
    files::get(
        &conn,
        Arc::new(console.clone()),
        &GetArgs {
            recursive: true,
            jobs: 4,
            paths: vec!["~/up".to_owned(), down.display().to_string()],
            ..GetArgs::default()
        },
        None,
        &local,
    )
    .await
    .expect("get -r -j 4");
    assert_eq!(snapshot(&down), expected);
    assert!(down.join("empty").is_dir());

    // A file that cannot be written locally (a directory sits where it
    // goes) aborts the whole tree with an error naming it.
    let down2 = local.join("down2");
    std::fs::create_dir_all(down2.join("up").join("a").join("f1")).expect("blocking dir");
    let err = files::get(
        &conn,
        Arc::new(console.clone()),
        &GetArgs {
            recursive: true,
            jobs: 4,
            paths: vec!["~/up".to_owned(), down2.display().to_string()],
            ..GetArgs::default()
        },
        None,
        &local,
    )
    .await
    .expect_err("blocked file fails");
    assert!(format!("{err:#}").contains("f1"), "{err:#}");

    conn.close().await;
    server.stop().await;
}

/// `put -` / `write` / `CMD` with more stdin than a control request may
/// carry fall back to a connection of their own; the bytes the socket probe
/// already consumed must not be lost (regression: the first 64 KiB vanished).
#[tokio::test]
async fn large_stdin_survives_the_control_socket_fallback() {
    let server = common::start_server(common::ServerOpts {
        shell: Some(PathBuf::from("/bin/sh")),
        ..common::ServerOpts::default()
    })
    .await;
    let run = TempDir::short("ctls");
    let env = env_with_runtime(&server, run.path());
    let lcwd = server.dir.join("lcwd");
    std::fs::create_dir_all(&lcwd).expect("lcwd");
    let payload = random_bytes(300_000, 11); // > CTL_STDIN_MAX (64 KiB)

    let mut m = Driver::spawn(&server, &env, lcwd.clone());
    m.wait_prompt(&server).await;

    for (sub, post, dest) in [
        ("put", vec!["-", "~/piped"], "piped"),
        ("write", vec!["~/written"], "written"),
    ] {
        let mut cmd = tokio::process::Command::new(common::mysh_bin());
        cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
        cmd.current_dir(&lcwd);
        cmd.arg(sub)
            .arg("--accept-new")
            .arg(server.host_arg())
            .args(&post);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn cli");
        let mut stdin = child.stdin.take().expect("stdin");
        let bytes = payload.clone();
        let feeder = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            stdin.write_all(&bytes).await.expect("feed stdin");
            stdin.shutdown().await.expect("close stdin");
        });
        let out = tokio::time::timeout(WAIT, child.wait_with_output())
            .await
            .expect("cli timed out")
            .expect("cli");
        feeder.await.expect("feeder");
        assert!(
            out.status.success(),
            "{sub} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read(server.home.join(dest)).expect("landed"),
            payload,
            "{sub}: remote bytes differ from what was piped in"
        );
    }

    // Same for a remote command's stdin.
    let mut cmd = tokio::process::Command::new(common::mysh_bin());
    cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    cmd.current_dir(&lcwd);
    cmd.arg("--accept-new").arg(server.host_arg()).arg("wc -c");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn cli");
    let mut stdin = child.stdin.take().expect("stdin");
    let bytes = payload.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let _ = stdin.write_all(&bytes).await;
        let _ = stdin.shutdown().await;
    });
    let out = tokio::time::timeout(WAIT, child.wait_with_output())
        .await
        .expect("cli timed out")
        .expect("cli");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        payload.len().to_string(),
        "wc -c over the fallback: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    m.send("disconnect\r").await;
}
