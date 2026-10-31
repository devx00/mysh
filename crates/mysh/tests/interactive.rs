//! Black-box tests of the interactive client under a real pty: the session
//! stack, meta key, background buffering and ring-drop accounting, exit
//! rules and the exit code (docs/05-client.md "Session stack" and "Modes and
//! exit"; docs/06-roadmap.md M3 tests).
//!
//! The server runs `/bin/sh` so the remote shell is predictable; every
//! synchronisation point waits for a marker the test itself produced (an
//! `echo` with arithmetic, so the typed line never matches its own output).

mod common;

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use mysh_proto::session::{Signal, WinSize};
use mysh_pty::{
    process,
    pty::{AsyncPtyMaster, open_pty},
    spawn::{Command, spawn_with_pty},
};
use tokio::{io::AsyncReadExt as _, io::AsyncWriteExt as _, task::JoinHandle};

const META: &str = "\x1d";
const WAIT: Duration = Duration::from_secs(5);
const EXIT_WAIT: Duration = Duration::from_secs(10);

fn size(cols: u16, rows: u16) -> WinSize {
    WinSize {
        cols,
        rows,
        xpixel: 0,
        ypixel: 0,
    }
}

/// The `mysh` binary under a pty, with a reader task collecting everything
/// it writes. Killed with `SIGKILL` on drop unless it was reaped.
struct Driver {
    master: Arc<AsyncPtyMaster>,
    buf: Arc<Mutex<Vec<u8>>>,
    child: tokio::process::Child,
    pid: u32,
    reaped: bool,
    /// Search position for [`Driver::wait_for`]: matches are consumed in
    /// order so an old prompt never satisfies a later wait.
    pos: usize,
    reader: JoinHandle<()>,
}

impl Driver {
    /// Spawn `mysh --accept-new [extra…] HOST` in `server`'s temp tree.
    fn spawn(server: &common::TestServer, extra: &[&str]) -> Self {
        let (master, slave) = open_pty(size(120, 40)).expect("open pty");
        let cwd = server.dir.join("lcwd");
        std::fs::create_dir_all(&cwd).expect("local cwd");

        let mut argv: Vec<OsString> = vec!["mysh".into(), "--accept-new".into()];
        argv.extend(extra.iter().map(OsString::from));
        argv.push(server.host_arg().into());
        let mut env: Vec<(OsString, OsString)> = common::client_env(server)
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        env.push(("SHELL".into(), "/bin/sh".into()));

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

    /// Type `text` as if at the keyboard.
    async fn send(&self, text: &str) {
        let mut wr: &AsyncPtyMaster = &self.master;
        wr.write_all(text.as_bytes()).await.expect("write to pty");
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().expect("buffer lock")).into_owned()
    }

    fn contains(&self, pattern: &str) -> bool {
        self.transcript().contains(pattern)
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

    /// Wait for the meta prompt.
    async fn wait_prompt(&mut self, server: &common::TestServer) {
        let prompt = format!("mysh {}> ", server.host_arg());
        self.wait_for(&prompt).await;
    }

    /// Wait for the remote `/bin/sh` to be ready: run a marker command.
    async fn sync_shell(&mut self, tag: u32) {
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.send(&format!("echo SYNC_$(({tag}+1000))\r")).await;
        self.wait_for(&format!("SYNC_{}", tag + 1000)).await;
    }

    /// Wait for the process to exit; returns its exit code.
    async fn wait_exit(&mut self) -> i32 {
        let status = tokio::time::timeout(EXIT_WAIT, self.child.wait())
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

async fn start() -> common::TestServer {
    common::start_server(common::ServerOpts {
        shell: Some(PathBuf::from("/bin/sh")),
        ..common::ServerOpts::default()
    })
    .await
}

#[tokio::test]
async fn shell_meta_key_sessions_fg_and_primary_exit_code() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &["-s"]);

    m.sync_shell(1).await;
    m.send("echo M$((20+22))\r").await;
    m.wait_for("M42").await;

    m.send(META).await;
    m.wait_prompt(&server).await;
    m.send("sessions\r").await;
    m.wait_for("* 1    ").await;

    m.send("shell\r").await;
    m.sync_shell(2).await;
    m.send("echo S$((1+1))\r").await;
    m.wait_for("S2").await;

    m.send(META).await;
    m.wait_prompt(&server).await;
    m.send("sessions\r").await;
    m.wait_for("* 2    ").await;
    m.wait_for("  1    ").await;

    m.send("fg 1\r").await;
    m.sync_shell(3).await;
    m.send("echo B$((3+3))\r").await;
    m.wait_for("B6").await;
    m.send("exit 4\r").await;
    m.wait_for("session 1 exited: exit 4").await;

    m.wait_prompt(&server).await;
    m.send("exit\r").await;
    m.wait_for("still running").await;

    m.send("fg\r").await;
    m.sync_shell(4).await;
    m.send("exit\r").await;
    let code = m.wait_exit().await;
    assert_eq!(
        code, 4,
        "exit code follows the primary session (1), not the last one"
    );

    server.stop().await;
}

#[tokio::test]
async fn background_output_is_buffered_and_replayed() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &[]);

    m.wait_prompt(&server).await;
    m.send("shell\r").await;
    m.sync_shell(1).await;
    m.send("sh -c 'sleep 0.5; echo BG$((5+5))' &\r").await;
    m.send(META).await;
    m.wait_prompt(&server).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !m.contains("BG10"),
        "background output must not reach the terminal:\n{}",
        m.transcript()
    );

    m.send("fg\r").await;
    m.wait_for("BG10").await;

    m.send("exit\r").await;
    m.wait_for("session 1 exited: exit 0").await;
    m.wait_prompt(&server).await;
    m.send("exit\r").await;
    assert_eq!(m.wait_exit().await, 0);

    server.stop().await;
}

#[tokio::test]
async fn ring_drop_accounting_past_1mib() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &[]);

    m.wait_prompt(&server).await;
    m.send("shell\r").await;
    m.sync_shell(1).await;
    m.send("sleep 0.3; head -c 2000000 /dev/zero | tr '\\0' x; echo END_$((7+7))\r")
        .await;
    m.send(META).await;
    m.wait_prompt(&server).await;

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !m.contains("END_14"),
        "background output must not reach the terminal:\n{}",
        m.transcript()
    );

    m.send("fg\r").await;
    m.wait_for("bytes of output dropped").await;
    m.wait_for("END_14").await;

    // The notice names the drop count; the replayed tail is at most 1 MiB.
    let transcript = m.transcript();
    let notice = transcript
        .lines()
        .find(|l| l.contains("bytes of output dropped"))
        .expect("drop notice line");
    assert!(notice.contains("[mysh] "), "notice line: {notice:?}");
    let dropped: usize = notice
        .split_whitespace()
        .find_map(|w| w.parse().ok())
        .expect("drop count in notice");
    assert!(
        dropped >= 2_000_000 - 1024 * 1024,
        "dropped {dropped} bytes, expected at least the excess over 1 MiB"
    );

    m.send("exit\r").await;
    m.wait_for("session 1 exited: exit 0").await;
    m.wait_prompt(&server).await;
    m.send("exit\r").await;
    assert_eq!(m.wait_exit().await, 0);

    server.stop().await;
}

#[tokio::test]
async fn exit_refused_while_session_runs_and_disconnect_ends() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &[]);

    m.wait_prompt(&server).await;
    m.send("shell\r").await;
    m.sync_shell(1).await;
    m.send(META).await;
    m.wait_prompt(&server).await;

    m.send("exit\r").await;
    m.wait_for("still running").await;
    m.wait_prompt(&server).await;

    let started = Instant::now();
    m.send("disconnect\r").await;
    assert_eq!(m.wait_exit().await, 0);
    assert!(started.elapsed() < Duration::from_secs(5));

    server.stop().await;
}

#[tokio::test]
async fn exit_code_follows_primary_under_s() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &["-s"]);

    m.sync_shell(1).await;
    m.send("exit 9\r").await;
    assert_eq!(m.wait_exit().await, 9);

    server.stop().await;
}

#[tokio::test]
async fn ctrl_d_at_prompt_with_no_sessions_exits_zero() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &[]);

    m.wait_prompt(&server).await;
    m.send("\x04").await;
    assert_eq!(m.wait_exit().await, 0);

    server.stop().await;
}

#[tokio::test]
async fn resize_reaches_foreground_session() {
    let server = start().await;
    let mut m = Driver::spawn(&server, &["-s"]);

    m.sync_shell(1).await;
    m.send("stty size\r").await;
    m.wait_for("40 120").await;

    m.master.resize(size(90, 30)).expect("resize pty");
    // SIGWINCH → client → `Resize` on the session stream, then `stty size`.
    tokio::time::sleep(Duration::from_millis(300)).await;
    m.send("stty size\r").await;
    m.wait_for("30 90").await;

    m.send("exit\r").await;
    assert_eq!(m.wait_exit().await, 0);

    server.stop().await;
}
