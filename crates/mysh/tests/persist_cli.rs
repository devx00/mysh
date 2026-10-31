//! Black-box tests of session persistence through the `mysh` binary under a
//! real pty (docs/05-meta-shell.md "Session persistence", docs/06-roadmap.md
//! M5): a `SIGKILL`ed client leaves its shell running, `mysh --attach HOST`
//! replays what it printed meanwhile and restores typing; `disconnect`
//! leaves the session attachable; `detach`/`attach`/`sessions -a` at the
//! prompt; a clear error when the server keeps no sessions.
//!
//! The driver is the one from `tests/interactive.rs`: every synchronisation
//! point waits for a marker the test itself produced (an `echo` with
//! arithmetic, so the typed line never matches its own output).

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

    /// `SIGKILL` the client (a crash, a lost laptop) and reap it.
    async fn kill(&mut self) {
        process::kill(self.pid, Signal::Kill).expect("kill client");
        let _ = tokio::time::timeout(EXIT_WAIT, self.child.wait()).await;
        self.reaped = true;
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

async fn start(grace: Duration) -> common::TestServer {
    common::start_server(common::ServerOpts {
        shell: Some(PathBuf::from("/bin/sh")),
        detach_grace: Some(grace),
        ..common::ServerOpts::default()
    })
    .await
}

#[tokio::test]
async fn sigkilled_client_can_reattach_and_sees_the_marker() {
    let server = start(Duration::from_secs(30)).await;
    let mut first = Driver::spawn(&server, &["-s"]);
    first.sync_shell(1).await;
    // Prints after the client is gone; wait for the remote echo so the line
    // has reached the shell before the kill.
    first.send("sleep 0.5; echo MARK_$((5+5))\r").await;
    first.wait_for("MARK_$((5+5))").await;
    first.kill().await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let mut second = Driver::spawn(&server, &["--attach"]);
    second.wait_for("MARK_10").await;
    second.send("echo AFTER_$((2+2))\r").await;
    second.wait_for("AFTER_4").await;
    second.send("exit 3\r").await;
    assert_eq!(
        second.wait_exit().await,
        3,
        "the attached session is the primary: its status is the exit code"
    );

    server.stop().await;
}

#[tokio::test]
async fn disconnect_leaves_the_session_attachable() {
    let server = start(Duration::from_secs(30)).await;
    let mut first = Driver::spawn(&server, &[]);
    first.wait_prompt(&server).await;
    first.send("shell\r").await;
    first.sync_shell(1).await;
    first.send(META).await;
    first.wait_prompt(&server).await;
    first.send("disconnect\r").await;
    assert_eq!(first.wait_exit().await, 0);

    let mut second = Driver::spawn(&server, &["--attach=1"]);
    second.sync_shell(2).await;
    second.send("echo AFTER_$((3+3))\r").await;
    second.wait_for("AFTER_6").await;
    second.send("exit\r").await;
    assert_eq!(second.wait_exit().await, 0);

    server.stop().await;
}

#[tokio::test]
async fn detach_and_attach_at_the_prompt() {
    let server = start(Duration::from_secs(30)).await;
    let mut m = Driver::spawn(&server, &[]);
    m.wait_prompt(&server).await;
    m.send("attach\r").await;
    m.wait_for("no detached sessions").await;

    m.send("shell\r").await;
    m.sync_shell(1).await;
    m.send("sleep 0.3; echo LATER_$((7+7))\r").await;
    m.send(META).await;
    m.wait_prompt(&server).await;
    m.send("detach\r").await;
    m.wait_for("session 1 detached; reattach with: mysh --attach=1")
        .await;
    m.wait_prompt(&server).await;
    m.send("sessions\r").await;
    m.wait_for("no sessions").await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    m.send("sessions -a\r").await;
    m.wait_for("server:").await;
    m.wait_for("detached ").await;

    m.send("attach\r").await;
    m.wait_for("LATER_14").await;
    m.sync_shell(2).await;
    m.send(META).await;
    m.wait_prompt(&server).await;
    m.send("sessions\r").await;
    m.wait_for("* 1    ").await;
    m.send("fg\r").await;
    m.sync_shell(3).await;
    m.send("exit\r").await;
    m.wait_for("session 1 exited: exit 0").await;
    m.wait_prompt(&server).await;
    m.send("exit\r").await;
    assert_eq!(m.wait_exit().await, 0);

    server.stop().await;
}

#[tokio::test]
async fn attach_without_persistence_is_a_clear_error() {
    let server = start(Duration::ZERO).await;
    let mut m = Driver::spawn(&server, &["--attach"]);
    m.wait_for("does not keep detached sessions").await;
    assert_eq!(m.wait_exit().await, 2);

    let mut m = Driver::spawn(&server, &[]);
    m.wait_prompt(&server).await;
    m.send("shell\r").await;
    m.sync_shell(1).await;
    m.send(META).await;
    m.wait_prompt(&server).await;
    m.send("detach\r").await;
    m.wait_for("does not keep detached sessions").await;
    m.send("disconnect\r").await;
    assert_eq!(m.wait_exit().await, 0);

    server.stop().await;
}
