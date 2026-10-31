//! Spawn a session child: either with a pty slave as its controlling tty, or
//! with plain pipes (exec sessions). See `docs/04-sessions.md`.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::Stdio;

use crate::pty::PtySlave;

/// What to run. `argv[0]` is included (e.g. `-bash` for a login shell) and
/// becomes the child's `arg0`; `program` is what is actually executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: PathBuf,
    pub argv: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
}

/// A running child and its pid (captured at spawn; `Child::id` becomes
/// `None` once the child is reaped).
#[derive(Debug)]
pub struct Spawned {
    pub child: tokio::process::Child,
    pub pid: u32,
}

fn base_command(cmd: &Command) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(&cmd.program);
    if let Some((arg0, rest)) = cmd.argv.split_first() {
        command.arg0(arg0).args(rest);
    }
    command
        .env_clear()
        .envs(cmd.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&cmd.cwd)
        .kill_on_drop(false);
    command
}

fn finish(mut command: tokio::process::Command) -> io::Result<Spawned> {
    let child = command.spawn()?;
    // `Command` holds the `Stdio` descriptors (dups of the slave) until it is
    // dropped; drop it now so the parent keeps no slave fd and master reads
    // see EOF when the child side closes.
    drop(command);
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("spawned child has no pid"))?;
    Ok(Spawned { child, pid })
}

/// Spawn `cmd` with `slave` as stdin/stdout/stderr and controlling tty.
///
/// The child runs `setsid()` then `ioctl(0, TIOCSCTTY)` before exec. The
/// slave is consumed: every parent-side copy is closed before this returns.
pub fn spawn_with_pty(slave: PtySlave, cmd: &Command) -> io::Result<Spawned> {
    let slave: OwnedFd = slave.0;
    let mut command = base_command(cmd);
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));

    // SAFETY: the closure runs in the forked child before exec and only calls
    // async-signal-safe syscalls (`setsid`, `ioctl`) on fd 0, which std has
    // already dup2'd from the slave `Stdio`. No allocation, no locks.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid()?;
            rustix::process::ioctl_tiocsctty(rustix::stdio::stdin())?;
            Ok(())
        });
    }
    finish(command)
}

/// Spawn `cmd` with piped stdin/stdout/stderr and its own session
/// (`setsid()`), for exec sessions without a pty.
pub fn spawn_piped(cmd: &Command) -> io::Result<Spawned> {
    let mut command = base_command(cmd);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SAFETY: runs in the forked child before exec; `setsid` is
    // async-signal-safe and touches no parent state.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    finish(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{default_path, exit_status};
    use crate::pty::open_pty;
    use mysh_proto::session::{ExitStatus, WinSize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sh(script: &str) -> Command {
        Command {
            program: PathBuf::from("/bin/sh"),
            argv: vec!["sh".into(), "-c".into(), script.into()],
            env: vec![("PATH".into(), default_path().into())],
            cwd: PathBuf::from("/"),
        }
    }

    fn size(cols: u16, rows: u16) -> WinSize {
        WinSize {
            cols,
            rows,
            xpixel: 0,
            ypixel: 0,
        }
    }

    async fn run_in_pty(
        size: WinSize,
        resize_to: Option<WinSize>,
        script: &str,
    ) -> (String, ExitStatus) {
        let (master, slave) = open_pty(size).expect("open pty");
        if let Some(new) = resize_to {
            master.resize(new).expect("resize");
        }
        let mut spawned = spawn_with_pty(slave, &sh(script)).expect("spawn");
        let mut master = master.into_async().expect("async master");

        let mut out = Vec::new();
        master
            .read_to_end(&mut out)
            .await
            .expect("read master to EOF");
        let status = spawned.child.wait().await.expect("wait");
        (
            String::from_utf8_lossy(&out).into_owned(),
            exit_status(status),
        )
    }

    #[tokio::test]
    async fn child_sees_initial_window_size() {
        let (out, status) = run_in_pty(size(100, 40), None, "stty size").await;
        assert!(out.contains("40 100"), "stty output: {out:?}");
        assert_eq!(status, ExitStatus::Code(0));
    }

    #[tokio::test]
    async fn resize_before_spawn_is_visible_to_child() {
        let (out, _) = run_in_pty(size(100, 40), Some(size(120, 50)), "stty size").await;
        assert!(out.contains("50 120"), "stty output: {out:?}");
    }

    #[tokio::test]
    async fn pty_child_has_the_slave_as_controlling_tty() {
        // `tty` resolves stdin only if it is a terminal; `/dev/tty` opens
        // only if the process has a controlling terminal (TIOCSCTTY worked).
        let (out, status) = run_in_pty(size(80, 24), None, "tty && : < /dev/tty").await;
        assert!(out.contains("/dev/"), "stdin must be the pty, got {out:?}");
        assert!(
            !out.contains("not a tty"),
            "stdin must be the pty, got {out:?}"
        );
        assert_eq!(status, ExitStatus::Code(0), "no controlling tty: {out:?}");
    }

    #[tokio::test]
    async fn foreground_pgrp_is_the_child() {
        let (master, slave) = open_pty(size(80, 24)).expect("open pty");
        let mut spawned = spawn_with_pty(slave, &sh("cat")).expect("spawn");
        // `spawn` returns only after exec, so setsid/TIOCSCTTY have run.
        assert_eq!(
            master.foreground_pgrp().expect("tcgetpgrp"),
            Some(spawned.pid)
        );

        let mut master = master.into_async().expect("async master");
        // ^D at line start → EOF for cat (ICANON is on).
        master.write_all(b"\x04").await.expect("write eot");
        let mut out = Vec::new();
        master.read_to_end(&mut out).await.expect("read to EOF");
        let status = spawned.child.wait().await.expect("wait");
        assert_eq!(exit_status(status), ExitStatus::Code(0));
    }

    #[tokio::test]
    async fn exit_code_is_reported() {
        let mut spawned = spawn_piped(&sh("exit 7")).expect("spawn");
        let status = spawned.child.wait().await.expect("wait");
        assert_eq!(exit_status(status), ExitStatus::Code(7));
    }

    #[tokio::test]
    async fn death_by_signal_is_reported() {
        let mut spawned = spawn_piped(&sh("kill -TERM $$")).expect("spawn");
        let status = spawned.child.wait().await.expect("wait");
        assert_eq!(
            exit_status(status),
            ExitStatus::Signal {
                signal: 15,
                core_dumped: false
            }
        );
    }

    #[tokio::test]
    async fn piped_round_trip_and_stdin_eof() {
        let mut spawned = spawn_piped(&sh("cat")).expect("spawn");
        let mut stdin = spawned.child.stdin.take().expect("stdin");
        let mut stdout = spawned.child.stdout.take().expect("stdout");
        stdin.write_all(b"hello mysh\n").await.expect("write");
        // StdinEof: dropping the write end closes the child's stdin.
        drop(stdin);
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"hello mysh\n");
        let status = spawned.child.wait().await.expect("wait");
        assert_eq!(exit_status(status), ExitStatus::Code(0));
    }

    #[tokio::test]
    async fn env_is_cleared_and_cwd_applied() {
        let mut cmd = sh("echo \"$PATH|$HOME|$(pwd)\"");
        cmd.cwd = PathBuf::from("/");
        let mut spawned = spawn_piped(&cmd).expect("spawn");
        let mut stdout = spawned.child.stdout.take().expect("stdout");
        let mut out = String::new();
        stdout.read_to_string(&mut out).await.expect("read");
        spawned.child.wait().await.expect("wait");
        assert_eq!(out.trim(), format!("{}||/", default_path()));
    }
}
