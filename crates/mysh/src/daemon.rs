//! `--daemon` for `serve` and `accept` (docs/05-meta-shell.md, "Running
//! without a supervisor"): the process re-executes itself detached — its
//! own process group, standard input from `/dev/null`, standard output and
//! error appended to a log file — and the parent returns 0 only once the
//! child reports that it is listening (or accepting), so a script can rely
//! on the exit status.
//!
//! The child learns where to report through [`READY_FILE_ENV`]; it writes
//! its pid there from [`ready`]. No `fork(2)`: `unsafe` stays confined to
//! `mysh-pty`, and a re-exec gives the same detachment. A supervisor
//! (systemd, launchd, Termux:Boot; see `contrib/`) should run the
//! foreground form instead.

use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use tracing::debug;

/// Environment variable naming the file the detached child writes its pid
/// to once it is ready; set by the parent, read once by [`ready`].
pub const READY_FILE_ENV: &str = "MYSH_READY_FILE";

/// How long the parent waits for the child to come up.
const READY_WAIT: Duration = Duration::from_secs(15);
const READY_POLL: Duration = Duration::from_millis(50);
/// Bytes of the log shown when the child dies before it is ready.
const LOG_TAIL: u64 = 4096;

/// The `--daemon` family of options, shared by `serve` and `accept`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct DaemonArgs {
    /// Detach: re-run in the background (own process group, no terminal)
    /// and exit 0 once it is up; `--log` and `--pid-file` say where it
    /// writes. Prefer a service unit from `contrib/` where one exists.
    #[arg(long)]
    pub daemon: bool,

    /// With `--daemon`: append the log to PATH (default
    /// `$XDG_STATE_HOME/mysh/<command>.log`).
    #[arg(long, value_name = "PATH")]
    pub log: Option<PathBuf>,

    /// Write the process id to PATH once up (removed on exit); with
    /// `--daemon` or without.
    #[arg(long, value_name = "PATH")]
    pub pid_file: Option<PathBuf>,
}

/// What the parent reports after a successful detach.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Started {
    pub pid: u32,
    pub log: PathBuf,
}

/// Parent side: re-exec the current command line without `--daemon`,
/// detached, and wait until the child reports ready. `default_log` is used
/// when `--log` was not given.
pub fn spawn(args: &DaemonArgs, default_log: &Path) -> Result<Started> {
    let exe = std::env::current_exe().context("locating the mysh binary")?;
    let child_args: Vec<OsString> = std::env::args_os()
        .skip(1)
        .filter(|a| a != "--daemon")
        .collect();
    let log = args
        .log
        .clone()
        .unwrap_or_else(|| default_log.to_path_buf());
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log)
        .with_context(|| format!("opening log {}", log.display()))?;
    // Only what this child writes is shown on failure, not earlier runs.
    let log_start = log_file.metadata().map_or(0, |m| m.len());
    let log_err = log_file.try_clone().context("duplicating the log handle")?;
    let ready_path = ready_file_path();
    let _ = std::fs::remove_file(&ready_path);

    let mut child = Command::new(&exe)
        .args(&child_args)
        .env(READY_FILE_ENV, &ready_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        // Own process group: a Ctrl-C or hangup on this terminal must not
        // reach the daemon.
        .process_group(0)
        .spawn()
        .context("starting the detached process")?;
    debug!(pid = child.id(), log = %log.display(), "detached child spawned");

    let deadline = Instant::now() + READY_WAIT;
    let outcome = loop {
        if let Ok(contents) = std::fs::read_to_string(&ready_path)
            && contents.trim() == child.id().to_string()
        {
            break Ok(());
        }
        match child
            .try_wait()
            .context("waiting for the detached process")?
        {
            Some(status) => break Err(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_file(&ready_path);
                bail!(
                    "the detached process did not come up within {}s (log: {})",
                    READY_WAIT.as_secs(),
                    log.display()
                );
            }
            None => std::thread::sleep(READY_POLL),
        }
    };
    let _ = std::fs::remove_file(&ready_path);
    match outcome {
        Ok(()) => Ok(Started {
            pid: child.id(),
            log,
        }),
        Err(status) => {
            let tail = log_tail(&log, log_start).unwrap_or_default();
            let tail = tail.trim();
            if tail.is_empty() {
                bail!(
                    "the detached process exited ({status}) before it was up; see {}",
                    log.display()
                );
            }
            bail!("the detached process exited ({status}) before it was up:\n{tail}");
        }
    }
}

/// Child side: report readiness to a waiting parent (if any) and write the
/// pid file (if any). The returned guard removes the pid file on drop.
pub fn ready(args: &DaemonArgs) -> Result<PidFile> {
    let pid = std::process::id().to_string();
    if let Some(path) = &args.pid_file {
        write_atomic(path, &pid).with_context(|| format!("writing pid file {}", path.display()))?;
    }
    // The variable is left in place (`remove_var` is unsafe): session
    // children start from a cleared environment, so nothing inherits it.
    if let Some(path) = std::env::var_os(READY_FILE_ENV) {
        write_atomic(Path::new(&path), &pid)
            .with_context(|| format!("reporting readiness to {}", Path::new(&path).display()))?;
    }
    Ok(PidFile {
        path: args.pid_file.clone(),
    })
}

/// Removes the pid file when dropped (at a clean exit).
#[derive(Debug)]
pub struct PidFile {
    path: Option<PathBuf>,
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The default log path for `command` next to the prompt history:
/// `$XDG_STATE_HOME/mysh/<command>.log`.
#[must_use]
pub fn default_log(history: &Path, command: &str) -> PathBuf {
    history
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        .join(format!("{command}.log"))
}

fn ready_file_path() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    std::env::temp_dir().join(format!("mysh-ready-{}-{nanos}", std::process::id()))
}

/// Write `text` (plus newline) to `path` through a temp file and rename, so
/// a reader never sees a partial pid.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// The log from `from` on, capped to the last [`LOG_TAIL`] bytes.
fn log_tail(path: &Path, from: u64) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(LOG_TAIL).max(from);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_sits_next_to_the_history_file() {
        assert_eq!(
            default_log(Path::new("/s/mysh/history"), "serve"),
            PathBuf::from("/s/mysh/serve.log")
        );
        assert_eq!(
            default_log(Path::new("history"), "accept"),
            PathBuf::from("./accept.log")
        );
    }

    #[test]
    fn pid_file_is_written_and_removed() {
        let dir = std::env::temp_dir().join(format!("mysh-daemon-test-{}", std::process::id()));
        let path = dir.join("run").join("mysh.pid");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        let args = DaemonArgs {
            pid_file: Some(path.clone()),
            ..DaemonArgs::default()
        };
        let guard = ready(&args).expect("ready");
        assert_eq!(
            std::fs::read_to_string(&path).expect("pid").trim(),
            std::process::id().to_string()
        );
        drop(guard);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
