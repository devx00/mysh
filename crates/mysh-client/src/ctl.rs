//! Control socket, requester side (docs/05-meta-shell.md "Control
//! socket"): an interactive client or master listens on a unix socket so
//! `mysh put HOST …` from another terminal reuses its connection instead of
//! opening a new one.
//!
//! Protocol, one request per connection: the requester writes one
//! `Msg<CtlRequest>`; the serving client answers with a stream of
//! `Msg<CtlEvent>` (the capture-console events of the command) ending in
//! `Done { code }`. Both sides use `mysh_proto::frame` framing. The serving
//! side lives in the `mysh` binary.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use mysh_net::framing::{read_msg, write_msg};
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tracing::debug;

use crate::{
    config::{Paths, Target},
    report::Reporter,
    types::Mode,
};

/// Largest stdin a CLI call may hand to the serving client; a bigger input
/// is streamed over a connection of the requester's own instead.
pub const CTL_STDIN_MAX: usize = 64 * 1024;

/// Longest wait for a freshly spawned master's socket.
const SPAWN_WAIT: Duration = Duration::from_secs(3);
/// Poll interval while waiting for it.
const SPAWN_POLL: Duration = Duration::from_millis(25);

/// What a CLI subcommand asks the interactive client to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtlRequest {
    /// Prompt words, e.g. `["put", "-r", "--", "a", "dest"]`.
    pub argv: Vec<String>,
    /// The requester's working directory for local paths.
    pub cwd: String,
    /// The requester's output mode; the command renders in it.
    #[serde(default)]
    pub mode: Mode,
    /// Standard input for `exec`/`CMD` and `session send --stdin`.
    #[serde(default)]
    pub stdin: Vec<u8>,
}

/// One event of the reply stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtlEvent {
    /// Bytes for the requester's stdout, already rendered in its mode.
    Out(Vec<u8>),
    /// Bytes for the requester's stderr.
    Err(Vec<u8>),
    /// One update of a progress line.
    Progress {
        /// What is being transferred.
        label: String,
        /// Bytes done so far.
        done: u64,
        /// Total bytes when known.
        total: Option<u64>,
    },
    /// Last event; `code` is the exit status for the requester.
    Done {
        /// The command's exit status.
        code: i32,
    },
}

/// `runtime_dir/<host>_<port>.sock` with every byte outside
/// `[A-Za-z0-9.-]` of the host replaced by `_`.
pub fn socket_path(paths: &Paths, target: &Target) -> PathBuf {
    let host: String = target
        .host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    paths
        .runtime_dir
        .join(format!("{host}_{}.sock", target.port))
}

/// Whether a client or master is serving `target`'s control socket.
pub async fn socket_ready(paths: &Paths, target: &Target) -> bool {
    UnixStream::connect(socket_path(paths, target))
        .await
        .is_ok()
}

/// Run `argv` through the interactive client serving `target`, relaying
/// its output to `reporter`. `Ok(None)` when there is no usable socket (the
/// caller opens its own connection); `Err` only for a failure after the
/// request was accepted.
pub async fn request(
    paths: &Paths,
    target: &Target,
    argv: Vec<String>,
    reporter: &dyn Reporter,
    stdin: Vec<u8>,
) -> Result<Option<i32>> {
    let path = socket_path(paths, target);
    let mut stream = match UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(e) => {
            debug!(path = %path.display(), error = %e, "no control socket");
            return Ok(None);
        }
    };
    let cwd = std::env::current_dir()
        .map_or_else(|_| ".".to_owned(), |p| p.to_string_lossy().into_owned());
    write_msg(
        &mut stream,
        &CtlRequest {
            argv,
            cwd,
            mode: reporter.mode(),
            stdin,
        },
    )
    .await
    .context("sending control request")?;
    debug!(path = %path.display(), "control request sent");
    let mut progress_active = false;
    loop {
        let ev: CtlEvent = read_msg(&mut stream)
            .await
            .context("reading control reply")?;
        match ev {
            CtlEvent::Out(b) => {
                if progress_active {
                    reporter.progress_done();
                    progress_active = false;
                }
                reporter.write_raw(&b);
            }
            CtlEvent::Err(b) => {
                if progress_active {
                    reporter.progress_done();
                    progress_active = false;
                }
                reporter.write_raw_err(&b);
            }
            CtlEvent::Progress { label, done, total } => {
                reporter.progress(&label, done, total);
                progress_active = true;
            }
            CtlEvent::Done { code } => {
                if progress_active {
                    reporter.progress_done();
                }
                reporter.flush().await;
                return Ok(Some(code));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Starting a master (docs/05-meta-shell.md, "Master mode")

/// Start a detached master for `target` with the `mysh` binary at `exe`
/// and wait for its socket. `Ok(true)` when a usable socket is there
/// afterwards (an already running master counts).
pub async fn ensure(
    paths: &Paths,
    target: &Target,
    idle: Option<Duration>,
    exe: &Path,
) -> Result<bool> {
    let path = socket_path(paths, target);
    if UnixStream::connect(&path).await.is_ok() {
        return Ok(true);
    }
    spawn_detached(target, idle, exe)?;
    let deadline = Instant::now() + SPAWN_WAIT;
    while Instant::now() < deadline {
        if UnixStream::connect(&path).await.is_ok() {
            debug!(socket = %path.display(), "master is up");
            return Ok(true);
        }
        tokio::time::sleep(SPAWN_POLL).await;
    }
    Ok(false)
}

/// Spawn `exe master …` in its own process group with no standard
/// streams, so it outlives the caller's terminal.
pub fn spawn_detached(target: &Target, idle: Option<Duration>, exe: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("master");
    for arg in master_argv(target, idle) {
        cmd.arg(arg);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Detach from the caller's process group: a Ctrl-C there must not
        // reach the master. `process_group` is the safe std API for it.
        .process_group(0);
    let child = cmd.spawn().context("starting the master")?;
    debug!(pid = child.id(), host = %target.host, "master spawned");
    Ok(())
}

/// The arguments after `master` that reproduce `target`'s connection for
/// a fresh master; resolved values, so a config alias does not have to be
/// re-read.
#[must_use]
pub fn master_argv(target: &Target, idle: Option<Duration>) -> Vec<String> {
    let mut argv = vec!["--port".to_owned(), target.port.to_string()];
    if let Some(idle) = idle {
        argv.push("--idle".to_owned());
        argv.push(format!("{}ms", idle.as_millis()));
    }
    if let Some(identity) = &target.identity {
        argv.push("--identity".to_owned());
        argv.push(identity.to_string_lossy().into_owned());
    }
    if let Some(pin) = &target.pin {
        argv.push("--pin".to_owned());
        argv.push(pin.clone());
    }
    if target.accept_new {
        argv.push("--accept-new".to_owned());
    }
    if target.strict {
        argv.push("--strict".to_owned());
    }
    if target.baked_only {
        argv.push("--baked-only".to_owned());
    }
    for (name, value) in &target.env {
        argv.push("--env".to_owned());
        argv.push(match value {
            Some(v) => format!("{name}={v}"),
            None => name.clone(),
        });
    }
    argv.push("--plain".to_owned());
    argv.push(target.host.clone());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        args::ConnectOpts,
        config::{Config, resolve_target},
        report::NullReporter,
    };

    #[test]
    fn socket_path_is_sanitised() {
        let paths = Paths {
            runtime_dir: PathBuf::from("/run/mysh"),
            ..Paths::with_config_dir(PathBuf::from("/cfg"))
        };
        let t = resolve_target(
            "[fe80::1]:7000",
            &ConnectOpts::default(),
            &Config::default(),
        )
        .expect("target");
        assert_eq!(
            socket_path(&paths, &t),
            PathBuf::from("/run/mysh/fe80__1_7000.sock")
        );
        let t =
            resolve_target("pi.lan", &ConnectOpts::default(), &Config::default()).expect("target");
        assert_eq!(
            socket_path(&paths, &t),
            PathBuf::from("/run/mysh/pi.lan_7722.sock")
        );
    }

    #[tokio::test]
    async fn request_without_socket_falls_back() {
        let dir = std::env::temp_dir().join(format!("mysh-ctl-unit-{}", std::process::id()));
        let paths = Paths {
            runtime_dir: dir.clone(),
            ..Paths::with_config_dir(dir.join("cfg"))
        };
        let t = resolve_target("127.0.0.1:1", &ConnectOpts::default(), &Config::default())
            .expect("target");
        let r = request(&paths, &t, vec!["ping".into()], &NullReporter, Vec::new())
            .await
            .expect("no socket is not an error");
        assert_eq!(r, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn argv_reproduces_the_connection() {
        let mut t = resolve_target(
            "127.0.0.1:7100",
            &ConnectOpts {
                accept_new: true,
                ..ConnectOpts::default()
            },
            &Config::default(),
        )
        .expect("resolve");
        t.pin = Some("SHA256:abc".to_owned());
        t.env = vec![
            ("LANG".to_owned(), Some("C".to_owned())),
            ("EDITOR".to_owned(), None),
        ];
        let argv = master_argv(&t, Some(Duration::from_millis(1500)));
        assert_eq!(argv.first().map(String::as_str), Some("--port"));
        assert!(argv.contains(&"7100".to_owned()), "{argv:?}");
        assert!(argv.contains(&"--idle".to_owned()));
        assert!(argv.contains(&"1500ms".to_owned()), "{argv:?}");
        assert!(argv.contains(&"--accept-new".to_owned()));
        assert!(argv.contains(&"SHA256:abc".to_owned()));
        assert!(argv.contains(&"LANG=C".to_owned()), "{argv:?}");
        assert!(argv.contains(&"EDITOR".to_owned()), "{argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("127.0.0.1"));
    }
}
