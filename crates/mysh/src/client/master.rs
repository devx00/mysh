//! Master mode (docs/05-meta-shell.md, "Master mode"): `mysh -M HOST` /
//! `mysh master HOST` holds one connection open and serves the control
//! socket for other `mysh` calls, like ssh's `ControlMaster`. It has no
//! prompt and never reads stdin, logs to stderr, removes its socket when it
//! leaves, and exits after `--idle` without a client, on `SIGTERM`, or when
//! the connection drops.
//!
//! `--daemon` re-spawns the same binary in its own process group with
//! `Stdio::null()` and waits for the socket to appear; `master = "auto"` in
//! the config does the same for a socket-less CLI call.

use std::{
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use mysh_proto::limits::MASTER_IDLE;
use tokio::{
    net::UnixStream,
    signal::unix::{SignalKind, signal},
};
use tracing::{debug, info};

use super::{conn::Connection, console::Console, ctl, forward::Forwards, shared::Shared};
use crate::{
    cli::MasterArgs,
    config::{Paths, Target},
};

/// Longest wait for a freshly spawned master's socket.
const SPAWN_WAIT: Duration = Duration::from_secs(3);
/// Poll interval while waiting for it.
const SPAWN_POLL: Duration = Duration::from_millis(25);
/// Upper bound on the idle check interval.
const IDLE_TICK_MAX: Duration = Duration::from_millis(500);

/// Serve the control socket until the idle timer, a signal, or the
/// connection ends. Returns the process exit code.
pub async fn serve(
    conn: &Connection,
    console: &Console,
    target: &Target,
    paths: &Paths,
    forwards: Forwards,
    args: &MasterArgs,
) -> Result<i32> {
    let idle = args.idle.unwrap_or(MASTER_IDLE);
    let shared = Shared::new(conn.clone(), console.clone(), forwards, super::home_dir());
    let Some(ctl) = ctl::CtlServer::start(paths, target, Arc::clone(&shared)).await else {
        bail!(
            "another client already serves {}",
            ctl::socket_path(paths, target).display()
        );
    };
    info!(
        target = %target.display,
        socket = %ctl.path().display(),
        idle_secs = idle.as_secs(),
        "master listening"
    );
    console.notice(&format!(
        "master for {} on {} (idle {}s)",
        target.display,
        ctl.path().display(),
        idle.as_secs()
    ));
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("SIGINT handler")?;
    let tick = (idle / 4).clamp(Duration::from_millis(20), IDLE_TICK_MAX);
    let reason = loop {
        tokio::select! {
            _ = sigterm.recv() => break "signal",
            _ = sigint.recv() => break "interrupt",
            () = conn.closed() => break "connection closed",
            () = tokio::time::sleep(tick) => {
                if ctl.idle_for().is_some_and(|quiet| quiet >= idle) {
                    break "idle";
                }
            }
        }
    };
    info!(target = %target.display, reason, "master exiting");
    console.notice(&format!("master exiting ({reason})"));
    // Removes the socket.
    drop(ctl);
    Ok(0)
}

/// Start a detached master for `target` and wait for its socket. `Ok(true)`
/// when a usable socket is there afterwards (an already running master
/// counts).
pub async fn ensure(paths: &Paths, target: &Target, idle: Option<Duration>) -> Result<bool> {
    let path = ctl::socket_path(paths, target);
    if UnixStream::connect(&path).await.is_ok() {
        return Ok(true);
    }
    spawn_detached(target, idle)?;
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

/// Re-spawn this binary as `mysh master …` in its own process group with
/// no standard streams, so it outlives the caller's terminal.
fn spawn_detached(target: &Target, idle: Option<Duration>) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let exe = std::env::current_exe().context("locating the mysh binary")?;
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

/// The arguments that reproduce `target`'s connection for a fresh master;
/// resolved values, so a config alias does not have to be re-read.
fn master_argv(target: &Target, idle: Option<Duration>) -> Vec<String> {
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

/// `~` for the master's own file commands.
#[must_use]
pub fn home() -> PathBuf {
    super::home_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cli::ConnectOpts, config::resolve_target};

    fn target(host: &str) -> Target {
        resolve_target(
            host,
            &ConnectOpts {
                accept_new: true,
                ..ConnectOpts::default()
            },
            &crate::config::Config::default(),
        )
        .expect("resolve")
    }

    #[test]
    fn argv_reproduces_the_connection() {
        let mut t = target("127.0.0.1:7100");
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
