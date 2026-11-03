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

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail};
use mysh_proto::limits::MASTER_IDLE;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

use super::{conn::Connection, console::Console, ctl, forward::Forwards, shared::Shared};
use crate::{
    cli::MasterArgs,
    config::{Paths, Target},
};

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

/// Start a detached master (this binary) for `target` and wait for its
/// socket. `Ok(true)` when a usable socket is there afterwards (an already
/// running master counts).
pub async fn ensure(paths: &Paths, target: &Target, idle: Option<Duration>) -> Result<bool> {
    let exe = std::env::current_exe().context("locating the mysh binary")?;
    mysh_client::ctl::ensure(paths, target, idle, &exe).await
}

/// `~` for the master's own file commands.
#[must_use]
pub fn home() -> PathBuf {
    super::home_dir()
}
