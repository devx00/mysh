//! Control socket (docs/05-meta-shell.md "Control socket"): an interactive
//! client listens on a unix socket so `mysh put HOST …` from another
//! terminal reuses its connection instead of opening a new one.
//!
//! Protocol, one request per connection: the client writes one
//! `Msg<CtlRequest>`; the serving client answers with a stream of
//! `Msg<CtlEvent>` (the capture-console events of the command) ending in
//! `Done { code }`. Both sides use `mysh_proto::frame` framing.

use std::{
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use anyhow::{Context as _, Result};
use mysh_net::framing::{read_msg, write_msg};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt as _,
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use tracing::{debug, warn};

use super::{
    console::{CaptureEvent, Console},
    meta::{Ctx, Flow, exec_command, execute},
    session_api,
    shared::Shared,
};
use crate::{
    cli::{MetaCommand, parse_meta_argv},
    config::{Paths, Target},
    output::Mode,
};

/// Largest stdin a CLI call may hand to the serving client; a bigger input
/// is streamed over a connection of the requester's own instead.
pub const CTL_STDIN_MAX: usize = 64 * 1024;

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
    Out(Vec<u8>),
    Err(Vec<u8>),
    Progress {
        label: String,
        done: u64,
        total: Option<u64>,
    },
    /// Last event; `code` is the exit status for the requester.
    Done {
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

/// Why a command is refused over the socket, if it is.
pub fn refusal(cmd: &MetaCommand) -> Option<&'static str> {
    match cmd {
        MetaCommand::Shell(_)
        | MetaCommand::Fg { .. }
        | MetaCommand::Send { .. }
        | MetaCommand::Resize
        | MetaCommand::Log { .. }
        | MetaCommand::Exit
        | MetaCommand::Disconnect
        | MetaCommand::Attach { .. }
        | MetaCommand::Detach { .. } => Some("needs the interactive client's terminal"),
        MetaCommand::Lcd { .. } => Some("the request carries its own working directory"),
        MetaCommand::Help { .. }
        | MetaCommand::Sessions { .. }
        | MetaCommand::Kill { .. }
        | MetaCommand::Put(_)
        | MetaCommand::Get(_)
        | MetaCommand::Ls(_)
        | MetaCommand::Cwd
        | MetaCommand::Forward(_)
        | MetaCommand::Exec { .. }
        | MetaCommand::Info
        | MetaCommand::Ping { .. }
        | MetaCommand::Authorize(_)
        | MetaCommand::Jobs { .. }
        | MetaCommand::Session(_)
        | MetaCommand::Stat { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Serving side (the interactive client)

/// Request traffic on the socket, for the master's idle timer
/// (docs/05-meta-shell.md, "Master mode").
#[derive(Debug)]
struct Activity {
    /// Requests being served right now.
    running: AtomicUsize,
    /// When the last request finished (or the socket opened).
    last: Mutex<Instant>,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            running: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
        })
    }

    fn started(&self) {
        self.running.fetch_add(1, Ordering::SeqCst);
    }

    fn finished(&self) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
        self.running.fetch_sub(1, Ordering::SeqCst);
    }

    /// How long the socket has been quiet; `None` while a request runs.
    fn idle_for(&self) -> Option<std::time::Duration> {
        if self.running.load(Ordering::SeqCst) > 0 {
            return None;
        }
        let last = *self.last.lock().unwrap_or_else(PoisonError::into_inner);
        Some(last.elapsed())
    }
}

/// A listening control socket; removed on drop.
#[derive(Debug)]
pub struct CtlServer {
    path: PathBuf,
    accept: JoinHandle<()>,
    activity: Arc<Activity>,
}

impl CtlServer {
    /// Bind `socket_path(paths, target)` and serve requests on `shared`.
    /// `Ok(None)` when another client already serves this target or the
    /// socket cannot be created (reported as a notice; the prompt works
    /// without it).
    pub async fn start(paths: &Paths, target: &Target, shared: Arc<Shared>) -> Option<Self> {
        let path = socket_path(paths, target);
        let console = shared.console.clone();
        match bind(&path).await {
            Ok(Some(listener)) => {
                let activity = Activity::new();
                let accept = tokio::spawn(accept_loop(listener, shared, Arc::clone(&activity)));
                debug!(path = %path.display(), "control socket listening");
                Some(Self {
                    path,
                    accept,
                    activity,
                })
            }
            Ok(None) => {
                console.notice(&format!(
                    "control socket {} is served by another client; CLI commands will not reuse this connection",
                    path.display()
                ));
                None
            }
            Err(e) => {
                console.notice(&format!("control socket unavailable: {e:#}"));
                None
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How long no request has been served; `None` while one runs.
    #[must_use]
    pub fn idle_for(&self) -> Option<std::time::Duration> {
        self.activity.idle_for()
    }
}

impl Drop for CtlServer {
    fn drop(&mut self) {
        self.accept.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Create the runtime dir (0700) and bind the socket (0600). A socket file
/// that still accepts connections belongs to another client (`Ok(None)`);
/// a stale one is removed.
async fn bind(path: &Path) -> Result<Option<UnixListener>> {
    let dir = path
        .parent()
        .context("control socket path has no parent directory")?;
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating {}", dir.display()))?;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .await
        .with_context(|| format!("setting mode on {}", dir.display()))?;
    if tokio::fs::symlink_metadata(path).await.is_ok() {
        if UnixStream::connect(path).await.is_ok() {
            return Ok(None);
        }
        debug!(path = %path.display(), "removing stale control socket");
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("removing stale {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("setting mode on {}", path.display()))?;
    Ok(Some(listener))
}

async fn accept_loop(listener: UnixListener, shared: Arc<Shared>, activity: Arc<Activity>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                activity.started();
                tokio::spawn(handle(
                    stream,
                    Arc::clone(&shared),
                    ActivityGuard(Arc::clone(&activity)),
                ));
            }
            Err(e) => {
                warn!(error = %e, "control socket accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Counts one in-flight request for the idle timer.
#[derive(Debug)]
struct ActivityGuard(Arc<Activity>);

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.0.finished();
    }
}

/// Run one request's command on a detached context. `exec` and `session`
/// carry an exit code of their own; everything else succeeds or fails.
async fn run_command(ctx: &mut Ctx, cmd: MetaCommand, stdin: Vec<u8>) -> Result<i32> {
    match cmd {
        MetaCommand::Exec {
            timeout,
            cwd,
            command,
        } => {
            let limit = timeout.or(ctx.shared.conn.target().timeout);
            exec_command(ctx, command, cwd, limit, Some(&stdin), None).await
        }
        MetaCommand::Session(args) => {
            let conn = ctx.shared.conn.clone();
            let console = ctx.console.clone();
            session_api::run(&conn, &console, &args, Some(&stdin)).await
        }
        other => match execute(ctx, other, None).await? {
            Flow::Continue => Ok(0),
            flow => anyhow::bail!("unexpected outcome {flow:?}"),
        },
    }
}

/// Serve one request: parse, check the allow-list, run it on a detached
/// context with a capture console in the requester's output mode, and
/// relay the events.
async fn handle(mut stream: UnixStream, shared: Arc<Shared>, _busy: ActivityGuard) {
    let req: CtlRequest = match read_msg(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "control request not read");
            return;
        }
    };
    let line = req.argv.join(" ");
    let (cmd, background) = match parse_meta_argv(req.argv) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            let _ = reply_error(&mut stream, "empty request").await;
            return;
        }
        Err(msg) => {
            let _ = reply_error(&mut stream, msg.trim_end()).await;
            return;
        }
    };
    if background {
        let _ = reply_error(&mut stream, "`&` is not accepted over the control socket").await;
        return;
    }
    if let Some(why) = refusal(&cmd) {
        let _ = reply_error(
            &mut stream,
            &format!("{line}: not available over the control socket ({why})"),
        )
        .await;
        return;
    }
    shared.console.notice(&format!("ctl: {line}"));
    let (console, mut rx) = Console::capture_with_mode(req.mode);
    let mut ctx = Ctx::detached(&shared, console, PathBuf::from(req.cwd));
    let stdin = req.stdin;
    let mut run = tokio::spawn(async move {
        let result = run_command(&mut ctx, cmd, stdin).await;
        drop(ctx);
        result
    });
    // Session reader tasks keep console clones briefly after the command
    // returns, so the task's end (not the channel's) ends the relay; events
    // still queued at that point are flushed first.
    let joined = loop {
        let ev = tokio::select! {
            ev = rx.recv() => ev,
            joined = &mut run => {
                while let Some(ev) = rx.try_recv() {
                    if relay(&mut stream, ev).await.is_err() {
                        return;
                    }
                }
                break joined;
            }
        };
        match ev {
            Some(CaptureEvent::Done) | None => break run.await,
            Some(ev) => {
                if relay(&mut stream, ev).await.is_err() {
                    debug!("control requester went away; cancelling {line}");
                    run.abort();
                    return;
                }
            }
        }
    };
    let code = match joined {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            let _ = write_msg(
                &mut stream,
                &CtlEvent::Err(format!("error: {e:#}\n").into_bytes()),
            )
            .await;
            1
        }
        Err(e) => {
            let _ = write_msg(
                &mut stream,
                &CtlEvent::Err(format!("error: command task failed: {e}\n").into_bytes()),
            )
            .await;
            1
        }
    };
    let _ = write_msg(&mut stream, &CtlEvent::Done { code }).await;
}

/// Forward one capture event to the requester.
async fn relay(stream: &mut UnixStream, ev: CaptureEvent) -> std::io::Result<()> {
    let ev = match ev {
        CaptureEvent::Out(b) => CtlEvent::Out(b),
        CaptureEvent::Err(b) => CtlEvent::Err(b),
        CaptureEvent::Progress { label, done, total } => CtlEvent::Progress { label, done, total },
        CaptureEvent::Done => return Ok(()),
    };
    write_msg(stream, &ev).await
}

async fn reply_error(stream: &mut UnixStream, msg: &str) -> std::io::Result<()> {
    write_msg(
        stream,
        &CtlEvent::Err(format!("error: {msg}\n").into_bytes()),
    )
    .await?;
    write_msg(stream, &CtlEvent::Done { code: 1 }).await
}

// ---------------------------------------------------------------------------
// Requesting side (CLI subcommands)

/// Standard input for a control request: at most [`CTL_STDIN_MAX`] bytes
/// read from this process's stdin. `None` means "too much to carry", and
/// the caller should open its own connection instead.
pub async fn read_ctl_stdin() -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut reader = tokio::io::stdin().take(CTL_STDIN_MAX as u64 + 1);
    if reader.read_to_end(&mut buf).await.is_err() {
        return Some(Vec::new());
    }
    (buf.len() <= CTL_STDIN_MAX).then_some(buf)
}

/// Whether a client or master is serving `target`'s control socket.
pub async fn socket_ready(paths: &Paths, target: &Target) -> bool {
    UnixStream::connect(socket_path(paths, target))
        .await
        .is_ok()
}

/// Run `argv` through the interactive client serving `target`, relaying
/// its output to `console`. `Ok(None)` when there is no usable socket (the
/// caller opens its own connection); `Err` only for a failure after the
/// request was accepted.
pub async fn request(
    paths: &Paths,
    target: &Target,
    argv: Vec<String>,
    console: &Console,
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
            mode: console.mode(),
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
                    console.progress_done();
                    progress_active = false;
                }
                console.write_raw(&b);
            }
            CtlEvent::Err(b) => {
                if progress_active {
                    console.progress_done();
                    progress_active = false;
                }
                console.write_raw_err(&b);
            }
            CtlEvent::Progress { label, done, total } => {
                console.progress(&label, done, total);
                progress_active = true;
            }
            CtlEvent::Done { code } => {
                if progress_active {
                    console.progress_done();
                }
                console.flush().await;
                return Ok(Some(code));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::ConnectOpts,
        config::{Config, resolve_target},
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

    #[test]
    fn refusals() {
        let parse = |s: &str| {
            parse_meta_argv(s.split(' ').map(str::to_owned).collect())
                .expect("parse")
                .expect("cmd")
                .0
        };
        for allowed in [
            "put a",
            "get a",
            "ls",
            "cwd",
            "forward ls",
            "exec true",
            "info",
            "ping",
            "sessions",
            "kill 1",
            "jobs",
            "authorize",
            "help",
        ] {
            assert!(refusal(&parse(allowed)).is_none(), "{allowed}");
        }
        for refused in [
            "shell",
            "fg",
            "send x",
            "resize",
            "log off",
            "exit",
            "disconnect",
            "attach",
            "detach",
            "lcd",
        ] {
            assert!(refusal(&parse(refused)).is_some(), "{refused}");
        }
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
        let console = Console::new();
        let r = request(&paths, &t, vec!["ping".into()], &console, Vec::new())
            .await
            .expect("no socket is not an error");
        assert_eq!(r, None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
