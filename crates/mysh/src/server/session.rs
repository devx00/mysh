//! Session streams (docs/03-protocol.md §7, docs/04-sessions.md): PTY and
//! exec sessions, the per-connection session table, and the cwd probe
//! (docs/03-protocol.md §10).
//!
//! Each session stream is split: a reader task turns incoming `SessionIn`
//! frames into a channel (so the pump loop can `select!` without cancelling
//! a half-read frame), and the pump owns the write half.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    io,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use mysh_net::{
    framing::{read_msg, write_msg, write_reply},
    mux::Stream,
};
use mysh_proto::{
    SESSION_CHUNK,
    limits::MAX_SESSIONS,
    open::{ErrorCode, OpenReply},
    session::{ExitStatus, PtyRequest, SessionIn, SessionKind, SessionOut, SessionRequest},
};
use mysh_pty::{
    process::{exit_status, kill, login_shell, process_cwd},
    pty::{AsyncPtyMaster, open_pty},
    spawn::{Command, Spawned, spawn_piped, spawn_with_pty},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, WriteHalf},
    process::ChildStdin,
    sync::mpsc,
    task::JoinHandle,
    time::Instant,
};
use tracing::{debug, info, warn};

use super::{ConnCtx, Policy, files, resolve_remote_path};
use crate::cli::Feature;

/// After the child is reaped, keep draining the pty for at most this long
/// (docs/04-sessions.md, "Exit").
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(2);

/// Client environment accepted without `--accept-env`; `LC_*` is accepted
/// by prefix as well (docs/02-security.md).
const DEFAULT_ACCEPT_ENV: [&str; 3] = ["TERM", "LANG", "COLORTERM"];

/// Exit status reported when `wait` itself fails.
const WAIT_FAILED: ExitStatus = ExitStatus::Code(255);

/// A live session, as seen by the cwd probe.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub pid: u32,
    /// `None` for exec sessions.
    pub master: Option<Arc<AsyncPtyMaster>>,
}

#[derive(Debug, Default)]
struct Table {
    /// Last id handed out; ids start at 1 and are never reused.
    last_id: u32,
    /// Reserved (`None`) and started (`Some`) sessions; `len()` is the
    /// quota count.
    live: HashMap<u32, Option<SessionHandle>>,
}

/// Per-connection session table (shared through [`ConnCtx`]).
#[derive(Debug, Clone, Default)]
pub struct Sessions(Arc<Mutex<Table>>);

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve a session id (it counts towards `MAX_SESSIONS` at once);
    /// `None` when the quota is reached.
    pub fn reserve(&self) -> Option<u32> {
        let mut table = self.table();
        if table.live.len() >= MAX_SESSIONS {
            return None;
        }
        table.last_id += 1;
        let id = table.last_id;
        table.live.insert(id, None);
        Some(id)
    }

    /// Attach the started process to a reserved id.
    pub fn set(&self, id: u32, handle: SessionHandle) {
        if let Some(slot) = self.table().live.get_mut(&id) {
            *slot = Some(handle);
        }
    }

    pub fn remove(&self, id: u32) {
        self.table().live.remove(&id);
    }

    /// The started session `id`, if any.
    pub fn get(&self, id: u32) -> Option<SessionHandle> {
        self.table().live.get(&id).cloned().flatten()
    }

    /// Reserved plus started sessions.
    pub fn len(&self) -> usize {
        self.table().live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Request → command

/// Program and argv for a session (docs/04-sessions.md, "Spawn").
#[derive(Debug, Clone, PartialEq, Eq)]
struct Program {
    program: PathBuf,
    argv: Vec<OsString>,
}

fn basename(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.to_string_lossy(), |n| n.to_string_lossy())
        .into_owned()
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `which`-style lookup over `path`; names containing `/` are used as-is.
fn lookup_in_path(name: &str, path: &str) -> Option<PathBuf> {
    if name.contains('/') {
        return Some(PathBuf::from(name));
    }
    path.split(':')
        .map(|dir| if dir.is_empty() { "." } else { dir })
        .map(|dir| Path::new(dir).join(name))
        .find(|candidate| is_executable_file(candidate))
}

/// `Shell` → login shell (`-<basename>` as argv0); `Exec` with one element →
/// `shell -c <script>`; longer `Exec` → `argv[0]` found on `path`, argv as
/// given.
fn program_for(
    kind: &SessionKind,
    shell: &Path,
    path: &str,
) -> Result<Program, (ErrorCode, String)> {
    match kind {
        SessionKind::Shell => Ok(Program {
            program: shell.to_path_buf(),
            argv: vec![OsString::from(format!("-{}", basename(shell)))],
        }),
        SessionKind::Exec { argv } => match argv.as_slice() {
            [] => Err((ErrorCode::Protocol, "exec with empty argv".to_owned())),
            [script] => Ok(Program {
                program: shell.to_path_buf(),
                argv: vec![basename(shell).into(), "-c".into(), script.into()],
            }),
            [name, ..] => {
                let program = lookup_in_path(name, path)
                    .ok_or_else(|| (ErrorCode::NotFound, format!("{name}: command not found")))?;
                Ok(Program {
                    program,
                    argv: argv.iter().map(OsString::from).collect(),
                })
            }
        },
    }
}

/// `command="…"` from the key's options (docs/02-security.md, "Per-key
/// options"): `shell -c <forced>` regardless of what was requested.
fn forced_program(shell: &Path, forced: &str) -> Program {
    Program {
        program: shell.to_path_buf(),
        argv: vec![basename(shell).into(), "-c".into(), forced.into()],
    }
}

/// `MYSH_ORIGINAL_COMMAND` for a forced command: the requested argv joined
/// by spaces, empty for a `Shell` request.
fn original_command(kind: &SessionKind) -> String {
    match kind {
        SessionKind::Shell => String::new(),
        SessionKind::Exec { argv } => argv.join(" "),
    }
}

/// Whether a client-supplied variable passes the allow-list: the built-in
/// names, any `LC_*`, or a `--accept-env` entry (exact, or by prefix when
/// the entry ends in `*`).
fn env_allowed(name: &str, accept_env: &[String]) -> bool {
    DEFAULT_ACCEPT_ENV.contains(&name)
        || name.starts_with("LC_")
        || accept_env
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => pattern == name,
            })
}

fn valid_env(name: &str, value: &str) -> bool {
    !name.is_empty() && !name.contains(['=', '\0']) && !value.contains('\0')
}

/// Child environment: allow-listed client variables, then the base set
/// (`HOME`, `USER`, `LOGNAME`, `PATH`, `SHELL`, which a client may only
/// override when `--accept-env` names them), then `TERM` from the pty
/// request and the always-authoritative `MYSH_*` variables
/// (`MYSH_ORIGINAL_COMMAND` only under a forced command).
fn build_env(
    policy: &Policy,
    shell: &Path,
    connection: &str,
    session: u32,
    client_env: &[(String, String)],
    term: Option<&str>,
    original_command: Option<&str>,
) -> Vec<(OsString, OsString)> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in client_env {
        if valid_env(name, value) && env_allowed(name, &policy.accept_env) {
            env.insert(name.clone(), value.clone());
        }
    }
    let base = [
        ("HOME", policy.home.to_string_lossy().into_owned()),
        ("USER", policy.user.clone()),
        ("LOGNAME", policy.user.clone()),
        ("PATH", policy.path.clone()),
        ("SHELL", shell.to_string_lossy().into_owned()),
    ];
    for (name, value) in base {
        env.entry(name.to_owned()).or_insert(value);
    }
    if let Some(term) = term {
        env.insert("TERM".to_owned(), term.to_owned());
    }
    env.insert("MYSH_CONNECTION".to_owned(), connection.to_owned());
    env.insert("MYSH_SESSION".to_owned(), session.to_string());
    match original_command {
        Some(original) => {
            env.insert("MYSH_ORIGINAL_COMMAND".to_owned(), original.to_owned());
        }
        None => {
            env.remove("MYSH_ORIGINAL_COMMAND");
        }
    }
    env.into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
}

/// Start directory and whether it fell back to home.
fn session_cwd(requested: Option<&str>, home: &Path) -> (PathBuf, bool) {
    if let Some(requested) = requested {
        let dir = resolve_remote_path(requested, None, home);
        if dir.is_dir() {
            return (dir, false);
        }
        return (home.to_path_buf(), true);
    }
    (home.to_path_buf(), false)
}

fn check_policy(policy: &Policy, req: &SessionRequest) -> Result<(), (ErrorCode, String)> {
    if req.pty.is_some() && policy.denies(Feature::Pty) {
        return Err((ErrorCode::Denied, "pty sessions are disabled".to_owned()));
    }
    if matches!(req.kind, SessionKind::Exec { .. }) && policy.denies(Feature::Exec) {
        return Err((ErrorCode::Denied, "exec sessions are disabled".to_owned()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream plumbing

/// Write half plus the reader task feeding `SessionIn` frames.
struct SessionIo {
    wr: WriteHalf<Stream>,
    inputs: mpsc::Receiver<SessionIn>,
    reader: JoinHandle<()>,
}

impl SessionIo {
    fn new(stream: Stream) -> Self {
        let (mut rd, wr) = tokio::io::split(stream);
        let (tx, inputs) = mpsc::channel(4);
        let reader = tokio::spawn(async move {
            loop {
                match read_msg::<_, SessionIn>(&mut rd).await {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() != io::ErrorKind::UnexpectedEof {
                            debug!(error = %e, "session stream read ended");
                        }
                        break;
                    }
                }
            }
        });
        Self { wr, inputs, reader }
    }

    async fn send(&mut self, msg: &SessionOut) -> io::Result<()> {
        write_msg(&mut self.wr, msg).await
    }

    /// `Exited` is the last message; then half-close.
    async fn finish(mut self, status: ExitStatus) {
        let _ = self.send(&SessionOut::Exited(status)).await;
        let _ = self.wr.shutdown().await;
        self.reader.abort();
    }
}

impl Drop for SessionIo {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

fn spawn_error(err: &io::Error) -> (ErrorCode, String) {
    (files::error_code(err), err.to_string())
}

// ---------------------------------------------------------------------------
// Handlers

/// Serve one `Open::Session` stream: reply (`Denied` when the policy forbids
/// it, `Limit` at `MAX_SESSIONS`, `NotFound`/`Io` when the spawn fails),
/// then `Started`, output, and `Exited` per docs/04-sessions.md.
#[allow(clippy::needless_pass_by_value)] // handler signature per the dispatch contract
pub async fn handle_session(mut stream: Stream, req: SessionRequest, ctx: ConnCtx) {
    if let Err((code, message)) = check_policy(&ctx.policy, &req) {
        files::send_error(&mut stream, code, &message).await;
        return;
    }
    let Some(id) = ctx.sessions.reserve() else {
        files::send_error(
            &mut stream,
            ErrorCode::Limit,
            &format!("at most {MAX_SESSIONS} sessions per connection"),
        )
        .await;
        return;
    };
    run_session(stream, &req, &ctx, id).await;
    ctx.sessions.remove(id);
}

async fn run_session(mut stream: Stream, req: &SessionRequest, ctx: &ConnCtx, id: u32) {
    let policy = &*ctx.policy;
    let shell = login_shell(policy.shell.as_deref());
    let program = match &policy.forced_command {
        Some(forced) => forced_program(&shell, forced),
        None => match program_for(&req.kind, &shell, &policy.path) {
            Ok(program) => program,
            Err((code, message)) => {
                files::send_error(&mut stream, code, &message).await;
                return;
            }
        },
    };
    let original = policy
        .forced_command
        .as_ref()
        .map(|_| original_command(&req.kind));
    let (cwd, cwd_fallback) = session_cwd(req.cwd.as_deref(), &policy.home);
    let term = req.pty.as_ref().map(|p| p.term.as_str());
    let env = build_env(
        policy,
        &shell,
        &ctx.connection_env(),
        id,
        &req.env,
        term,
        original.as_deref(),
    );
    let cmd = Command {
        program: program.program,
        argv: program.argv,
        env,
        cwd,
    };
    match &req.pty {
        Some(pty) => run_pty(stream, &cmd, pty, ctx, id, cwd_fallback).await,
        None => run_exec(stream, &cmd, ctx, id, cwd_fallback).await,
    }
}

fn spawn_pty(cmd: &Command, pty: &PtyRequest) -> io::Result<(Spawned, AsyncPtyMaster)> {
    let (master, slave) = open_pty(pty.size)?;
    let spawned = spawn_with_pty(slave, cmd)?;
    let master = master.into_async()?;
    Ok((spawned, master))
}

/// How a pump loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Child reaped and output drained: report `status`.
    Exited(ExitStatus),
    /// The client closed or reset the stream; nothing more to report.
    ClientGone,
}

/// Map the child's wait result onto the wire status.
fn reaped(waited: io::Result<std::process::ExitStatus>, id: u32, pid: u32) -> ExitStatus {
    match waited {
        Ok(status) => exit_status(status),
        Err(e) => {
            warn!(session = id, pid, error = %e, "wait failed");
            WAIT_FAILED
        }
    }
}

/// Split the stream, reply `Ok`, send `Started`. `None` when the client is
/// already gone.
async fn start_stream(stream: Stream, id: u32, pid: u32, cwd_fallback: bool) -> Option<SessionIo> {
    let mut io = SessionIo::new(stream);
    write_reply(&mut io.wr, &OpenReply::Ok).await.ok()?;
    io.send(&SessionOut::Started {
        session: id,
        pid,
        cwd_fallback,
    })
    .await
    .ok()?;
    Some(io)
}

async fn run_pty(
    mut stream: Stream,
    cmd: &Command,
    pty: &PtyRequest,
    ctx: &ConnCtx,
    id: u32,
    cwd_fallback: bool,
) {
    let (Spawned { mut child, pid }, master) = match spawn_pty(cmd, pty) {
        Ok(spawned) => spawned,
        Err(e) => {
            let (code, message) = spawn_error(&e);
            files::send_error(&mut stream, code, &message).await;
            return;
        }
    };
    let master = Arc::new(master);
    ctx.sessions.set(
        id,
        SessionHandle {
            pid,
            master: Some(Arc::clone(&master)),
        },
    );
    info!(peer = %ctx.peer, session = id, pid, program = %cmd.program.display(), "pty session started");
    let Some(mut io) = start_stream(stream, id, pid, cwd_fallback).await else {
        ctx.sessions.remove(id);
        return;
    };

    let outcome = pump_pty(&mut io, &master, &mut child, id, pid).await;

    // Closing the master hangs up the session's controlling tty (SIGHUP);
    // the child, if still running, is reaped in the background.
    ctx.sessions.remove(id);
    drop(master);
    match outcome {
        Outcome::ClientGone => {
            debug!(peer = %ctx.peer, session = id, pid, "client left; pty session hung up");
        }
        Outcome::Exited(status) => {
            debug!(peer = %ctx.peer, session = id, pid, %status, "pty session exited");
            io.finish(status).await;
        }
    }
}

/// Pump a pty session until the child is reaped and the master drained
/// (or the 2 s post-exit bound passes), or the client goes away.
async fn pump_pty(
    io: &mut SessionIo,
    master: &AsyncPtyMaster,
    child: &mut tokio::process::Child,
    id: u32,
    pid: u32,
) -> Outcome {
    let mut reader: &AsyncPtyMaster = master;
    let mut writer: &AsyncPtyMaster = master;
    let mut buf = vec![0u8; SESSION_CHUNK];
    // Stdin bytes not yet written to the master; `written` is the offset.
    let mut pending: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut status: Option<ExitStatus> = None;
    let mut master_eof = false;
    let mut drain_until: Option<Instant> = None;

    loop {
        tokio::select! {
            read = reader.read(&mut buf), if !master_eof => match read {
                Ok(0) | Err(_) => {
                    master_eof = true;
                    if let Some(status) = status {
                        return Outcome::Exited(status);
                    }
                }
                Ok(n) => {
                    if io.send(&SessionOut::Stdout(buf[..n].to_vec())).await.is_err() {
                        return Outcome::ClientGone;
                    }
                }
            },
            wrote = writer.write(&pending[written..]), if written < pending.len() => match wrote {
                Ok(n) => {
                    written += n;
                    if written >= pending.len() {
                        pending.clear();
                        written = 0;
                    }
                }
                Err(e) => {
                    debug!(session = id, error = %e, "pty write failed; dropping input");
                    pending.clear();
                    written = 0;
                }
            },
            msg = io.inputs.recv(), if pending.is_empty() => match msg {
                None => return Outcome::ClientGone,
                Some(SessionIn::Stdin(data)) => {
                    pending = data;
                    written = 0;
                }
                Some(SessionIn::StdinEof) => {}
                Some(SessionIn::Resize(size)) => {
                    if let Err(e) = master.resize(size) {
                        debug!(session = id, error = %e, "resize failed");
                    }
                }
                Some(SessionIn::Signal(signal)) => {
                    if let Err(e) = kill(pid, signal) {
                        debug!(session = id, signal = signal.name(), error = %e, "kill failed");
                    }
                }
            },
            waited = child.wait(), if status.is_none() => {
                let exited = reaped(waited, id, pid);
                if master_eof {
                    return Outcome::Exited(exited);
                }
                status = Some(exited);
                drain_until = Some(Instant::now() + DRAIN_AFTER_EXIT);
            },
            () = tokio::time::sleep_until(drain_until.unwrap_or_else(Instant::now)), if drain_until.is_some() => {
                debug!(session = id, "pty still open {}s after exit; hanging up", DRAIN_AFTER_EXIT.as_secs());
                return status.map_or(Outcome::ClientGone, Outcome::Exited);
            },
        }
    }
}

/// `write` to the child's stdin, or nothing when it has been closed.
async fn write_stdin(stdin: Option<&mut ChildStdin>, data: &[u8]) -> io::Result<usize> {
    if let Some(stdin) = stdin {
        stdin.write(data).await
    } else {
        Ok(data.len())
    }
}

async fn run_exec(mut stream: Stream, cmd: &Command, ctx: &ConnCtx, id: u32, cwd_fallback: bool) {
    let Spawned { mut child, pid } = match spawn_piped(cmd) {
        Ok(spawned) => spawned,
        Err(e) => {
            let (code, message) = spawn_error(&e);
            files::send_error(&mut stream, code, &message).await;
            return;
        }
    };
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        files::send_error(&mut stream, ErrorCode::Io, "child pipes unavailable").await;
        return;
    };
    ctx.sessions.set(id, SessionHandle { pid, master: None });
    info!(peer = %ctx.peer, session = id, pid, program = %cmd.program.display(), "exec session started");
    let Some(mut io) = start_stream(stream, id, pid, cwd_fallback).await else {
        ctx.sessions.remove(id);
        return;
    };

    let pipes = ExecPipes {
        stdin: Some(stdin),
        stdout,
        stderr,
    };
    let outcome = pump_exec(&mut io, pipes, &mut child, id, pid).await;

    ctx.sessions.remove(id);
    match outcome {
        Outcome::ClientGone => {
            debug!(peer = %ctx.peer, session = id, pid, "client left; exec session abandoned");
        }
        Outcome::Exited(status) => {
            debug!(peer = %ctx.peer, session = id, pid, %status, "exec session exited");
            io.finish(status).await;
        }
    }
}

struct ExecPipes {
    /// `None` once closed by `StdinEof`, stream EOF, or a write error.
    stdin: Option<ChildStdin>,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
}

/// Pump an exec session until both output pipes hit EOF and the child is
/// reaped, or the client goes away.
async fn pump_exec(
    io: &mut SessionIo,
    mut pipes: ExecPipes,
    child: &mut tokio::process::Child,
    id: u32,
    pid: u32,
) -> Outcome {
    let mut out_buf = vec![0u8; SESSION_CHUNK];
    let mut err_buf = vec![0u8; SESSION_CHUNK];
    let mut pending: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status: Option<ExitStatus> = None;

    loop {
        if stdout_eof
            && stderr_eof
            && let Some(status) = status
        {
            return Outcome::Exited(status);
        }
        tokio::select! {
            read = pipes.stdout.read(&mut out_buf), if !stdout_eof => match read {
                Ok(0) | Err(_) => stdout_eof = true,
                Ok(n) => {
                    if io.send(&SessionOut::Stdout(out_buf[..n].to_vec())).await.is_err() {
                        return Outcome::ClientGone;
                    }
                }
            },
            read = pipes.stderr.read(&mut err_buf), if !stderr_eof => match read {
                Ok(0) | Err(_) => stderr_eof = true,
                Ok(n) => {
                    if io.send(&SessionOut::Stderr(err_buf[..n].to_vec())).await.is_err() {
                        return Outcome::ClientGone;
                    }
                }
            },
            wrote = write_stdin(pipes.stdin.as_mut(), &pending[written..]), if pipes.stdin.is_some() && written < pending.len() => match wrote {
                Ok(n) => {
                    written += n;
                    if written >= pending.len() {
                        pending.clear();
                        written = 0;
                    }
                }
                Err(e) => {
                    debug!(session = id, error = %e, "stdin write failed; closing it");
                    pipes.stdin = None;
                    pending.clear();
                    written = 0;
                }
            },
            msg = io.inputs.recv(), if pending.is_empty() => match msg {
                // Stream EOF without `StdinEof` is treated the same way: the
                // child keeps running and its output still flows to the
                // client until a write fails.
                None | Some(SessionIn::StdinEof) => pipes.stdin = None,
                Some(SessionIn::Stdin(data)) => {
                    if pipes.stdin.is_some() {
                        pending = data;
                        written = 0;
                    }
                }
                Some(SessionIn::Resize(_)) => {}
                Some(SessionIn::Signal(signal)) => {
                    if let Err(e) = kill(pid, signal) {
                        debug!(session = id, signal = signal.name(), error = %e, "kill failed");
                    }
                }
            },
            waited = child.wait(), if status.is_none() => {
                status = Some(reaped(waited, id, pid));
            },
        }
    }
}

/// Current directory of a session: the pty's foreground process group
/// leader, else the child itself (docs/04-sessions.md, "Cwd probe").
fn probe_cwd(handle: &SessionHandle) -> Option<String> {
    let foreground = handle
        .master
        .as_ref()
        .and_then(|master| master.foreground_pgrp().ok().flatten());
    foreground
        .and_then(|pgrp| process_cwd(pgrp).ok())
        .or_else(|| process_cwd(handle.pid).ok())
        .map(|dir| dir.to_string_lossy().into_owned())
}

/// Serve one `Open::Cwd` stream: `Ok`, one `Msg<Option<String>>`, close.
/// Unknown session ids get `NotFound`.
#[allow(clippy::needless_pass_by_value)] // handler signature per the dispatch contract
pub async fn handle_cwd(mut stream: Stream, session: u32, ctx: ConnCtx) {
    let Some(handle) = ctx.sessions.get(session) else {
        files::send_error(&mut stream, ErrorCode::NotFound, "no such session").await;
        return;
    };
    if write_reply(&mut stream, &OpenReply::Ok).await.is_err() {
        return;
    }
    let cwd = probe_cwd(&handle);
    let _ = write_msg(&mut stream, &cwd).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn policy() -> Policy {
        Policy {
            deny: HashSet::new(),
            accept_env: vec!["EDITOR".to_owned(), "FOO_*".to_owned()],
            shell: None,
            name: "test".to_owned(),
            home: PathBuf::from("/home/u"),
            user: "u".to_owned(),
            path: "/usr/bin:/bin".to_owned(),
            forced_command: None,
            handshakes_per_minute: 0,
            idle_timeout: Duration::from_secs(120),
            detach_grace: Duration::from_secs(600),
            signature_auth: true,
        }
    }

    fn env_value<'a>(env: &'a [(OsString, OsString)], name: &str) -> Option<&'a str> {
        env.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.to_str())
    }

    #[test]
    fn env_allow_list() {
        let accept = vec!["EDITOR".to_owned(), "FOO_*".to_owned()];
        for name in [
            "TERM",
            "LANG",
            "COLORTERM",
            "LC_ALL",
            "LC_MESSAGES",
            "EDITOR",
            "FOO_BAR",
        ] {
            assert!(env_allowed(name, &accept), "{name} should pass");
        }
        for name in [
            "PATH",
            "HOME",
            "LD_PRELOAD",
            "EDITORS",
            "FOO",
            "lc_all",
            "BAR_FOO_X",
        ] {
            assert!(!env_allowed(name, &accept), "{name} should be filtered");
        }
    }

    #[test]
    fn build_env_filters_and_sets_base() {
        let client = vec![
            ("TERM".to_owned(), "xterm-256color".to_owned()),
            ("LD_PRELOAD".to_owned(), "/evil.so".to_owned()),
            ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
            ("EDITOR".to_owned(), "vi".to_owned()),
            ("FOO_X".to_owned(), "1".to_owned()),
            ("PATH".to_owned(), "/tmp".to_owned()),
            ("BAD=NAME".to_owned(), "x".to_owned()),
        ];
        let env = build_env(
            &policy(),
            Path::new("/bin/zsh"),
            "10.0.0.2 5000 10.0.0.1 7722",
            7,
            &client,
            Some("screen"),
            None,
        );
        assert_eq!(env_value(&env, "HOME"), Some("/home/u"));
        assert_eq!(env_value(&env, "USER"), Some("u"));
        assert_eq!(env_value(&env, "LOGNAME"), Some("u"));
        assert_eq!(env_value(&env, "PATH"), Some("/usr/bin:/bin"));
        assert_eq!(env_value(&env, "SHELL"), Some("/bin/zsh"));
        assert_eq!(
            env_value(&env, "MYSH_CONNECTION"),
            Some("10.0.0.2 5000 10.0.0.1 7722")
        );
        assert_eq!(env_value(&env, "MYSH_SESSION"), Some("7"));
        // The pty request's TERM wins over the client's env entry.
        assert_eq!(env_value(&env, "TERM"), Some("screen"));
        assert_eq!(env_value(&env, "LC_ALL"), Some("C.UTF-8"));
        assert_eq!(env_value(&env, "EDITOR"), Some("vi"));
        assert_eq!(env_value(&env, "FOO_X"), Some("1"));
        assert_eq!(env_value(&env, "LD_PRELOAD"), None);
        assert_eq!(env_value(&env, "BAD=NAME"), None);

        // Without a pty the client's TERM is used; with none at all, unset.
        let env = build_env(&policy(), Path::new("/bin/sh"), "c", 1, &client, None, None);
        assert_eq!(env_value(&env, "TERM"), Some("xterm-256color"));
        let env = build_env(&policy(), Path::new("/bin/sh"), "c", 1, &[], None, None);
        assert_eq!(env_value(&env, "TERM"), None);
        assert_eq!(env_value(&env, "MYSH_ORIGINAL_COMMAND"), None);

        // A forced command exposes the request; a client cannot smuggle
        // its own value in even when the name is accepted.
        let mut accepting = policy();
        accepting.accept_env.push("MYSH_*".to_owned());
        let smuggled = vec![("MYSH_ORIGINAL_COMMAND".to_owned(), "evil".to_owned())];
        let env = build_env(
            &accepting,
            Path::new("/bin/sh"),
            "c",
            1,
            &smuggled,
            None,
            Some("ls -l"),
        );
        assert_eq!(env_value(&env, "MYSH_ORIGINAL_COMMAND"), Some("ls -l"));
        let env = build_env(
            &accepting,
            Path::new("/bin/sh"),
            "c",
            1,
            &smuggled,
            None,
            None,
        );
        assert_eq!(env_value(&env, "MYSH_ORIGINAL_COMMAND"), None);
    }

    #[test]
    fn forced_command_replaces_request() {
        let shell = Path::new("/bin/zsh");
        let p = forced_program(shell, "echo forced $MYSH_ORIGINAL_COMMAND");
        assert_eq!(p.program, PathBuf::from("/bin/zsh"));
        assert_eq!(
            p.argv,
            vec![
                OsString::from("zsh"),
                OsString::from("-c"),
                OsString::from("echo forced $MYSH_ORIGINAL_COMMAND")
            ]
        );
        assert_eq!(original_command(&SessionKind::Shell), "");
        assert_eq!(
            original_command(&SessionKind::Exec {
                argv: vec!["ls".to_owned(), "-l".to_owned(), "a b".to_owned()],
            }),
            "ls -l a b"
        );
    }

    #[test]
    fn program_for_shell_and_exec() {
        let shell = Path::new("/bin/zsh");
        let path = "/usr/bin:/bin";

        let p = program_for(&SessionKind::Shell, shell, path).unwrap();
        assert_eq!(p.program, PathBuf::from("/bin/zsh"));
        assert_eq!(p.argv, vec![OsString::from("-zsh")]);

        let single = SessionKind::Exec {
            argv: vec!["ls | wc -l".to_owned()],
        };
        let p = program_for(&single, shell, path).unwrap();
        assert_eq!(p.program, PathBuf::from("/bin/zsh"));
        assert_eq!(
            p.argv,
            vec![
                OsString::from("zsh"),
                OsString::from("-c"),
                OsString::from("ls | wc -l")
            ]
        );

        let multi = SessionKind::Exec {
            argv: vec!["sh".to_owned(), "-c".to_owned(), "true".to_owned()],
        };
        let p = program_for(&multi, shell, path).unwrap();
        // Merged-/usr distributions resolve `sh` to /usr/bin/sh first.
        assert!(
            p.program == Path::new("/bin/sh") || p.program == Path::new("/usr/bin/sh"),
            "{:?}",
            p.program
        );
        assert_eq!(
            p.argv,
            vec![
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("true")
            ]
        );

        let explicit = SessionKind::Exec {
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()],
        };
        let p = program_for(&explicit, shell, path).unwrap();
        assert_eq!(p.program, PathBuf::from("/bin/sh"));

        let missing = SessionKind::Exec {
            argv: vec!["definitely-not-a-command-xyz".to_owned(), "a".to_owned()],
        };
        assert!(matches!(
            program_for(&missing, shell, path),
            Err((ErrorCode::NotFound, _))
        ));
        let empty = SessionKind::Exec { argv: Vec::new() };
        assert!(matches!(
            program_for(&empty, shell, path),
            Err((ErrorCode::Protocol, _))
        ));
    }

    #[test]
    fn policy_denials() {
        let mut deny = policy();
        deny.deny.insert(Feature::Pty);
        deny.deny.insert(Feature::Exec);
        let pty = SessionRequest {
            kind: SessionKind::Shell,
            env: Vec::new(),
            pty: Some(PtyRequest {
                term: "xterm".to_owned(),
                size: mysh_proto::session::WinSize::default(),
            }),
            cwd: None,
        };
        assert!(matches!(
            check_policy(&deny, &pty),
            Err((ErrorCode::Denied, _))
        ));
        let exec = SessionRequest {
            kind: SessionKind::Exec {
                argv: vec!["true".to_owned()],
            },
            env: Vec::new(),
            pty: None,
            cwd: None,
        };
        assert!(matches!(
            check_policy(&deny, &exec),
            Err((ErrorCode::Denied, _))
        ));
        let shell = SessionRequest {
            kind: SessionKind::Shell,
            env: Vec::new(),
            pty: None,
            cwd: None,
        };
        assert!(check_policy(&deny, &shell).is_ok());
        assert!(check_policy(&policy(), &pty).is_ok());
        assert!(check_policy(&policy(), &exec).is_ok());
    }

    #[test]
    fn cwd_falls_back_to_home() {
        let tmp = std::env::temp_dir();
        assert_eq!(session_cwd(None, &tmp), (tmp.clone(), false));
        assert_eq!(session_cwd(Some("/"), &tmp), (PathBuf::from("/"), false));
        assert_eq!(
            session_cwd(Some("/definitely/not/here"), &tmp),
            (tmp.clone(), true)
        );
        assert_eq!(session_cwd(Some("~"), &tmp), (tmp.clone(), false));
    }

    #[test]
    fn session_table_quota_and_ids() {
        let sessions = Sessions::new();
        assert!(sessions.is_empty());
        let first = sessions.reserve().unwrap();
        assert_eq!(first, 1);
        assert!(sessions.get(first).is_none(), "reserved but not started");
        sessions.set(
            first,
            SessionHandle {
                pid: 42,
                master: None,
            },
        );
        assert_eq!(sessions.get(first).map(|h| h.pid), Some(42));
        sessions.remove(first);
        assert!(sessions.get(first).is_none());
        // Ids are never reused.
        assert_eq!(sessions.reserve().unwrap(), 2);
        while sessions.len() < MAX_SESSIONS {
            sessions.reserve().unwrap();
        }
        assert!(sessions.reserve().is_none());
    }
}
