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
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use mysh_net::{
    framing::{read_msg, write_msg, write_reply},
    handshake::Peer,
    mux::Stream,
};
use mysh_proto::{
    SESSION_CHUNK,
    limits::{DETACHED_RING, MAX_SESSIONS},
    open::{ErrorCode, OpenReply},
    session::{
        DetachedSession, ExitStatus, PtyRequest, SessionIn, SessionKind, SessionOut, SessionRequest,
    },
};
use mysh_pty::{
    process::{exit_status, kill, login_shell, process_cwd},
    pty::{AsyncPtyMaster, open_pty},
    spawn::{Command, Spawned, spawn_piped, spawn_with_pty},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, WriteHalf},
    process::{Child, ChildStdin},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};
use tracing::{debug, info, warn};

use super::{ConnCtx, Policy, files, resolve_remote_path};
use crate::{cli::Feature, client::session::Ring};

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

/// Per-connection session table (shared through [`ConnCtx`]): the quota
/// count and the handles the cwd probe needs. Ids come from the server-wide
/// [`Registry`] so a detached session keeps its id across connections.
#[derive(Debug, Clone, Default)]
pub struct Sessions {
    registry: Registry,
    /// Reserved (`None`) and started (`Some`) sessions; `len()` is the
    /// quota count.
    live: Arc<Mutex<HashMap<u32, Option<SessionHandle>>>>,
}

impl Sessions {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            live: Arc::default(),
        }
    }

    fn table(&self) -> MutexGuard<'_, HashMap<u32, Option<SessionHandle>>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve a fresh session id (it counts towards `MAX_SESSIONS` at
    /// once); `None` when the quota is reached.
    pub fn reserve(&self) -> Option<u32> {
        let mut table = self.table();
        if table.len() >= MAX_SESSIONS {
            return None;
        }
        let id = self.registry.next_id();
        table.insert(id, None);
        Some(id)
    }

    /// Reserve a slot for an existing (detached) session id; `false` at the
    /// quota.
    pub fn adopt(&self, id: u32) -> bool {
        let mut table = self.table();
        if table.len() >= MAX_SESSIONS {
            return false;
        }
        table.insert(id, None);
        true
    }

    /// Attach the started process to a reserved id.
    pub fn set(&self, id: u32, handle: SessionHandle) {
        if let Some(slot) = self.table().get_mut(&id) {
            *slot = Some(handle);
        }
    }

    pub fn remove(&self, id: u32) {
        self.table().remove(&id);
    }

    /// The started session `id`, if any.
    pub fn get(&self, id: u32) -> Option<SessionHandle> {
        self.table().get(&id).cloned().flatten()
    }

    /// Reserved plus started sessions.
    pub fn len(&self) -> usize {
        self.table().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Server-wide registry: ids and detached sessions

/// What `ListSessions` reports about a PTY session.
#[derive(Debug, Clone)]
struct Meta {
    /// Who opened the session; only that peer may list or attach it.
    owner: Peer,
    pid: u32,
    /// `shell` or the exec command line.
    kind: String,
    /// Unix seconds.
    started: i64,
}

/// A PTY session waiting in the detach grace window
/// (docs/04-sessions.md, "Client gone").
#[derive(Debug)]
struct Parked {
    meta: Meta,
    /// Unix seconds.
    since: i64,
    /// Output captured while detached; shared with the pump task.
    ring: Arc<Mutex<Ring>>,
    /// Tells the pump task to hand the session back; dropping it (server
    /// shutdown) hangs the session up instead.
    stop: oneshot::Sender<()>,
    /// The detached pump; `None` once it hung the session up.
    pump: JoinHandle<Option<PtySession>>,
}

#[derive(Debug)]
enum Slot {
    /// A client is attached (listed with `detached: None`).
    Attached(Meta),
    Detached(Parked),
}

impl Slot {
    fn meta(&self) -> &Meta {
        match self {
            Self::Attached(meta) => meta,
            Self::Detached(parked) => &parked.meta,
        }
    }
}

#[derive(Debug, Default)]
struct RegistryInner {
    /// Last id handed out; ids start at 1 and are never reused.
    last_id: AtomicU32,
    /// Every live PTY session, attached or detached, by id.
    pty: Mutex<HashMap<u32, Slot>>,
}

/// Server-wide session state shared by every connection: the id counter
/// and the PTY sessions that `ListSessions`/`Attach` can see
/// (docs/03-protocol.md §10bis).
#[derive(Debug, Clone, Default)]
pub struct Registry(Arc<RegistryInner>);

impl Registry {
    fn next_id(&self) -> u32 {
        self.0.last_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn pty(&self) -> MutexGuard<'_, HashMap<u32, Slot>> {
        self.0.pty.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, id: u32, meta: Meta) {
        self.pty().insert(id, Slot::Attached(meta));
    }

    fn unregister(&self, id: u32) {
        self.pty().remove(&id);
    }

    /// `owner`'s sessions, detached ones first (then by id).
    fn list(&self, owner: &Peer) -> Vec<DetachedSession> {
        let table = self.pty();
        let mut rows: Vec<DetachedSession> = table
            .iter()
            .filter(|(_, slot)| slot.meta().owner == *owner)
            .map(|(id, slot)| {
                let meta = slot.meta();
                let (detached, buffered) = match slot {
                    Slot::Attached(_) => (None, 0),
                    Slot::Detached(parked) => (
                        Some(parked.since),
                        parked.ring.lock().map_or(0, |ring| ring.len() as u64),
                    ),
                };
                DetachedSession {
                    id: *id,
                    pid: meta.pid,
                    kind: meta.kind.clone(),
                    started: meta.started,
                    detached,
                    buffered,
                    pty: true,
                    next: 0,
                    oldest: 0,
                    exited: None,
                }
            })
            .collect();
        rows.sort_by_key(|row| (row.detached.is_none(), row.id));
        rows
    }

    /// Take `id` out of the grace window for `owner`; the slot stays
    /// registered as attached. Sessions of other peers do not exist.
    fn claim(&self, id: u32, owner: &Peer) -> Result<Parked, (ErrorCode, String)> {
        let mut table = self.pty();
        match table.get(&id) {
            Some(Slot::Detached(parked)) if parked.meta.owner == *owner => {}
            Some(Slot::Attached(meta)) if meta.owner == *owner => {
                return Err((
                    ErrorCode::Limit,
                    "attached by another connection".to_owned(),
                ));
            }
            _ => return Err((ErrorCode::NotFound, "no such detached session".to_owned())),
        }
        let Some(Slot::Detached(parked)) = table.remove(&id) else {
            unreachable!("checked above under the same lock");
        };
        table.insert(id, Slot::Attached(parked.meta.clone()));
        Ok(parked)
    }

    /// Grace expiry from the pump task: forget `id` unless a client claimed
    /// it meanwhile. `true` when the caller must hang the session up.
    fn expire(&self, id: u32) -> bool {
        let mut table = self.pty();
        match table.get(&id) {
            Some(Slot::Attached(_)) => false,
            Some(Slot::Detached(_)) => {
                table.remove(&id);
                true
            }
            None => true,
        }
    }

    /// Server shutdown: hang up every detached session and wait for the
    /// pumps to reap them (bounded per session by `DRAIN_AFTER_EXIT`).
    pub async fn close_detached(&self) {
        let parked: Vec<Parked> = {
            let mut table = self.pty();
            let ids: Vec<u32> = table
                .iter()
                .filter(|(_, slot)| matches!(slot, Slot::Detached(_)))
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| match table.remove(&id) {
                    Some(Slot::Detached(parked)) => Some(parked),
                    _ => None,
                })
                .collect()
        };
        for Parked { stop, pump, .. } in parked {
            drop(stop);
            let _ = pump.await;
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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
        Some(pty) => {
            let meta = Meta {
                owner: ctx.client,
                pid: 0,
                kind: kind_label(&req.kind),
                started: unix_now(),
            };
            run_pty(stream, &cmd, pty, ctx, id, cwd_fallback, meta).await;
        }
        None => run_exec(stream, &cmd, ctx, id, cwd_fallback).await,
    }
}

/// `ListSessions` label: `shell` or the exec command line.
fn kind_label(kind: &SessionKind) -> String {
    match kind {
        SessionKind::Shell => "shell".to_owned(),
        SessionKind::Exec { argv } => argv.join(" "),
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

/// A PTY session's resources, which outlive any one stream once the server
/// keeps detached sessions: the pump state travels with them between the
/// attached pump, the detached pump and a reattach.
#[derive(Debug)]
struct PtySession {
    id: u32,
    pid: u32,
    master: Arc<AsyncPtyMaster>,
    child: Child,
    /// Set once the child is reaped.
    status: Option<ExitStatus>,
    master_eof: bool,
}

#[allow(clippy::too_many_arguments)] // spawn inputs; a struct would only move them
async fn run_pty(
    mut stream: Stream,
    cmd: &Command,
    pty: &PtyRequest,
    ctx: &ConnCtx,
    id: u32,
    cwd_fallback: bool,
    mut meta: Meta,
) {
    let (Spawned { child, pid }, master) = match spawn_pty(cmd, pty) {
        Ok(spawned) => spawned,
        Err(e) => {
            let (code, message) = spawn_error(&e);
            files::send_error(&mut stream, code, &message).await;
            return;
        }
    };
    let session = PtySession {
        id,
        pid,
        master: Arc::new(master),
        child,
        status: None,
        master_eof: false,
    };
    meta.pid = pid;
    ctx.sessions.set(
        id,
        SessionHandle {
            pid,
            master: Some(Arc::clone(&session.master)),
        },
    );
    ctx.registry.register(id, meta.clone());
    info!(peer = %ctx.peer, session = id, pid, program = %cmd.program.display(), "pty session started");
    match start_stream(stream, id, pid, cwd_fallback).await {
        Some(io) => serve_pty(io, session, meta, ctx).await,
        None => settle(Outcome::ClientGone, None, session, meta, ctx, &[]).await,
    }
}

/// Pump `session` over `io` until it ends or the client goes away, then
/// report `Exited` or park it (shared by a fresh session and a reattach).
async fn serve_pty(mut io: SessionIo, mut session: PtySession, meta: Meta, ctx: &ConnCtx) {
    let outcome = pump_pty(&mut io, &mut session).await;
    settle(outcome, Some(io), session, meta, ctx, &[]).await;
}

/// After a pump: `Exited` → hang up and finish the stream; the client gone
/// → park the session for the grace window (persistence on and the child
/// still running) or hang up as before. `carry` seeds the ring with replay
/// bytes the client never received.
async fn settle(
    outcome: Outcome,
    io: Option<SessionIo>,
    session: PtySession,
    meta: Meta,
    ctx: &ConnCtx,
    carry: &[u8],
) {
    let (id, pid) = (session.id, session.pid);
    ctx.sessions.remove(id);
    match outcome {
        Outcome::Exited(status) => {
            debug!(peer = %ctx.peer, session = id, pid, %status, "pty session exited");
            ctx.registry.unregister(id);
            // Closing the master hangs up the session's controlling tty
            // (SIGHUP); the child, if still running, is reaped in the
            // background.
            drop(session);
            if let Some(io) = io {
                io.finish(status).await;
            }
        }
        Outcome::ClientGone => {
            let grace = ctx.policy.detach_grace;
            if grace.is_zero() || session.status.is_some() {
                debug!(peer = %ctx.peer, session = id, pid, "client left; pty session hung up");
                ctx.registry.unregister(id);
                drop(session);
            } else {
                info!(peer = %ctx.peer, session = id, pid, grace_secs = grace.as_secs(), "client left; pty session detached");
                park(session, meta, grace, &ctx.registry, carry);
            }
        }
    }
}

/// Move `session` into the grace window: a pump task keeps draining the
/// master into a ring so the process never blocks on a full pty buffer,
/// and hangs up when the window passes without a reattach.
fn park(session: PtySession, meta: Meta, grace: Duration, registry: &Registry, carry: &[u8]) {
    let id = session.id;
    let mut ring = Ring::new(DETACHED_RING);
    ring.push(carry);
    let ring = Arc::new(Mutex::new(ring));
    let (stop, stop_rx) = oneshot::channel();
    // The slot is inserted under the lock the pump's expiry path takes, so
    // even a tiny grace window cannot fire before the session is parked.
    let mut table = registry.pty();
    let pump = tokio::spawn(detached_pump(
        session,
        Arc::clone(&ring),
        stop_rx,
        grace,
        registry.clone(),
    ));
    table.insert(
        id,
        Slot::Detached(Parked {
            meta,
            since: unix_now(),
            ring,
            stop,
            pump,
        }),
    );
}

/// Detached pump: master → ring, reap the child, hang up at grace expiry.
/// Returns the session when `stop` asks for it (a reattach), `None` once
/// it hung up (expiry, or the sender dropped at server shutdown).
async fn detached_pump(
    mut session: PtySession,
    ring: Arc<Mutex<Ring>>,
    mut stop: oneshot::Receiver<()>,
    grace: Duration,
    registry: Registry,
) -> Option<PtySession> {
    let master = Arc::clone(&session.master);
    let mut reader: &AsyncPtyMaster = &master;
    let mut buf = vec![0u8; SESSION_CHUNK];
    let deadline = Instant::now() + grace;
    let mut grace_armed = true;
    let (id, pid) = (session.id, session.pid);
    loop {
        tokio::select! {
            stopped = &mut stop => {
                if stopped.is_ok() {
                    return Some(session);
                }
                // Sender dropped (server shutdown): hang up.
                registry.expire(id);
                break;
            },
            read = reader.read(&mut buf), if !session.master_eof => match read {
                Ok(0) | Err(_) => session.master_eof = true,
                Ok(n) => {
                    if let Ok(mut ring) = ring.lock() {
                        ring.push(&buf[..n]);
                    }
                }
            },
            waited = session.child.wait(), if session.status.is_none() => {
                let status = reaped(waited, id, pid);
                debug!(session = id, pid, %status, "detached pty session exited");
                session.status = Some(status);
            },
            () = tokio::time::sleep_until(deadline), if grace_armed => {
                if registry.expire(id) {
                    debug!(session = id, pid, "detach grace expired; hanging up");
                    break;
                }
                // Claimed concurrently: the stop signal is on its way.
                grace_armed = false;
            },
        }
    }
    drop(master);
    hang_up(session).await;
    None
}

/// Close the master (SIGHUP through the controlling tty) and reap the
/// child, waiting at most `DRAIN_AFTER_EXIT` for it.
async fn hang_up(session: PtySession) {
    let PtySession {
        master,
        mut child,
        status,
        ..
    } = session;
    drop(master);
    if status.is_none() {
        let _ = tokio::time::timeout(DRAIN_AFTER_EXIT, child.wait()).await;
    }
}

/// Pump a pty session until the child is reaped and the master drained
/// (or the 2 s post-exit bound passes), or the client goes away. Picks up
/// where a detached pump left off (`status`, `master_eof`).
async fn pump_pty(io: &mut SessionIo, session: &mut PtySession) -> Outcome {
    let (id, pid) = (session.id, session.pid);
    let master = Arc::clone(&session.master);
    let mut reader: &AsyncPtyMaster = &master;
    let mut writer: &AsyncPtyMaster = &master;
    let mut buf = vec![0u8; SESSION_CHUNK];
    // Stdin bytes not yet written to the master; `written` is the offset.
    let mut pending: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut drain_until: Option<Instant> = None;
    if let Some(status) = session.status {
        if session.master_eof {
            return Outcome::Exited(status);
        }
        drain_until = Some(Instant::now() + DRAIN_AFTER_EXIT);
    }

    loop {
        tokio::select! {
            read = reader.read(&mut buf), if !session.master_eof => match read {
                Ok(0) | Err(_) => {
                    session.master_eof = true;
                    if let Some(status) = session.status {
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
            waited = session.child.wait(), if session.status.is_none() => {
                let exited = reaped(waited, id, pid);
                if session.master_eof {
                    return Outcome::Exited(exited);
                }
                session.status = Some(exited);
                drain_until = Some(Instant::now() + DRAIN_AFTER_EXIT);
            },
            () = tokio::time::sleep_until(drain_until.unwrap_or_else(Instant::now)), if drain_until.is_some() => {
                debug!(session = id, "pty still open {}s after exit; hanging up", DRAIN_AFTER_EXIT.as_secs());
                return session.status.map_or(Outcome::ClientGone, Outcome::Exited);
            },
        }
    }
}

/// Serve one `Open::Attach` stream (docs/03-protocol.md §10bis): claim the
/// detached session for this client key, reply `Ok`, send `Attached` and
/// the buffered output, then pump it like a fresh session.
#[allow(clippy::needless_pass_by_value)] // handler signature per the dispatch contract
pub async fn handle_attach(mut stream: Stream, id: u32, ctx: ConnCtx) {
    if ctx.policy.detach_grace.is_zero() {
        files::send_error(
            &mut stream,
            ErrorCode::Unsupported,
            "session persistence is not enabled",
        )
        .await;
        return;
    }
    if ctx.policy.denies(Feature::Pty) {
        files::send_error(&mut stream, ErrorCode::Denied, "pty sessions are denied").await;
        return;
    }
    if !ctx.sessions.adopt(id) {
        files::send_error(
            &mut stream,
            ErrorCode::Limit,
            &format!("at most {MAX_SESSIONS} sessions per connection"),
        )
        .await;
        return;
    }
    let parked = match ctx.registry.claim(id, &ctx.client) {
        Ok(parked) => parked,
        Err((code, message)) => {
            ctx.sessions.remove(id);
            files::send_error(&mut stream, code, &message).await;
            return;
        }
    };
    let Parked {
        meta,
        ring,
        stop,
        pump,
        ..
    } = parked;
    let _ = stop.send(());
    let Some(session) = pump.await.ok().flatten() else {
        // Expired between the claim and the hand-over.
        ctx.registry.unregister(id);
        ctx.sessions.remove(id);
        files::send_error(&mut stream, ErrorCode::NotFound, "no such detached session").await;
        return;
    };
    let (replay, dropped) = ring.lock().map_or((Vec::new(), 0), |mut r| r.take());
    ctx.sessions.set(
        id,
        SessionHandle {
            pid: session.pid,
            master: Some(Arc::clone(&session.master)),
        },
    );
    info!(peer = %ctx.peer, session = id, pid = session.pid, buffered = replay.len(), dropped, "pty session reattached");

    let mut io = SessionIo::new(stream);
    let header = SessionOut::Attached {
        session: id,
        pid: session.pid,
        buffered: replay.len() as u64,
        dropped: dropped as u64,
    };
    let mut sent = 0usize;
    let delivered = async {
        write_reply(&mut io.wr, &OpenReply::Ok).await?;
        io.send(&header).await?;
        for chunk in replay.chunks(SESSION_CHUNK) {
            io.send(&SessionOut::Stdout(chunk.to_vec())).await?;
            sent += chunk.len();
        }
        Ok::<(), std::io::Error>(())
    }
    .await;
    if delivered.is_ok() {
        serve_pty(io, session, meta, &ctx).await;
    } else {
        settle(
            Outcome::ClientGone,
            Some(io),
            session,
            meta,
            &ctx,
            &replay[sent..],
        )
        .await;
    }
}

/// Serve one `Open::ListSessions` stream: `Ok`, one
/// `Msg<Vec<DetachedSession>>` with this client key's PTY sessions, close.
/// `Unsupported` when persistence is off.
#[allow(clippy::needless_pass_by_value)] // handler signature per the dispatch contract
pub async fn handle_list_sessions(mut stream: Stream, ctx: ConnCtx) {
    if ctx.policy.detach_grace.is_zero() {
        files::send_error(
            &mut stream,
            ErrorCode::Unsupported,
            "session persistence is not enabled",
        )
        .await;
        return;
    }
    if write_reply(&mut stream, &OpenReply::Ok).await.is_err() {
        return;
    }
    let rows = ctx.registry.list(&ctx.client);
    let _ = write_msg(&mut stream, &rows).await;
    let _ = stream.shutdown().await;
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
            persist: false,
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
            persist: false,
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
            persist: false,
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
        let registry = Registry::default();
        let sessions = Sessions::new(registry.clone());
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
        // Ids are never reused and are server-wide: a second connection on
        // the same registry continues the sequence.
        assert_eq!(sessions.reserve().unwrap(), 2);
        let other = Sessions::new(registry);
        assert_eq!(other.reserve().unwrap(), 3);
        while sessions.len() < MAX_SESSIONS {
            sessions.reserve().unwrap();
        }
        assert!(sessions.reserve().is_none());
        assert!(!sessions.adopt(99), "adopt honours the quota too");
        assert!(other.adopt(99));
        assert_eq!(other.len(), 2);
    }

    #[test]
    fn registry_lists_and_claims_per_owner() {
        let registry = Registry::default();
        let alice = Peer::Static(mysh_net::keys::SecretKey::generate().public());
        let bob = Peer::Ed25519([3u8; 32]);
        let meta = Meta {
            owner: alice,
            pid: 7,
            kind: "shell".to_owned(),
            started: 1,
        };
        registry.register(1, meta.clone());
        assert_eq!(registry.list(&alice).len(), 1);
        assert!(registry.list(&alice)[0].detached.is_none());
        assert_eq!(registry.list(&bob).len(), 0);
        // Attached: the owner gets `Limit`, anyone else `NotFound`.
        assert_eq!(
            registry.claim(1, &alice).err().map(|e| e.0),
            Some(ErrorCode::Limit)
        );
        assert_eq!(
            registry.claim(1, &bob).err().map(|e| e.0),
            Some(ErrorCode::NotFound)
        );
        assert_eq!(
            registry.claim(2, &alice).err().map(|e| e.0),
            Some(ErrorCode::NotFound)
        );
        assert!(!registry.expire(1), "an attached slot never expires");
        registry.unregister(1);
        assert_eq!(registry.list(&alice).len(), 0);
        assert!(registry.expire(1), "unknown ids hang up defensively");
        assert_eq!(kind_label(&SessionKind::Shell), "shell");
        assert_eq!(
            kind_label(&SessionKind::Exec {
                argv: vec!["ls".into(), "-l".into()]
            }),
            "ls -l"
        );
    }
}
