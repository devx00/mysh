//! The meta prompt (docs/05-meta-shell.md): the prompt loop driving the
//! line editor (`client::editor`) from the stdin reader task, the command
//! dispatcher shared with the scripted frontend (`mysh HOST < script`), and
//! the session request helpers.

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_proto::session::{ExitStatus, PtyRequest, SessionKind, SessionRequest, Signal, WinSize};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    sync::mpsc,
};
use tracing::debug;

use crate::{
    cli::{ForwardAction, MetaCommand, meta_help, parse_meta_line},
    client::{
        attach,
        conn::Connection,
        console::{Console, human},
        editor::{Edit, LineEditor, format_columns},
        files,
        forward::{ForwardInfo, ForwardKind},
        jobs,
        session::{Event, SessionInfo, Stack},
        shared::Shared,
        terminal::{Input, Terminal},
    },
    config::{ForwardSpec, Target, decode_send_text, expand_tilde},
    output::{
        self, ConnectionOut, CwdOut, EXIT_TIMEOUT, ExecResult, ForwardRow, InfoOut, JobOut, JobRow,
        OkOut, PingOut, ProgressOut, SessionRow, SessionsOut, code_for, codes, millis,
    },
};

pub use crate::client::editor::{HISTORY_CAP, History};

/// Why the prompt returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Hand the terminal to this session.
    Foreground(u32),
    /// `exit` / `Ctrl-D` with no sessions.
    Exit,
    /// `disconnect`, or the connection is gone.
    Disconnect,
}

/// Result of one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Foreground(u32),
    Exit,
    Disconnect,
}

/// Everything the dispatcher works on. The prompt owns one; a background
/// job or a control-socket request builds a detached one over the same
/// [`Shared`] state ([`Ctx::detached`]).
pub struct Ctx {
    /// Connection, forwards, jobs, home: shared with jobs and the control
    /// socket.
    pub shared: Arc<Shared>,
    pub console: Console,
    /// The prompt's session stack; a detached context has an empty private
    /// one (used by `exec`) and reads `shared.sessions` instead.
    pub stack: Stack,
    pub events: mpsc::UnboundedReceiver<Event>,
    pub history: History,
    /// Client-side working directory for `put`/`get`/`lcd`.
    pub local_cwd: PathBuf,
    /// `-s` / `CMD`: exit when the session list becomes empty.
    pub auto_exit: bool,
    /// Not the prompt: session commands use the shared snapshot.
    pub detached: bool,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("conn", &self.shared.conn)
            .field("sessions", &self.stack.len())
            .field("local_cwd", &self.local_cwd)
            .field("auto_exit", &self.auto_exit)
            .field("detached", &self.detached)
            .finish_non_exhaustive()
    }
}

impl Ctx {
    /// The prompt's context.
    pub fn new(shared: Arc<Shared>, console: Console, local_cwd: PathBuf, auto_exit: bool) -> Self {
        let (stack, events) = Stack::new(console.clone());
        Self {
            shared,
            console,
            stack,
            events,
            history: History::empty(),
            local_cwd,
            auto_exit,
            detached: false,
        }
    }

    /// A context for a job or a control request: its own console and an
    /// empty private stack.
    pub fn detached(shared: &Arc<Shared>, console: Console, local_cwd: PathBuf) -> Self {
        let mut ctx = Self::new(Arc::clone(shared), console, local_cwd, false);
        ctx.detached = true;
        ctx
    }

    /// Publish the prompt's stack to `shared.sessions`; call after anything
    /// that may have changed it.
    pub fn sync_sessions(&self) {
        if !self.detached {
            self.shared.sessions.update(&self.stack);
        }
    }

    /// Most recently used session id.
    pub fn mru(&self) -> Option<u32> {
        if self.detached {
            self.shared.sessions.mru()
        } else {
            self.stack.mru()
        }
    }

    fn session_rows(&self) -> Vec<SessionInfo> {
        if self.detached {
            self.shared.sessions.list()
        } else {
            self.stack.list()
        }
    }

    fn session_count(&self) -> usize {
        if self.detached {
            self.shared.sessions.len()
        } else {
            self.stack.len()
        }
    }

    fn signal(&self, id: u32, sig: Signal) -> Result<()> {
        if self.detached {
            self.shared.sessions.signal(id, sig)
        } else {
            self.stack.signal(id, sig)
        }
    }
}

impl Drop for Ctx {
    /// A job or control request that is cancelled mid-`exec` leaves its
    /// session in the private stack: ask the server to end it.
    fn drop(&mut self) {
        if self.detached {
            for s in self.stack.list() {
                let _ = self.stack.signal(s.id, Signal::Term);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session request helpers (shared with `client::run`)

/// Environment to send: `LANG`, `LC_*`, `COLORTERM` from the local
/// environment, plus `--env` items (`NAME` alone reads the local value).
pub fn session_env(target: &Target) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k == "LANG" || k == "COLORTERM" || k.starts_with("LC_"))
        .collect();
    for (name, value) in &target.env {
        let value = match value {
            Some(v) => v.clone(),
            None => match std::env::var(name) {
                Ok(v) => v,
                Err(_) => continue,
            },
        };
        env.retain(|(k, _)| k != name);
        env.push((name.clone(), value));
    }
    env
}

/// `$TERM`, or a sane default.
pub fn term_name() -> String {
    std::env::var("TERM")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "xterm-256color".to_owned())
}

/// Build a `SessionRequest`; `pty` is the window size when a PTY is wanted.
pub fn session_request(
    target: &Target,
    kind: SessionKind,
    pty: Option<WinSize>,
    cwd: Option<String>,
) -> SessionRequest {
    SessionRequest {
        persist: false,
        kind,
        env: session_env(target),
        pty: pty.map(|size| PtyRequest {
            term: term_name(),
            size,
        }),
        cwd,
    }
}

/// The MRU session's cwd, if there is one and the probe succeeds.
pub async fn mru_cwd(ctx: &Ctx) -> Option<String> {
    let id = ctx.mru()?;
    ctx.shared.conn.cwd_probe(id).await
}

/// Label for `sessions`: `shell` or `exec: CMD`.
pub fn kind_label(command: &[String]) -> String {
    if command.is_empty() {
        "shell".to_owned()
    } else {
        format!("exec: {}", command.join(" "))
    }
}

// ---------------------------------------------------------------------------
// Dispatcher

/// Wait for `Ctrl-C` on the terminal; never resolves without one.
async fn wait_ctrl_c(term: Option<&mut Terminal>) {
    let Some(term) = term else {
        return std::future::pending().await;
    };
    loop {
        match term.next().await {
            Some(Input::Bytes(b)) if b.contains(&0x03) => return,
            Some(Input::Eof) | None => return std::future::pending().await,
            _ => {}
        }
    }
}

async fn next_input(term: Option<&mut Terminal>) -> Option<Input> {
    if let Some(t) = term {
        t.next().await
    } else {
        std::future::pending().await
    }
}

/// Run `fut` until it finishes or the user presses `Ctrl-C` (`Ok(None)`).
async fn cancellable<T>(
    term: Option<&mut Terminal>,
    fut: impl Future<Output = Result<T>>,
) -> Result<Option<T>> {
    tokio::select! {
        r = fut => r.map(Some),
        () = wait_ctrl_c(term) => Ok(None),
    }
}

fn resolve_local(ctx: &Ctx, path: &str) -> PathBuf {
    let p = expand_tilde(path, &ctx.shared.home);
    if p.is_absolute() {
        p
    } else {
        ctx.local_cwd.join(p)
    }
}

/// Public key line for `authorize`: the first key line of `pubkey`, or the
/// identity in use.
pub fn pubkey_line(
    conn: &Connection,
    pubkey: Option<&Path>,
    home: &Path,
    local_cwd: &Path,
) -> Result<String> {
    let Some(path) = pubkey else {
        return Ok(conn.identity_line().trim().to_owned());
    };
    let path = expand_tilde(&path.to_string_lossy(), home);
    let path = if path.is_absolute() {
        path
    } else {
        local_cwd.join(path)
    };
    let text =
        fs::read_to_string(&path).with_context(|| format!("authorize: {}", path.display()))?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("authorize: no key in {}", path.display()))
}

fn format_sessions(ctx: &Ctx) -> String {
    let mut out = String::from("  ID   PID     KIND             BUFFERED\n");
    for s in ctx.session_rows() {
        let mark = if s.mru { '*' } else { ' ' };
        let buffered = if s.buffered == 0 {
            "-".to_owned()
        } else {
            human(s.buffered as u64)
        };
        let _ = writeln!(
            out,
            "{mark} {:<4} {:<7} {:<16} {buffered}",
            s.id, s.pid, s.kind
        );
    }
    out
}

fn format_forward(f: &ForwardInfo) -> String {
    let flag = match f.kind {
        ForwardKind::Local => "-L",
        ForwardKind::Remote => "-R",
        ForwardKind::Dynamic => "-D",
    };
    match &f.target {
        Some((host, port)) => format!(
            "{:>3}  {flag} {} -> {host}:{port}  ({} accepted)",
            f.id, f.bind, f.accepted
        ),
        None => format!(
            "{:>3}  {flag} {} (SOCKS5)  ({} accepted)",
            f.id, f.bind, f.accepted
        ),
    }
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m{:02}s", s / 3600, (s / 60) % 60, s % 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

fn ms(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1000.0)
}

/// Execute one parsed command. `term` is `None` in scripted mode, where
/// session commands are refused and nothing is cancellable.
pub async fn execute(ctx: &mut Ctx, cmd: MetaCommand, term: Option<&mut Terminal>) -> Result<Flow> {
    match cmd {
        MetaCommand::Help { json, cmd } => cmd_help(ctx, json, cmd.as_deref())?,
        MetaCommand::Shell(_)
        | MetaCommand::Fg { .. }
        | MetaCommand::Sessions { .. }
        | MetaCommand::Attach { .. }
        | MetaCommand::Detach { .. }
        | MetaCommand::Kill { .. }
        | MetaCommand::Send { .. }
        | MetaCommand::Resize => return execute_session(ctx, cmd, term).await,
        MetaCommand::Put(_)
        | MetaCommand::Get(_)
        | MetaCommand::Ls(_)
        | MetaCommand::Stat(_)
        | MetaCommand::Cat(_)
        | MetaCommand::Write(_)
        | MetaCommand::Tail(_)
        | MetaCommand::Mkdir(_)
        | MetaCommand::Rm(_)
        | MetaCommand::Mv(_)
        | MetaCommand::Realpath(_)
        | MetaCommand::Hash(_)
        | MetaCommand::Sync(_)
        | MetaCommand::Authorize(_) => execute_transfer(ctx, cmd, term).await?,
        MetaCommand::Cwd => cmd_cwd(ctx).await,
        MetaCommand::Lcd { dir } => cmd_lcd(ctx, dir.as_deref())?,
        MetaCommand::Forward(args) => cmd_forward(ctx, &args).await?,
        MetaCommand::Exec {
            timeout,
            cwd,
            command,
        } => {
            let timeout = timeout.or(ctx.shared.conn.target().timeout);
            let code = exec_command(ctx, command, cwd, timeout, None, term).await?;
            if !ctx.console.mode().is_json() {
                ctx.console.println(&format!("[exit {code}]"));
            }
        }
        MetaCommand::Session(args) => {
            let conn = ctx.shared.conn.clone();
            let console = ctx.console.clone();
            crate::client::session_api::run(&conn, &console, &args, None).await?;
        }
        MetaCommand::Info => cmd_info(ctx).await?,
        MetaCommand::Ping { count } => cmd_ping(ctx, count.unwrap_or(4).max(1), term).await?,
        MetaCommand::Log { target } => cmd_log(ctx, &target)?,
        MetaCommand::Jobs { wait, id } => cmd_jobs(ctx, wait, id).await?,
        MetaCommand::Exit => {
            if !ctx.stack.is_empty() {
                bail!(
                    "exit: {} session(s) still running:\n{}use `fg` to return to one, or `disconnect` to end them",
                    ctx.stack.len(),
                    format_sessions(ctx)
                );
            }
            return Ok(Flow::Exit);
        }
        MetaCommand::Disconnect => return Ok(Flow::Disconnect),
    }
    Ok(Flow::Continue)
}

/// Session-stack commands; those that hand the terminal to a session need
/// an interactive terminal.
async fn execute_session(
    ctx: &mut Ctx,
    cmd: MetaCommand,
    term: Option<&mut Terminal>,
) -> Result<Flow> {
    match cmd {
        MetaCommand::Shell(args) => {
            let Some(t) = term else {
                bail!("shell: stdin is not a terminal");
            };
            let ws = t.winsize();
            cmd_shell(ctx, &args, ws).await.map(Flow::Foreground)
        }
        MetaCommand::Fg { id } => {
            if term.is_none() {
                bail!("fg: stdin is not a terminal");
            }
            let id = id
                .or_else(|| ctx.stack.mru())
                .ok_or_else(|| anyhow!("fg: no sessions"))?;
            if ctx.stack.get(id).is_none() {
                bail!("fg: no session {id}");
            }
            Ok(Flow::Foreground(id))
        }
        MetaCommand::Sessions { all } => {
            cmd_sessions(ctx, all).await?;
            Ok(Flow::Continue)
        }
        MetaCommand::Attach { id } => {
            if term.is_none() || ctx.detached {
                bail!("attach: stdin is not a terminal");
            }
            let id = attach::attach(&ctx.shared.conn, &mut ctx.stack, id)
                .await
                .context("attach")?;
            Ok(Flow::Foreground(id))
        }
        MetaCommand::Detach { id } => {
            if ctx.detached {
                bail!("detach: only at the prompt");
            }
            attach::detach(&ctx.shared.conn, &ctx.console, &mut ctx.stack, id)?;
            ctx.console.report(&OkOut::OK, String::new);
            Ok(Flow::Continue)
        }
        MetaCommand::Kill { signal, id } => {
            cmd_kill(ctx, signal.as_deref(), &id)?;
            Ok(Flow::Continue)
        }
        MetaCommand::Send { text } => {
            if term.is_none() {
                bail!("send: stdin is not a terminal");
            }
            let id = ctx
                .stack
                .mru()
                .ok_or_else(|| anyhow!("send: no sessions"))?;
            let bytes = decode_send_text(&text.join(" "));
            ctx.stack.send_stdin(id, &bytes)?;
            Ok(Flow::Foreground(id))
        }
        MetaCommand::Resize => {
            let Some(t) = term else {
                bail!("resize: stdin is not a terminal");
            };
            let id = ctx
                .stack
                .mru()
                .ok_or_else(|| anyhow!("resize: no sessions"))?;
            let ws = t.winsize();
            ctx.stack.resize(id, ws)?;
            ctx.console.report(&OkOut::OK, || {
                format!("session {id}: {}x{}\n", ws.cols, ws.rows)
            });
            Ok(Flow::Continue)
        }
        other => bail!("internal: {other:?} is not a session command"),
    }
}

/// File commands; cancellable with `Ctrl-C` at an interactive prompt and
/// bounded by the connection's `--timeout`.
async fn execute_transfer(
    ctx: &mut Ctx,
    cmd: MetaCommand,
    term: Option<&mut Terminal>,
) -> Result<()> {
    let conn = ctx.shared.conn.clone();
    let limit = conn.target().timeout;
    let (name, done) = match cmd {
        MetaCommand::Put(args) => {
            let remote = mru_cwd(ctx).await;
            let fut = files::put(
                &conn,
                &ctx.console,
                &args,
                remote.as_deref(),
                &ctx.local_cwd,
            );
            (
                "put",
                cancellable(term, bounded(limit, fut)).await?.is_some(),
            )
        }
        MetaCommand::Get(args) => {
            let remote = mru_cwd(ctx).await;
            let fut = files::get(
                &conn,
                &ctx.console,
                &args,
                remote.as_deref(),
                &ctx.local_cwd,
            );
            (
                "get",
                cancellable(term, bounded(limit, fut)).await?.is_some(),
            )
        }
        MetaCommand::Ls(args) => {
            let remote = mru_cwd(ctx).await;
            let fut = files::ls(&conn, &ctx.console, &args, remote.as_deref());
            ("ls", cancellable(term, fut).await?.is_some())
        }
        MetaCommand::Authorize(args) => {
            let line = pubkey_line(
                &conn,
                args.pubkey.as_deref(),
                &ctx.shared.home,
                &ctx.local_cwd,
            )?;
            let fut = files::authorize(&conn, &ctx.console, &line);
            ("authorize", cancellable(term, fut).await?.is_some())
        }
        other => {
            let mut cmd = other
                .into_file_cmd()
                .map_err(|c| anyhow!("internal: {c:?} is not a transfer command"))?;
            let remote = mru_cwd(ctx).await;
            // `tail -f` ends on its own deadline: a plain `--timeout` would
            // turn its natural end into an error.
            let limit = if let crate::cli::FileCmd::Tail(tail) = &mut cmd
                && tail.follow
            {
                tail.timeout = tail.timeout.or(limit);
                None
            } else {
                limit
            };
            let fut = crate::client::fileops::run(
                &conn,
                &ctx.console,
                &cmd,
                remote.as_deref(),
                &ctx.local_cwd,
                None,
            );
            (
                cmd.name(),
                cancellable(term, bounded(limit, fut)).await?.is_some(),
            )
        }
    };
    if !done {
        ctx.console.println(&format!("{name}: cancelled"));
    }
    Ok(())
}

/// Run `fut` within `limit` (none: unbounded); expiry is a `timeout` error.
pub async fn bounded<T>(
    limit: Option<Duration>,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    match limit {
        None => fut.await,
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(r) => r,
            Err(_) => Err(output::coded(
                codes::TIMEOUT,
                anyhow!("timed out after {}", format_duration(d)),
            )),
        },
    }
}

/// `sessions [-a]`: the stack, and with `-a` the server's registered
/// sessions below it.
async fn cmd_sessions(ctx: &Ctx, all: bool) -> Result<()> {
    if ctx.console.mode().is_json() {
        let server = if all {
            Some(attach::list(&ctx.shared.conn).await?)
        } else {
            None
        };
        let out = SessionsOut {
            sessions: ctx.session_rows().iter().map(session_row).collect(),
            server,
        };
        ctx.console.report(&out, String::new);
        return Ok(());
    }
    if ctx.session_count() == 0 {
        ctx.console.println("no sessions");
    } else {
        ctx.console.print(&format_sessions(ctx));
    }
    if all {
        ctx.console.println("server:");
        attach::print_remote(&ctx.shared.conn, &ctx.console).await?;
    }
    Ok(())
}

fn session_row(s: &SessionInfo) -> SessionRow {
    SessionRow {
        id: s.id,
        pid: s.pid,
        kind: s.kind.clone(),
        buffered: s.buffered as u64,
        mru: s.mru,
        foreground: s.foreground,
    }
}

/// `help [--json] [CMD]`: the prompt grammar as text or as a tree.
fn cmd_help(ctx: &Ctx, json: bool, cmd: Option<&str>) -> Result<()> {
    if json || ctx.console.mode().is_json() {
        let tree = crate::cli::meta_help_tree();
        let tree = match cmd {
            Some(name) => tree
                .subcommand(name)
                .cloned()
                .ok_or_else(|| anyhow!("unknown command {name:?}; type `help` for the list"))?,
            None => tree,
        };
        if ctx.console.mode().is_json() {
            ctx.console.report(&tree, String::new);
        } else {
            ctx.console.print(&format!(
                "{}\n",
                serde_json::to_string(&tree).unwrap_or_default()
            ));
        }
        return Ok(());
    }
    ctx.console.print(&meta_help(cmd));
    Ok(())
}

/// `shell [--home] [CMD...]`: open a PTY session; the caller foregrounds it.
async fn cmd_shell(ctx: &mut Ctx, args: &crate::cli::ShellArgs, ws: WinSize) -> Result<u32> {
    let cwd = if args.home { None } else { mru_cwd(ctx).await };
    let kind = if args.command.is_empty() {
        SessionKind::Shell
    } else {
        SessionKind::Exec {
            argv: args.command.clone(),
        }
    };
    let req = session_request(ctx.shared.conn.target(), kind, Some(ws), cwd);
    ctx.stack
        .open_session(&ctx.shared.conn, req, &kind_label(&args.command))
        .await
}

/// `kill [-s SIG] ID` signals a session; `kill %ID` cancels a job.
fn cmd_kill(ctx: &Ctx, signal: Option<&str>, id: &str) -> Result<()> {
    if let Some(job) = id.strip_prefix('%') {
        if signal.is_some() {
            bail!("kill: jobs take no signal; `kill %ID` cancels");
        }
        let job: u32 = job
            .parse()
            .map_err(|_| anyhow!("kill: invalid job id {id:?}"))?;
        ctx.shared.jobs.cancel(job)?;
        ctx.console
            .report(&OkOut::OK, || format!("job {job} cancelled\n"));
        return Ok(());
    }
    let sig = match signal {
        Some(s) => Signal::parse(s).ok_or_else(|| anyhow!("kill: unknown signal {s:?}"))?,
        None => Signal::Term,
    };
    let id: u32 = id
        .parse()
        .map_err(|_| anyhow!("kill: invalid session id {id:?} (jobs are `%ID`)"))?;
    ctx.signal(id, sig)?;
    ctx.console.report(&OkOut::OK, String::new);
    Ok(())
}

fn job_row(j: &jobs::JobInfo) -> JobRow {
    let (state, exit, error) = match &j.state {
        jobs::JobState::Running => ("running", None, None),
        jobs::JobState::Done { code } => ("done", Some(*code), None),
        jobs::JobState::Failed { msg } => ("failed", None, Some(msg.clone())),
        jobs::JobState::Cancelled => ("cancelled", None, None),
    };
    JobRow {
        id: j.id,
        state: state.to_owned(),
        exit,
        error,
        elapsed_ms: u64::try_from(j.elapsed().as_millis()).unwrap_or(u64::MAX),
        command: j.line.clone(),
        progress: j.progress.as_ref().map(|p| ProgressOut {
            label: p.label.clone(),
            done: p.done,
            total: p.total,
        }),
    }
}

/// `jobs [-w] [ID]`: list jobs, show one job's state and output, or wait
/// for it.
async fn cmd_jobs(ctx: &Ctx, wait: bool, id: Option<u32>) -> Result<()> {
    let jobs = &ctx.shared.jobs;
    let Some(id) = id else {
        let list = jobs.list();
        let rows: Vec<JobRow> = list.iter().map(job_row).collect();
        ctx.console.report(&rows, || {
            if list.is_empty() {
                "no jobs\n".to_owned()
            } else {
                jobs.format_list()
            }
        });
        return Ok(());
    };
    if wait {
        jobs.wait(id)
            .await
            .ok_or_else(|| anyhow!("jobs: no job {id}"))?;
    }
    let (info, output) = jobs.get(id).ok_or_else(|| anyhow!("jobs: no job {id}"))?;
    let out = JobOut {
        job: job_row(&info),
        output: output::Bytes::new(output.clone()),
    };
    ctx.console.report(&out, || {
        let mut text = format!("job {id} {}: {}\n", info.state, info.summary());
        if !output.is_empty() {
            text.push_str(String::from_utf8_lossy(&output).trim_end_matches('\n'));
            text.push('\n');
        }
        text
    });
    Ok(())
}

async fn cmd_cwd(ctx: &Ctx) {
    let (session, cwd) = match ctx.mru() {
        Some(id) => (Some(id), ctx.shared.conn.cwd_probe(id).await),
        None => (None, None),
    };
    let out = CwdOut {
        remote: cwd.clone(),
        session,
        local: ctx.local_cwd.display().to_string(),
    };
    ctx.console.report(&out, || {
        let remote = match (session, cwd) {
            (Some(id), Some(cwd)) => format!("{cwd} (session {id})"),
            (Some(id), None) => format!("~ (probe failed for session {id}; server home)"),
            (None, _) => "~ (no session; server home)".to_owned(),
        };
        format!("remote: {remote}\nlocal:  {}\n", ctx.local_cwd.display())
    });
}

fn cmd_lcd(ctx: &mut Ctx, dir: Option<&str>) -> Result<()> {
    let dir = match dir {
        Some(d) => resolve_local(ctx, d),
        None => ctx.shared.home.clone(),
    };
    let dir = dir
        .canonicalize()
        .with_context(|| format!("lcd: {}", dir.display()))?;
    if !dir.is_dir() {
        bail!("lcd: {} is not a directory", dir.display());
    }
    ctx.local_cwd = dir;
    Ok(())
}

fn forward_row(f: &ForwardInfo) -> ForwardRow {
    ForwardRow {
        id: f.id,
        kind: match f.kind {
            ForwardKind::Local => "local",
            ForwardKind::Remote => "remote",
            ForwardKind::Dynamic => "dynamic",
        }
        .to_owned(),
        bind: f.bind.to_string(),
        target: f.target.as_ref().map(|(h, p)| format!("{h}:{p}")),
        accepted: f.accepted,
    }
}

async fn cmd_forward(ctx: &Ctx, args: &crate::cli::ForwardArgs) -> Result<()> {
    match args.action().map_err(|e| anyhow!(e))? {
        ForwardAction::Add => {
            let mut added = Vec::new();
            let mut text = String::new();
            for s in &args.local {
                let spec = ForwardSpec::parse_local(s).map_err(|e| anyhow!(e))?;
                let id = ctx.shared.forwards.add_local(&spec).await?;
                added.push(id);
                let _ = writeln!(text, "forward {id}: -L {s}");
            }
            for s in &args.remote {
                let spec = ForwardSpec::parse_local(s).map_err(|e| anyhow!(e))?;
                let id = ctx.shared.forwards.add_remote(&spec).await?;
                added.push(id);
                let _ = writeln!(text, "forward {id}: -R {s}");
            }
            for s in &args.dynamic {
                let spec = ForwardSpec::parse_dynamic(s).map_err(|e| anyhow!(e))?;
                let id = ctx.shared.forwards.add_dynamic(&spec).await?;
                added.push(id);
                let _ = writeln!(text, "forward {id}: -D {s}");
            }
            let rows: Vec<ForwardRow> = ctx
                .shared
                .forwards
                .list()
                .iter()
                .filter(|f| added.contains(&f.id))
                .map(forward_row)
                .collect();
            ctx.console.report(&rows, || text);
        }
        ForwardAction::List => {
            let list = ctx.shared.forwards.list();
            let rows: Vec<ForwardRow> = list.iter().map(forward_row).collect();
            ctx.console.report(&rows, || {
                if list.is_empty() {
                    return "no forwards\n".to_owned();
                }
                let mut text = String::new();
                for f in &list {
                    let _ = writeln!(text, "{}", format_forward(f));
                }
                text
            });
        }
        ForwardAction::Remove(id) => {
            if !ctx.shared.forwards.remove(id).await {
                bail!("forward rm: no forward {id}");
            }
            ctx.console
                .report(&OkOut::OK, || format!("forward {id} removed\n"));
        }
    }
    Ok(())
}

/// `Open::Info`; `None` when the server does not implement it.
pub async fn server_info(conn: &Connection) -> Result<Option<mysh_proto::info::Info>> {
    use mysh_net::{framing::read_msg, mux::OpenError};
    use mysh_proto::open::{ErrorCode, Open};
    match conn.open(&Open::Info).await {
        Ok(mut stream) => Ok(Some(
            read_msg(&mut stream).await.context("reading server info")?,
        )),
        Err(OpenError::Rejected {
            code: ErrorCode::Unsupported,
            ..
        }) => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context("server info")),
    }
}

async fn cmd_info(ctx: &Ctx) -> Result<()> {
    let conn = &ctx.shared.conn;
    let server = server_info(conn).await?;
    let stats = conn.stats();
    let forwards = ctx.shared.forwards.list();
    let out = InfoOut {
        server,
        connection: ConnectionOut {
            host: conn.target().host.clone(),
            port: conn.target().port,
            peer: conn.peer_addr().to_string(),
            peer_fingerprint: conn.remote_key().fingerprint().to_string(),
            trusted_via: conn.trusted_via().to_owned(),
            our_key: conn.identity().describe(),
            protocol: conn.version(),
            cipher: mysh_proto::NOISE_PATTERN.to_owned(),
            connected_secs: conn.connected_at().elapsed().as_secs(),
            rtt_ms: conn.last_rtt().map(millis),
            bytes_in: stats.bytes_in,
            bytes_out: stats.bytes_out,
            rekeys: stats.rekeys_in + stats.rekeys_out,
        },
        sessions: ctx.session_rows().iter().map(session_row).collect(),
        forwards: forwards.iter().map(forward_row).collect(),
    };
    ctx.console.report(&out, || {
        let rtt = conn.last_rtt().map_or_else(|| "n/a".to_owned(), ms);
        let mut text = format!(
            "server:    {} ({})\n\
             protocol:  v{}\n\
             peer key:  {} (trusted via {})\n\
             our key:   {}\n\
             cipher:    {}\n\
             uptime:    {}\n\
             traffic:   {} in, {} out\n\
             rtt:       {rtt}\n\
             sessions:  {}\n",
            conn.server_hello().name,
            conn.peer_addr(),
            conn.version(),
            conn.remote_key().fingerprint(),
            conn.trusted_via(),
            conn.identity().describe(),
            mysh_proto::NOISE_PATTERN,
            format_duration(conn.connected_at().elapsed()),
            human(stats.bytes_in),
            human(stats.bytes_out),
            out.sessions.len(),
        );
        let _ = writeln!(text, "forwards:  {}", forwards.len());
        for f in &forwards {
            let _ = writeln!(text, "  {}", format_forward(f));
        }
        if let Some(info) = &out.server {
            let denied = if info.limits.denied.is_empty() {
                "none".to_owned()
            } else {
                info.limits.denied.join(", ")
            };
            let _ = write!(
                text,
                "remote:    mysh {} on {} {} (kernel {})\n\
                 \x20          shell {}, home {}, user {}\n\
                 \x20          up {}, idle timeout {}, detach grace {}, denied: {denied}\n",
                info.version,
                info.platform.os,
                info.platform.arch,
                info.platform.kernel,
                info.shell,
                info.home,
                info.user,
                format_duration(Duration::from_secs(info.uptime_secs)),
                format_duration(Duration::from_secs(info.limits.idle_timeout_secs)),
                format_duration(Duration::from_secs(info.limits.detach_grace_secs)),
            );
        }
        text
    });
    Ok(())
}

async fn cmd_ping(ctx: &Ctx, count: u32, term: Option<&mut Terminal>) -> Result<()> {
    let conn = ctx.shared.conn.clone();
    let console = ctx.console.clone();
    let fut = async move {
        let mut rtts = Vec::new();
        for i in 0..count {
            let rtt = conn.ping().await?;
            if !console.mode().is_json() {
                console.println(&format!("pong {}: {}", i + 1, ms(rtt)));
            }
            rtts.push(rtt);
            if i + 1 < count {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        Ok(rtts)
    };
    let Some(rtts) = cancellable(term, fut).await? else {
        ctx.console.println("ping: cancelled");
        return Ok(());
    };
    let min = rtts.iter().min().copied().unwrap_or_default();
    let max = rtts.iter().max().copied().unwrap_or_default();
    let avg = rtts.iter().sum::<Duration>() / u32::try_from(rtts.len()).unwrap_or(1);
    let out = PingOut {
        rtts_ms: rtts.iter().copied().map(millis).collect(),
        min: millis(min),
        avg: millis(avg),
        max: millis(max),
    };
    ctx.console.report(&out, || {
        format!("rtt min/avg/max = {}/{}/{}\n", ms(min), ms(avg), ms(max))
    });
    Ok(())
}

fn cmd_log(ctx: &Ctx, target: &str) -> Result<()> {
    if target == "off" {
        ctx.console.set_log(None);
        ctx.console
            .report(&OkOut::OK, || "logging off\n".to_owned());
        return Ok(());
    }
    let path = resolve_local(ctx, target);
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("log: {}", path.display()))?;
    ctx.console.set_log(Some(file));
    ctx.console
        .report(&OkOut::OK, || format!("logging to {}\n", path.display()));
    Ok(())
}

/// The `--timeout` escalation for an exec session: TERM at the deadline,
/// KILL two seconds later, and if the server still reports nothing (a
/// grandchild holding the output pipes) the client stops waiting one second
/// after that.
#[derive(Debug)]
pub struct ExecTimeout {
    next: Option<tokio::time::Instant>,
    step: u8,
    /// The deadline has passed.
    pub fired: bool,
}

/// What to do when [`ExecTimeout::due`] resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutStep {
    Signal(Signal),
    /// Stop waiting for `Exited`; the session is left to the server.
    Abandon,
}

impl ExecTimeout {
    /// Pause between `Term` and `Kill`.
    pub const KILL_AFTER: Duration = Duration::from_secs(2);
    /// Pause between `Kill` and giving up on the exit report.
    pub const ABANDON_AFTER: Duration = Duration::from_secs(1);

    #[must_use]
    pub fn new(limit: Option<Duration>) -> Self {
        Self {
            next: limit.map(|d| tokio::time::Instant::now() + d),
            step: 0,
            fired: false,
        }
    }

    /// Resolves when the next step is due; never without a limit.
    pub async fn due(&self) {
        match self.next {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }

    /// After [`ExecTimeout::due`]: the step to take now, arming the next.
    pub fn fire(&mut self) -> TimeoutStep {
        self.fired = true;
        self.step += 1;
        let now = tokio::time::Instant::now();
        match self.step {
            1 => {
                self.next = Some(now + Self::KILL_AFTER);
                TimeoutStep::Signal(Signal::Term)
            }
            2 => {
                self.next = Some(now + Self::ABANDON_AFTER);
                TimeoutStep::Signal(Signal::Kill)
            }
            _ => {
                self.next = None;
                TimeoutStep::Abandon
            }
        }
    }
}

/// Build the exec result once the session ended and report it: the JSON
/// document, the `exit` event, or nothing (text mode streams as it goes).
/// Returns the process exit code.
pub fn finish_exec(
    console: &Console,
    status: Option<ExitStatus>,
    started: std::time::Instant,
    timed_out: bool,
) -> i32 {
    let (stdout, stderr) = console.take_exec_capture();
    let (exit, signal) = match status {
        Some(ExitStatus::Code(code)) => (Some(code), None),
        Some(ExitStatus::Signal { signal, .. }) => (None, Some(signal)),
        None => (None, None),
    };
    let result = ExecResult {
        stdout: output::Bytes::new(stdout),
        stderr: output::Bytes::new(stderr),
        exit,
        signal,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        timed_out,
    };
    match console.mode() {
        output::Mode::Json => console.emit(&result),
        output::Mode::JsonStream => console.event(&output::Event::Exit {
            exit,
            signal,
            duration_ms: result.duration_ms,
            timed_out,
        }),
        output::Mode::Human | output::Mode::Plain => {
            if timed_out {
                console.notice("timed out");
            }
        }
    }
    result.code()
}

/// `exec [--timeout D] [--cwd DIR] CMD...`: non-PTY session, output
/// streamed to the console, `Ctrl-C` forwarded as `SIGINT`. Returns the
/// shell-style exit code (124 after a timeout). `stdin` is the input a
/// control-socket request carried along (`None`: the session gets EOF at
/// once, as the prompt's `exec` always did).
pub(crate) async fn exec_command(
    ctx: &mut Ctx,
    command: Vec<String>,
    cwd: Option<String>,
    limit: Option<Duration>,
    stdin: Option<&[u8]>,
    mut term: Option<&mut Terminal>,
) -> Result<i32> {
    let cwd = match cwd {
        Some(dir) => Some(dir),
        None => mru_cwd(ctx).await,
    };
    let label = kind_label(&command);
    let req = session_request(
        ctx.shared.conn.target(),
        SessionKind::Exec { argv: command },
        None,
        cwd,
    );
    let started = std::time::Instant::now();
    // Bytes of an earlier foreground session must not leak into this result.
    let _ = ctx.console.take_exec_capture();
    let id = ctx
        .stack
        .open_session(&ctx.shared.conn, req, &label)
        .await?;
    if let Some(s) = ctx.stack.get(id) {
        ctx.console.event(&output::Event::Started {
            session: id,
            pid: s.pid,
        });
    }
    ctx.stack.foreground(id, None)?;
    if let Some(bytes) = stdin.filter(|b| !b.is_empty()) {
        ctx.stack.send_stdin(id, bytes)?;
    }
    ctx.stack.stdin_eof(id)?;
    let mut deadline = ExecTimeout::new(limit);
    loop {
        tokio::select! {
            ev = ctx.events.recv() => {
                let Some(ev) = ev else { bail!("session events closed") };
                let mine = matches!(ev, Event::Exited { id: eid, .. } | Event::Lost { id: eid } if eid == id);
                ctx.stack.apply(&ev, !mine);
                if mine {
                    return match ev {
                        Event::Exited { status, .. } => {
                            Ok(finish_exec(&ctx.console, Some(status), started, deadline.fired))
                        }
                        Event::Lost { .. } => bail!("exec: connection lost"),
                    };
                }
            }
            () = deadline.due() => match deadline.fire() {
                TimeoutStep::Signal(sig) => {
                    let _ = ctx.stack.signal(id, sig);
                }
                TimeoutStep::Abandon => {
                    let _ = ctx.stack.detach(id);
                    return Ok(finish_exec(&ctx.console, None, started, true));
                }
            },
            inp = next_input(term.as_deref_mut()) => {
                if let Some(Input::Bytes(b)) = inp
                    && b.contains(&0x03) {
                        let _ = ctx.stack.signal(id, Signal::Int);
                    }
            }
            () = ctx.shared.conn.closed() => bail!("exec: connection lost"),
        }
    }
}

/// Apply a pending session event at the prompt; `true` when auto-exit mode
/// should end the client.
fn on_event(ctx: &mut Ctx, ev: &Event) -> bool {
    ctx.stack.apply(ev, true);
    ctx.auto_exit && ctx.stack.is_empty()
}

fn exit_status_hint(status: Option<ExitStatus>) -> String {
    status.map_or_else(|| "n/a".to_owned(), |s| s.to_string())
}

// ---------------------------------------------------------------------------
// Interactive prompt

fn install_hook(console: &Console, render: &Arc<Mutex<String>>) {
    let c = console.clone();
    let r = Arc::clone(render);
    console.set_prompt_hook(Some(Arc::new(move || {
        if let Ok(s) = r.lock() {
            c.print(&s);
        }
    })));
}

fn draw(console: &Console, editor: &LineEditor, render: &Arc<Mutex<String>>) {
    let s = editor.render();
    if let Ok(mut r) = render.lock() {
        r.clone_from(&s);
    }
    console.print(&s);
}

/// Run the prompt until a session is foregrounded or the client should
/// leave. The terminal must be interactive.
pub async fn run_prompt(ctx: &mut Ctx, term: &mut Terminal) -> Outcome {
    let prompt = format!("mysh {}> ", ctx.shared.conn.target().display);
    let mut editor = LineEditor::new(
        &prompt,
        ctx.history.entries().to_vec(),
        ctx.shared.home.clone(),
        ctx.local_cwd.clone(),
    );
    ctx.sync_sessions();
    let render = Arc::new(Mutex::new(String::new()));
    install_hook(&ctx.console, &render);
    draw(&ctx.console, &editor, &render);
    let outcome = prompt_loop(ctx, term, &mut editor, &render).await;
    ctx.console.set_prompt_hook(None);
    outcome
}

async fn prompt_loop(
    ctx: &mut Ctx,
    term: &mut Terminal,
    editor: &mut LineEditor,
    render: &Arc<Mutex<String>>,
) -> Outcome {
    loop {
        let input = tokio::select! {
            inp = term.next() => inp,
            ev = ctx.events.recv() => {
                if let Some(ev) = ev
                    && on_event(ctx, &ev) {
                        return Outcome::Exit;
                    }
                ctx.sync_sessions();
                continue;
            }
            () = ctx.shared.conn.closed() => return Outcome::Disconnect,
        };
        match input {
            Some(Input::Bytes(bytes)) => {
                for edit in editor.feed(&bytes) {
                    match edit {
                        Edit::Line(line) => {
                            ctx.console.print("\r\n");
                            ctx.console.set_prompt_hook(None);
                            ctx.history.push(&line);
                            editor.push_history(&line);
                            let flow = handle_line(ctx, &line, term).await;
                            ctx.sync_sessions();
                            editor.set_cwd(ctx.local_cwd.clone());
                            install_hook(&ctx.console, render);
                            match flow {
                                Flow::Continue => {}
                                Flow::Foreground(id) => return Outcome::Foreground(id),
                                Flow::Exit => return Outcome::Exit,
                                Flow::Disconnect => return Outcome::Disconnect,
                            }
                            if ctx.auto_exit && ctx.stack.is_empty() {
                                return Outcome::Exit;
                            }
                        }
                        Edit::Cancel => ctx.console.print("^C\r\n"),
                        Edit::Eof => {
                            ctx.console.print("\r\n");
                            ctx.console.set_prompt_hook(None);
                            let flow = handle_cmd(ctx, MetaCommand::Exit, term).await;
                            install_hook(&ctx.console, render);
                            if flow == Flow::Exit {
                                return Outcome::Exit;
                            }
                        }
                        Edit::Suspend => {
                            ctx.console.print("\r\n");
                            ctx.console.flush().await;
                            term.suspend();
                        }
                        Edit::ClearScreen => ctx.console.print("\x1b[H\x1b[2J"),
                        Edit::ShowCandidates(items) => {
                            ctx.console.print("\r\n");
                            ctx.console
                                .print(&format_columns(&items, usize::from(term.winsize().cols)));
                        }
                    }
                }
                draw(&ctx.console, editor, render);
            }
            Some(Input::MetaKey) => {
                if let Some(id) = ctx.stack.mru() {
                    ctx.console.print("\r\n");
                    return Outcome::Foreground(id);
                }
                ctx.console.notice("no session to foreground; type `shell`");
            }
            Some(Input::Winch) => draw(&ctx.console, editor, render),
            Some(Input::Eof) | None => {
                ctx.console.print("\r\n");
                if ctx.stack.is_empty() {
                    return Outcome::Exit;
                }
                ctx.console.notice(&format!(
                    "stdin closed with {} session(s) running; disconnecting",
                    ctx.stack.len()
                ));
                return Outcome::Disconnect;
            }
        }
    }
}

/// A clap diagnostic for a prompt line: printed as is (it is the help text
/// for `-h`), or a `usage` error in JSON modes.
fn usage_error(console: &Console, msg: &str) {
    if console.mode().is_json() {
        console.error(&output::coded(codes::USAGE, anyhow!("{}", msg.trim_end())));
        return;
    }
    console.print(msg);
    if !msg.ends_with('\n') {
        console.print("\n");
    }
}

/// Parse and run one prompt line, reporting errors on the console. A
/// trailing `&` starts a background job instead (`client::jobs`).
async fn handle_line(ctx: &mut Ctx, line: &str, term: &mut Terminal) -> Flow {
    match parse_meta_line(line) {
        Ok(None) => Flow::Continue,
        Ok(Some((cmd, false))) => handle_cmd(ctx, cmd, term).await,
        Ok(Some((cmd, true))) => {
            match start_job(ctx, line, cmd) {
                Ok(id) => ctx.console.println(&format!("[{id}] started")),
                Err(e) => ctx.console.error(&e),
            }
            Flow::Continue
        }
        Err(msg) => {
            usage_error(&ctx.console, &msg);
            Flow::Continue
        }
    }
}

/// `LINE &`: run `cmd` as a job; `line` is shown by `jobs` without the `&`.
fn start_job(ctx: &Ctx, line: &str, cmd: MetaCommand) -> Result<u32> {
    if !jobs::backgroundable(&cmd) {
        bail!("only put, get, ls, exec and authorize can run in the background");
    }
    let line = line.trim_end().trim_end_matches('&').trim_end().to_owned();
    Ok(jobs::spawn(&ctx.shared, ctx.local_cwd.clone(), &line, cmd))
}

async fn handle_cmd(ctx: &mut Ctx, cmd: MetaCommand, term: &mut Terminal) -> Flow {
    match execute(ctx, cmd, Some(term)).await {
        Ok(flow) => flow,
        Err(e) => {
            ctx.console.error(&e);
            Flow::Continue
        }
    }
}

// ---------------------------------------------------------------------------
// Scripted frontend

/// `mysh HOST < script`: one command per stdin line, no prompt, stop at the
/// first failure. Exit code per docs/04-sessions.md. A trailing `&` starts
/// a job; at end of input the script waits for running jobs and fails if
/// one of them did.
pub async fn run_script(ctx: &mut Ctx) -> Result<i32> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.context("reading stdin")? else {
                    return Ok(finish_script_jobs(ctx).await);
                };
                let cmd = match parse_meta_line(&line) {
                    Ok(None) => continue,
                    Ok(Some((cmd, false))) => cmd,
                    Ok(Some((cmd, true))) => {
                        if let Err(e) = start_job(ctx, &line, cmd) {
                            ctx.console.error(&e);
                            return Ok(1);
                        }
                        continue;
                    }
                    Err(msg) => {
                        usage_error(&ctx.console, &msg);
                        return Ok(1);
                    }
                };
                debug!(%line, "script command");
                match execute(ctx, cmd, None).await {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Exit | Flow::Disconnect) => return Ok(0),
                    Ok(Flow::Foreground(id)) => {
                        ctx.console.error(&anyhow!("cannot foreground session {id}: stdin is not a terminal"));
                        return Ok(1);
                    }
                    Err(e) => {
                        ctx.console.error(&e);
                        return Ok(if code_for(&e) == codes::TIMEOUT { EXIT_TIMEOUT } else { 1 });
                    }
                }
            }
            ev = ctx.events.recv() => {
                if let Some(ev) = ev {
                    ctx.stack.apply(&ev, true);
                    ctx.sync_sessions();
                }
            }
            () = ctx.shared.conn.closed() => {
                ctx.console.notice(&format!(
                    "connection lost ({})",
                    exit_status_hint(ctx.stack.primary_status())
                ));
                return Ok(255);
            }
        }
    }
}

/// Wait for the script's background jobs; 1 if any failed, else 0.
async fn finish_script_jobs(ctx: &Ctx) -> i32 {
    let jobs = &ctx.shared.jobs;
    if jobs.running() > 0 {
        tokio::select! {
            () = jobs.wait_all() => {}
            () = ctx.shared.conn.closed() => return 255,
        }
    }
    let failed = jobs
        .list()
        .iter()
        .any(|j| !matches!(j.state, jobs::JobState::Done { code: 0 }));
    i32::from(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_labels() {
        assert_eq!(kind_label(&[]), "shell");
        assert_eq!(kind_label(&["htop".to_owned()]), "exec: htop");
    }
}
