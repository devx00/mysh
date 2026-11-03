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
        MetaCommand::Help { cmd } => ctx.console.print(&meta_help(cmd.as_deref())),
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
        | MetaCommand::Authorize(_) => execute_transfer(ctx, cmd, term).await?,
        MetaCommand::Cwd => cmd_cwd(ctx).await,
        MetaCommand::Lcd { dir } => cmd_lcd(ctx, dir.as_deref())?,
        MetaCommand::Forward(args) => cmd_forward(ctx, &args).await?,
        MetaCommand::Exec { command } => {
            let code = exec_command(ctx, command, term).await?;
            ctx.console.println(&format!("[exit {code}]"));
        }
        MetaCommand::Info => cmd_info(ctx),
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
            if ctx.session_count() == 0 {
                ctx.console.println("no sessions");
            } else {
                ctx.console.print(&format_sessions(ctx));
            }
            if all {
                ctx.console.println("server:");
                attach::print_remote(&ctx.shared.conn, &ctx.console).await?;
            }
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
            ctx.console
                .println(&format!("session {id}: {}x{}", ws.cols, ws.rows));
            Ok(Flow::Continue)
        }
        other => bail!("internal: {other:?} is not a session command"),
    }
}

/// File commands; cancellable with `Ctrl-C` at an interactive prompt.
async fn execute_transfer(
    ctx: &mut Ctx,
    cmd: MetaCommand,
    term: Option<&mut Terminal>,
) -> Result<()> {
    let conn = ctx.shared.conn.clone();
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
            ("put", cancellable(term, fut).await?.is_some())
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
            ("get", cancellable(term, fut).await?.is_some())
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
        other => bail!("internal: {other:?} is not a transfer command"),
    };
    if !done {
        ctx.console.println(&format!("{name}: cancelled"));
    }
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
        ctx.console.println(&format!("job {job} cancelled"));
        return Ok(());
    }
    let sig = match signal {
        Some(s) => Signal::parse(s).ok_or_else(|| anyhow!("kill: unknown signal {s:?}"))?,
        None => Signal::Term,
    };
    let id: u32 = id
        .parse()
        .map_err(|_| anyhow!("kill: invalid session id {id:?} (jobs are `%ID`)"))?;
    ctx.signal(id, sig)
}

/// `jobs [-w] [ID]`: list jobs, show one job's state and output, or wait
/// for it.
async fn cmd_jobs(ctx: &Ctx, wait: bool, id: Option<u32>) -> Result<()> {
    let jobs = &ctx.shared.jobs;
    let Some(id) = id else {
        if jobs.list().is_empty() {
            ctx.console.println("no jobs");
        } else {
            ctx.console.print(&jobs.format_list());
        }
        return Ok(());
    };
    if wait {
        jobs.wait(id)
            .await
            .ok_or_else(|| anyhow!("jobs: no job {id}"))?;
    }
    let (info, output) = jobs.get(id).ok_or_else(|| anyhow!("jobs: no job {id}"))?;
    ctx.console
        .println(&format!("job {id} {}: {}", info.state, info.summary()));
    if !output.is_empty() {
        let text = String::from_utf8_lossy(&output);
        ctx.console.print(text.trim_end_matches('\n'));
        ctx.console.print("\n");
    }
    Ok(())
}

async fn cmd_cwd(ctx: &Ctx) {
    let remote = if let Some(id) = ctx.mru() {
        match ctx.shared.conn.cwd_probe(id).await {
            Some(cwd) => format!("{cwd} (session {id})"),
            None => format!("~ (probe failed for session {id}; server home)"),
        }
    } else {
        "~ (no session; server home)".to_owned()
    };
    ctx.console.println(&format!("remote: {remote}"));
    ctx.console
        .println(&format!("local:  {}", ctx.local_cwd.display()));
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

async fn cmd_forward(ctx: &Ctx, args: &crate::cli::ForwardArgs) -> Result<()> {
    match args.action().map_err(|e| anyhow!(e))? {
        ForwardAction::Add => {
            for s in &args.local {
                let spec = ForwardSpec::parse_local(s).map_err(|e| anyhow!(e))?;
                let id = ctx.shared.forwards.add_local(&spec).await?;
                ctx.console.println(&format!("forward {id}: -L {s}"));
            }
            for s in &args.remote {
                let spec = ForwardSpec::parse_local(s).map_err(|e| anyhow!(e))?;
                let id = ctx.shared.forwards.add_remote(&spec).await?;
                ctx.console.println(&format!("forward {id}: -R {s}"));
            }
            for s in &args.dynamic {
                let spec = ForwardSpec::parse_dynamic(s).map_err(|e| anyhow!(e))?;
                let id = ctx.shared.forwards.add_dynamic(&spec).await?;
                ctx.console.println(&format!("forward {id}: -D {s}"));
            }
        }
        ForwardAction::List => {
            let list = ctx.shared.forwards.list();
            if list.is_empty() {
                ctx.console.println("no forwards");
            }
            for f in &list {
                ctx.console.println(&format_forward(f));
            }
        }
        ForwardAction::Remove(id) => {
            if !ctx.shared.forwards.remove(id).await {
                bail!("forward rm: no forward {id}");
            }
            ctx.console.println(&format!("forward {id} removed"));
        }
    }
    Ok(())
}

fn cmd_info(ctx: &Ctx) {
    let conn = &ctx.shared.conn;
    let stats = conn.stats();
    let rtt = conn.last_rtt().map_or_else(|| "n/a".to_owned(), ms);
    let mut out = format!(
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
        ctx.session_count(),
    );
    let forwards = ctx.shared.forwards.list();
    let _ = writeln!(out, "forwards:  {}", forwards.len());
    for f in &forwards {
        let _ = writeln!(out, "  {}", format_forward(f));
    }
    ctx.console.print(&out);
}

async fn cmd_ping(ctx: &Ctx, count: u32, term: Option<&mut Terminal>) -> Result<()> {
    let conn = ctx.shared.conn.clone();
    let console = ctx.console.clone();
    let fut = async move {
        let mut rtts = Vec::new();
        for i in 0..count {
            let rtt = conn.ping().await?;
            console.println(&format!("pong {}: {}", i + 1, ms(rtt)));
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
    ctx.console.println(&format!(
        "rtt min/avg/max = {}/{}/{}",
        ms(min),
        ms(avg),
        ms(max)
    ));
    Ok(())
}

fn cmd_log(ctx: &Ctx, target: &str) -> Result<()> {
    if target == "off" {
        ctx.console.set_log(None);
        ctx.console.println("logging off");
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
        .println(&format!("logging to {}", path.display()));
    Ok(())
}

/// `exec CMD...`: non-PTY session, output streamed to the console, `Ctrl-C`
/// forwarded as `SIGINT`. Returns the shell-style exit code.
async fn exec_command(
    ctx: &mut Ctx,
    command: Vec<String>,
    mut term: Option<&mut Terminal>,
) -> Result<i32> {
    let cwd = mru_cwd(ctx).await;
    let label = kind_label(&command);
    let req = session_request(
        ctx.shared.conn.target(),
        SessionKind::Exec { argv: command },
        None,
        cwd,
    );
    let id = ctx
        .stack
        .open_session(&ctx.shared.conn, req, &label)
        .await?;
    ctx.stack.foreground(id, None)?;
    ctx.stack.stdin_eof(id)?;
    loop {
        tokio::select! {
            ev = ctx.events.recv() => {
                let Some(ev) = ev else { bail!("session events closed") };
                let mine = matches!(ev, Event::Exited { id: eid, .. } | Event::Lost { id: eid } if eid == id);
                ctx.stack.apply(&ev, !mine);
                if mine {
                    return match ev {
                        Event::Exited { status, .. } => Ok(status.shell_code()),
                        Event::Lost { .. } => bail!("exec: connection lost"),
                    };
                }
            }
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

/// Parse and run one prompt line, reporting errors on the console. A
/// trailing `&` starts a background job instead (`client::jobs`).
async fn handle_line(ctx: &mut Ctx, line: &str, term: &mut Terminal) -> Flow {
    match parse_meta_line(line) {
        Ok(None) => Flow::Continue,
        Ok(Some((cmd, false))) => handle_cmd(ctx, cmd, term).await,
        Ok(Some((cmd, true))) => {
            match start_job(ctx, line, cmd) {
                Ok(id) => ctx.console.println(&format!("[{id}] started")),
                Err(e) => ctx.console.println(&format!("error: {e:#}")),
            }
            Flow::Continue
        }
        Err(msg) => {
            ctx.console.print(&msg);
            if !msg.ends_with('\n') {
                ctx.console.print("\n");
            }
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
            ctx.console.println(&format!("error: {e:#}"));
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
                            ctx.console.println(&format!("error: {e:#}"));
                            return Ok(1);
                        }
                        continue;
                    }
                    Err(msg) => {
                        ctx.console.print(&msg);
                        return Ok(1);
                    }
                };
                debug!(%line, "script command");
                match execute(ctx, cmd, None).await {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Exit | Flow::Disconnect) => return Ok(0),
                    Ok(Flow::Foreground(id)) => {
                        ctx.console.println(&format!("error: cannot foreground session {id}: stdin is not a terminal"));
                        return Ok(1);
                    }
                    Err(e) => {
                        ctx.console.println(&format!("error: {e:#}"));
                        return Ok(1);
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
