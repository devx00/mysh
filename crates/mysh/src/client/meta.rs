//! The meta prompt (docs/05-meta-shell.md): a small built-in line editor fed
//! by the stdin reader task, the command dispatcher shared with the
//! scripted frontend (`mysh HOST < script`), and prompt history.
//!
//! The editor is deliberately tiny: the terminal is in raw mode for the
//! whole run and one task owns stdin, so a readline crate would have to be
//! driven byte by byte anyway. Every keystroke redraws the line
//! (`\r`, clear to end of line, prompt, buffer, cursor move), which is
//! correct for lines shorter than the terminal width and good enough here.

use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
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
        conn::Connection,
        console::{Console, human},
        files,
        forward::{ForwardInfo, ForwardKind, Forwards},
        session::{Event, Stack},
        terminal::{Input, Terminal},
    },
    config::{ForwardSpec, Target, decode_send_text, expand_tilde},
};

/// Lines kept in the history file.
pub const HISTORY_CAP: usize = 1000;

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

/// Everything the dispatcher works on; owned by `client::run`.
pub struct Ctx {
    pub conn: Connection,
    pub console: Console,
    pub stack: Stack,
    pub events: mpsc::UnboundedReceiver<Event>,
    pub forwards: Forwards,
    pub history: History,
    /// Client-side working directory for `put`/`get`/`lcd`.
    pub local_cwd: PathBuf,
    pub home: PathBuf,
    /// `-s` / `CMD`: exit when the session list becomes empty.
    pub auto_exit: bool,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("conn", &self.conn)
            .field("sessions", &self.stack.len())
            .field("local_cwd", &self.local_cwd)
            .field("auto_exit", &self.auto_exit)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// History

/// Prompt history, persisted to `paths.history`.
#[derive(Debug)]
pub struct History {
    path: Option<PathBuf>,
    entries: Vec<String>,
    /// Entries added this run (appended on save).
    added: usize,
}

impl History {
    /// Load the last [`HISTORY_CAP`] lines; a missing file is empty history.
    pub fn load(path: &Path) -> Self {
        let text = fs::read_to_string(path).unwrap_or_default();
        Self {
            path: Some(path.to_path_buf()),
            entries: trim_history(text.lines().map(str::to_owned).collect()),
            added: 0,
        }
    }

    /// In-memory only (tests, scripted mode).
    pub fn empty() -> Self {
        Self {
            path: None,
            entries: Vec::new(),
            added: 0,
        }
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Remember `line` unless blank or identical to the previous entry.
    pub fn push(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || self.entries.last().is_some_and(|l| l == line) {
            return;
        }
        self.entries.push(line.to_owned());
        self.added += 1;
    }

    /// Append this run's lines, then trim the file to [`HISTORY_CAP`].
    /// Creates the parent directory `0700`.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if self.added == 0 {
            return Ok(());
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir)?;
        }
        let existing = fs::read_to_string(path).unwrap_or_default();
        let mut all: Vec<String> = existing.lines().map(str::to_owned).collect();
        all.extend(
            self.entries[self.entries.len() - self.added..]
                .iter()
                .cloned(),
        );
        let all = trim_history(all);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        for line in &all {
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

fn trim_history(mut lines: Vec<String>) -> Vec<String> {
    lines.retain(|l| !l.trim().is_empty());
    if lines.len() > HISTORY_CAP {
        lines.drain(..lines.len() - HISTORY_CAP);
    }
    lines
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

// ---------------------------------------------------------------------------
// Line editor

/// What a batch of keystrokes produced besides edits to the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Enter: the finished line.
    Line(String),
    /// `Ctrl-C`: the line was cleared.
    Cancel,
    /// `Ctrl-D` on an empty line.
    Eof,
    /// `Ctrl-Z`.
    Suspend,
    /// `Ctrl-L`.
    ClearScreen,
}

/// A decoded key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Char(char),
    Ctrl(u8),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    Home,
    End,
    Up,
    Down,
}

/// Minimal readline: one line, cursor, history navigation.
#[derive(Debug)]
pub struct LineEditor {
    prompt: String,
    buf: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Index into `history` while browsing; `None` = editing a new line.
    hist_pos: Option<usize>,
    /// The new line stashed while browsing history.
    stash: Vec<char>,
    esc: Vec<u8>,
    utf8: Vec<u8>,
}

impl LineEditor {
    pub fn new(prompt: &str, history: Vec<String>) -> Self {
        Self {
            prompt: prompt.to_owned(),
            buf: Vec::new(),
            cursor: 0,
            history,
            hist_pos: None,
            stash: Vec::new(),
            esc: Vec::new(),
            utf8: Vec::new(),
        }
    }

    pub fn line(&self) -> String {
        self.buf.iter().collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn push_history(&mut self, line: &str) {
        if !line.trim().is_empty() && self.history.last().is_none_or(|l| l != line) {
            self.history.push(line.to_owned());
        }
    }

    /// Terminal bytes that redraw the prompt and line with the cursor placed.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.prompt.len() + self.buf.len() + 16);
        out.push_str("\r\x1b[K");
        out.push_str(&self.prompt);
        out.extend(self.buf.iter());
        let back = self.buf.len() - self.cursor;
        if back > 0 {
            let _ = write!(out, "\x1b[{back}D");
        }
        out
    }

    /// Decode `bytes` (possibly a partial escape or UTF-8 sequence) and apply
    /// the keys; returns the non-edit results in order.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Edit> {
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(key) = self.decode(b)
                && let Some(edit) = self.apply(key)
            {
                out.push(edit);
            }
        }
        out
    }

    fn decode(&mut self, b: u8) -> Option<Key> {
        if !self.esc.is_empty() {
            return self.decode_escape(b);
        }
        if !self.utf8.is_empty() || b >= 0x80 {
            self.utf8.push(b);
            return match std::str::from_utf8(&self.utf8) {
                Ok(s) => {
                    let c = s.chars().next();
                    self.utf8.clear();
                    c.map(Key::Char)
                }
                Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => None,
                Err(_) => {
                    self.utf8.clear();
                    None
                }
            };
        }
        Some(match b {
            0x1b => {
                self.esc.push(b);
                return None;
            }
            b'\r' | b'\n' => Key::Enter,
            0x7f | 0x08 => Key::Backspace,
            0x01..=0x1a => Key::Ctrl(b + 0x40),
            0x20..=0x7e => Key::Char(char::from(b)),
            _ => return None,
        })
    }

    fn decode_escape(&mut self, b: u8) -> Option<Key> {
        match self.esc.as_slice() {
            [0x1b] => {
                if b == b'[' || b == b'O' {
                    self.esc.push(b);
                } else {
                    // Alt+key or a bare ESC: ignored.
                    self.esc.clear();
                }
                None
            }
            [0x1b, b'O'] => {
                self.esc.clear();
                match b {
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    b'H' => Some(Key::Home),
                    b'F' => Some(Key::End),
                    _ => None,
                }
            }
            _ => {
                // CSI: parameters until a final byte in 0x40..=0x7e.
                if (0x40..=0x7e).contains(&b) {
                    let params: String = self.esc[2..].iter().map(|&p| char::from(p)).collect();
                    self.esc.clear();
                    match b {
                        b'A' => Some(Key::Up),
                        b'B' => Some(Key::Down),
                        b'C' => Some(Key::Right),
                        b'D' => Some(Key::Left),
                        b'H' => Some(Key::Home),
                        b'F' => Some(Key::End),
                        b'~' => match params.as_str() {
                            "1" | "7" => Some(Key::Home),
                            "4" | "8" => Some(Key::End),
                            "3" => Some(Key::Delete),
                            _ => None,
                        },
                        _ => None,
                    }
                } else {
                    self.esc.push(b);
                    if self.esc.len() > 16 {
                        self.esc.clear();
                    }
                    None
                }
            }
        }
    }

    fn apply(&mut self, key: Key) -> Option<Edit> {
        match key {
            Key::Char(c) => {
                self.buf.insert(self.cursor, c);
                self.cursor += 1;
            }
            Key::Enter => {
                let line = self.line();
                self.buf.clear();
                self.cursor = 0;
                self.hist_pos = None;
                self.stash.clear();
                return Some(Edit::Line(line));
            }
            Key::Backspace | Key::Ctrl(b'H') => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.buf.remove(self.cursor);
                }
            }
            Key::Delete => {
                if self.cursor < self.buf.len() {
                    self.buf.remove(self.cursor);
                }
            }
            Key::Left | Key::Ctrl(b'B') => self.cursor = self.cursor.saturating_sub(1),
            Key::Right | Key::Ctrl(b'F') => self.cursor = (self.cursor + 1).min(self.buf.len()),
            Key::Home | Key::Ctrl(b'A') => self.cursor = 0,
            Key::End | Key::Ctrl(b'E') => self.cursor = self.buf.len(),
            Key::Up | Key::Ctrl(b'P') => self.history_move(-1),
            Key::Down | Key::Ctrl(b'N') => self.history_move(1),
            Key::Ctrl(b'U') => {
                self.buf.drain(..self.cursor);
                self.cursor = 0;
            }
            Key::Ctrl(b'K') => self.buf.truncate(self.cursor),
            Key::Ctrl(b'W') => {
                let mut start = self.cursor;
                while start > 0 && self.buf[start - 1] == ' ' {
                    start -= 1;
                }
                while start > 0 && self.buf[start - 1] != ' ' {
                    start -= 1;
                }
                self.buf.drain(start..self.cursor);
                self.cursor = start;
            }
            Key::Ctrl(b'D') => {
                if self.buf.is_empty() {
                    return Some(Edit::Eof);
                }
                if self.cursor < self.buf.len() {
                    self.buf.remove(self.cursor);
                }
            }
            Key::Ctrl(b'C') => {
                self.buf.clear();
                self.cursor = 0;
                self.hist_pos = None;
                return Some(Edit::Cancel);
            }
            Key::Ctrl(b'L') => return Some(Edit::ClearScreen),
            Key::Ctrl(b'Z') => return Some(Edit::Suspend),
            Key::Ctrl(_) => {}
        }
        None
    }

    fn history_move(&mut self, delta: i32) {
        if self.history.is_empty() {
            return;
        }
        let next = match (self.hist_pos, delta) {
            (None, d) if d < 0 => Some(self.history.len() - 1),
            (None, _) => return,
            (Some(0), d) if d < 0 => return,
            (Some(i), d) if d < 0 => Some(i - 1),
            (Some(i), _) if i + 1 >= self.history.len() => None,
            (Some(i), _) => Some(i + 1),
        };
        if self.hist_pos.is_none() {
            self.stash = self.buf.clone();
        }
        self.hist_pos = next;
        self.buf = match next {
            Some(i) => self.history[i].chars().collect(),
            None => self.stash.clone(),
        };
        self.cursor = self.buf.len();
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
    let id = ctx.stack.mru()?;
    ctx.conn.cwd_probe(id).await
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
    let p = expand_tilde(path, &ctx.home);
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
    for s in ctx.stack.list() {
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
        | MetaCommand::Sessions
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
        MetaCommand::Sessions => {
            if ctx.stack.is_empty() {
                ctx.console.println("no sessions");
            } else {
                ctx.console.print(&format_sessions(ctx));
            }
            Ok(Flow::Continue)
        }
        MetaCommand::Kill { signal, id } => {
            let sig = match signal {
                Some(s) => {
                    Signal::parse(&s).ok_or_else(|| anyhow!("kill: unknown signal {s:?}"))?
                }
                None => Signal::Term,
            };
            ctx.stack.signal(id, sig)?;
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
    let (name, done) = match cmd {
        MetaCommand::Put(args) => {
            let remote = mru_cwd(ctx).await;
            let fut = files::put(
                &ctx.conn,
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
                &ctx.conn,
                &ctx.console,
                &args,
                remote.as_deref(),
                &ctx.local_cwd,
            );
            ("get", cancellable(term, fut).await?.is_some())
        }
        MetaCommand::Ls(args) => {
            let remote = mru_cwd(ctx).await;
            let fut = files::ls(&ctx.conn, &ctx.console, &args, remote.as_deref());
            ("ls", cancellable(term, fut).await?.is_some())
        }
        MetaCommand::Authorize(args) => {
            let line = pubkey_line(&ctx.conn, args.pubkey.as_deref(), &ctx.home, &ctx.local_cwd)?;
            let fut = files::authorize(&ctx.conn, &ctx.console, &line);
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
    let req = session_request(ctx.conn.target(), kind, Some(ws), cwd);
    ctx.stack
        .open_session(&ctx.conn, req, &kind_label(&args.command))
        .await
}

async fn cmd_cwd(ctx: &Ctx) {
    let remote = if let Some(id) = ctx.stack.mru() {
        match ctx.conn.cwd_probe(id).await {
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
        None => ctx.home.clone(),
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
                let id = ctx.forwards.add_local(&spec).await?;
                ctx.console.println(&format!("forward {id}: -L {s}"));
            }
            for s in &args.remote {
                let spec = ForwardSpec::parse_local(s).map_err(|e| anyhow!(e))?;
                let id = ctx.forwards.add_remote(&spec).await?;
                ctx.console.println(&format!("forward {id}: -R {s}"));
            }
            for s in &args.dynamic {
                let spec = ForwardSpec::parse_dynamic(s).map_err(|e| anyhow!(e))?;
                let id = ctx.forwards.add_dynamic(&spec).await?;
                ctx.console.println(&format!("forward {id}: -D {s}"));
            }
        }
        ForwardAction::List => {
            let list = ctx.forwards.list();
            if list.is_empty() {
                ctx.console.println("no forwards");
            }
            for f in &list {
                ctx.console.println(&format_forward(f));
            }
        }
        ForwardAction::Remove(id) => {
            if !ctx.forwards.remove(id).await {
                bail!("forward rm: no forward {id}");
            }
            ctx.console.println(&format!("forward {id} removed"));
        }
    }
    Ok(())
}

fn cmd_info(ctx: &Ctx) {
    let conn = &ctx.conn;
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
        conn.identity_fingerprint(),
        mysh_proto::NOISE_PATTERN,
        format_duration(conn.connected_at().elapsed()),
        human(stats.bytes_in),
        human(stats.bytes_out),
        ctx.stack.len(),
    );
    let forwards = ctx.forwards.list();
    let _ = writeln!(out, "forwards:  {}", forwards.len());
    for f in &forwards {
        let _ = writeln!(out, "  {}", format_forward(f));
    }
    ctx.console.print(&out);
}

async fn cmd_ping(ctx: &Ctx, count: u32, term: Option<&mut Terminal>) -> Result<()> {
    let conn = ctx.conn.clone();
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
        ctx.conn.target(),
        SessionKind::Exec { argv: command },
        None,
        cwd,
    );
    let id = ctx.stack.open_session(&ctx.conn, req, &label).await?;
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
            () = ctx.conn.closed() => bail!("exec: connection lost"),
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
    let prompt = format!("mysh {}> ", ctx.conn.target().display);
    let mut editor = LineEditor::new(&prompt, ctx.history.entries().to_vec());
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
                continue;
            }
            () = ctx.conn.closed() => return Outcome::Disconnect,
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

/// Parse and run one prompt line, reporting errors on the console.
async fn handle_line(ctx: &mut Ctx, line: &str, term: &mut Terminal) -> Flow {
    match parse_meta_line(line) {
        Ok(None) => Flow::Continue,
        Ok(Some(cmd)) => handle_cmd(ctx, cmd, term).await,
        Err(msg) => {
            ctx.console.print(&msg);
            if !msg.ends_with('\n') {
                ctx.console.print("\n");
            }
            Flow::Continue
        }
    }
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
/// first failure. Exit code per docs/04-sessions.md.
pub async fn run_script(ctx: &mut Ctx) -> Result<i32> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.context("reading stdin")? else {
                    return Ok(0);
                };
                let cmd = match parse_meta_line(&line) {
                    Ok(None) => continue,
                    Ok(Some(cmd)) => cmd,
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
                }
            }
            () = ctx.conn.closed() => {
                ctx.console.notice(&format!(
                    "connection lost ({})",
                    exit_status_hint(ctx.stack.primary_status())
                ));
                return Ok(255);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor() -> LineEditor {
        LineEditor::new("p> ", vec!["first".to_owned(), "second".to_owned()])
    }

    #[test]
    fn insert_and_enter() {
        let mut e = editor();
        assert_eq!(e.feed(b"hel").len(), 0);
        assert_eq!(e.line(), "hel");
        assert_eq!(e.feed(b"lo\r"), vec![Edit::Line("hello".to_owned())]);
        assert_eq!(e.line(), "");
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn backspace_and_cursor_moves() {
        let mut e = editor();
        e.feed(b"abcd");
        e.feed(b"\x7f");
        assert_eq!(e.line(), "abc");
        e.feed(b"\x1b[D\x1b[D"); // left twice
        assert_eq!(e.cursor(), 1);
        e.feed(b"X");
        assert_eq!(e.line(), "aXbc");
        e.feed(b"\x01"); // Ctrl-A
        assert_eq!(e.cursor(), 0);
        e.feed(b"\x05"); // Ctrl-E
        assert_eq!(e.cursor(), 4);
        e.feed(b"\x1b[H");
        assert_eq!(e.cursor(), 0);
        e.feed(b"\x1b[3~"); // Delete
        assert_eq!(e.line(), "Xbc");
        e.feed(b"\x1bOF"); // End
        assert_eq!(e.cursor(), 3);
    }

    #[test]
    fn kill_keys() {
        let mut e = editor();
        e.feed(b"one two three");
        e.feed(b"\x17"); // Ctrl-W
        assert_eq!(e.line(), "one two ");
        e.feed(b"\x1b[D\x1b[D");
        e.feed(b"\x0b"); // Ctrl-K
        assert_eq!(e.line(), "one tw");
        e.feed(b"\x15"); // Ctrl-U
        assert_eq!(e.line(), "");
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn history_navigation() {
        let mut e = editor();
        e.feed(b"new");
        e.feed(b"\x1b[A");
        assert_eq!(e.line(), "second");
        e.feed(b"\x1b[A");
        assert_eq!(e.line(), "first");
        e.feed(b"\x1b[A");
        assert_eq!(e.line(), "first");
        e.feed(b"\x1b[B\x1b[B");
        assert_eq!(e.line(), "new");
        e.push_history("new");
        e.push_history("new");
        assert_eq!(e.history.len(), 3);
    }

    #[test]
    fn control_edits() {
        let mut e = editor();
        assert_eq!(e.feed(b"\x04"), vec![Edit::Eof]);
        e.feed(b"abc");
        assert_eq!(e.feed(b"\x03"), vec![Edit::Cancel]);
        assert_eq!(e.line(), "");
        assert_eq!(e.feed(b"\x0c"), vec![Edit::ClearScreen]);
        assert_eq!(e.feed(b"\x1a"), vec![Edit::Suspend]);
    }

    #[test]
    fn split_escape_and_utf8() {
        let mut e = editor();
        e.feed(b"ab");
        e.feed(b"\x1b");
        e.feed(b"[");
        e.feed(b"D");
        assert_eq!(e.cursor(), 1);
        let euro = "€".as_bytes();
        e.feed(&euro[..1]);
        e.feed(&euro[1..]);
        assert_eq!(e.line(), "a€b");
    }

    #[test]
    fn render_places_cursor() {
        let mut e = editor();
        e.feed(b"abc\x1b[D");
        assert_eq!(e.render(), "\r\x1b[Kp> abc\x1b[1D");
        e.feed(b"\x05");
        assert_eq!(e.render(), "\r\x1b[Kp> abc");
    }

    #[test]
    fn history_push_and_trim() {
        let mut h = History::empty();
        h.push("a");
        h.push("a");
        h.push("  ");
        h.push("b");
        assert_eq!(h.entries(), ["a", "b"]);
        let many: Vec<String> = (0..HISTORY_CAP + 5).map(|i| i.to_string()).collect();
        let trimmed = trim_history(many);
        assert_eq!(trimmed.len(), HISTORY_CAP);
        assert_eq!(trimmed[0], "5");
    }

    #[test]
    fn history_save_round_trip() {
        let dir = std::env::temp_dir().join(format!("mysh-hist-{}", std::process::id()));
        let path = dir.join("history");
        let mut h = History::load(&path);
        assert_eq!(h.entries().len(), 0);
        h.push("ls -l");
        h.push("exit");
        h.save().expect("save history");
        let again = History::load(&path);
        assert_eq!(again.entries(), ["ls -l", "exit"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kind_labels() {
        assert_eq!(kind_label(&[]), "shell");
        assert_eq!(kind_label(&["htop".to_owned()]), "exec: htop");
    }
}
