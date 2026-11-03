//! Single ordered writer for everything the client puts on the terminal:
//! session output, prompt text, notices, progress lines, and the `log` tee.
//!
//! One background task owns stdout/stderr so writes from the session
//! readers, the prompt, and meta commands never interleave mid-line. In raw
//! mode (`OPOST` off) text writes translate `\n` to `\r\n`; session bytes
//! are never translated because the remote tty already did that.
//!
//! The console carries the output [`Mode`] (docs/05-meta-shell.md "Agent
//! interface"): in `Json` mode results go out as one document per command
//! via [`Console::report`] and session bytes are collected for the
//! `ExecResult`; in `JsonStream` mode everything becomes an [`Event`] line.

use std::{
    fs::File,
    future::Future,
    io::Write as _,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use mysh_client::{Reporter, TrustPrompt};
use mysh_net::keys::Fingerprint;
use serde::Serialize;
use tokio::{
    io::AsyncWriteExt as _,
    sync::{mpsc, oneshot},
};

use crate::output::{Bytes, ErrorOut, Event, Mode};

pub use mysh_client::types::human;

/// Minimum interval between two redraws of the progress line.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

enum Op {
    Out(Vec<u8>),
    Err(Vec<u8>),
    SetLog(Option<File>),
    Flush(oneshot::Sender<()>),
}

/// What a capture console produced, in order. The receiving end of
/// [`Console::capture`] yields these; `Done` follows the last event once
/// every clone of the console is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEvent {
    /// Text or session bytes that would have gone to stdout.
    Out(Vec<u8>),
    /// Notices and stderr bytes.
    Err(Vec<u8>),
    /// A progress update (`progress` is never drawn in capture mode).
    Progress {
        label: String,
        done: u64,
        total: Option<u64>,
    },
    /// The console was dropped; nothing follows.
    Done,
}

/// Receiving end of a capture console.
#[derive(Debug)]
pub struct CaptureRx {
    rx: mpsc::UnboundedReceiver<CaptureEvent>,
    done: bool,
}

impl CaptureRx {
    /// Next event; `Done` exactly once after the console is dropped, then
    /// `None`.
    pub async fn recv(&mut self) -> Option<CaptureEvent> {
        if self.done {
            return None;
        }
        let ev = self.rx.recv().await;
        if ev.is_none() {
            self.done = true;
            return Some(CaptureEvent::Done);
        }
        ev
    }

    /// Whatever is already queued, without waiting; `None` when the queue
    /// is empty (or the console is gone — `recv` reports `Done` once).
    pub fn try_recv(&mut self) -> Option<CaptureEvent> {
        if self.done {
            return None;
        }
        self.rx.try_recv().ok()
    }
}

/// Where a console's output goes.
enum Sink {
    /// The writer task owning stdout/stderr.
    Terminal(mpsc::UnboundedSender<Op>),
    /// Structured events for a background job or control-socket request.
    Capture(mpsc::UnboundedSender<CaptureEvent>),
}

type Hook = Arc<dyn Fn() + Send + Sync>;

struct Progress {
    last_draw: Option<Instant>,
    line: String,
    active: bool,
    /// Latest values, whether or not they were forwarded (capture mode
    /// flushes them on `progress_done`).
    latest: Option<CaptureEvent>,
    forwarded: bool,
}

struct Inner {
    sink: Sink,
    mode: Mode,
    raw: AtomicBool,
    tty: bool,
    hook: Mutex<Option<Hook>>,
    progress: Mutex<Progress>,
    /// Session bytes collected in `Json` mode for the exec result.
    exec_capture: Mutex<(Vec<u8>, Vec<u8>)>,
}

/// Cloneable handle to the terminal writer. See the module docs.
#[derive(Clone)]
pub struct Console {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Console {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Console")
            .field("mode", &self.inner.mode)
            .field("tty", &self.inner.tty)
            .field("raw", &self.inner.raw.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}
impl Console {
    /// Spawns the writer task on the current tokio runtime; `Human` on a
    /// terminal, `Plain` otherwise.
    pub fn new() -> Self {
        let tty = mysh_pty::terminal::is_terminal(std::io::stdout());
        Self::with_mode(Mode::select(false, false, false, tty))
    }

    /// Spawns the writer task with an explicit output mode.
    pub fn with_mode(mode: Mode) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer(rx));
        let tty = mysh_pty::terminal::is_terminal(std::io::stdout());
        Self::with_sink(Sink::Terminal(tx), tty, mode)
    }

    /// A console that records instead of printing: every write becomes a
    /// [`CaptureEvent`] on the returned receiver. `is_tty()` is false, so
    /// notices arrive as `Err` and `progress` sends structured updates.
    #[must_use]
    pub fn capture() -> (Self, CaptureRx) {
        Self::capture_with_mode(Mode::Plain)
    }

    /// [`Console::capture`] in an explicit mode: with `Json`/`JsonStream`
    /// the `Out` events carry the JSON lines a terminal console would have
    /// printed (for control-socket requests made with `--json`).
    #[must_use]
    pub fn capture_with_mode(mode: Mode) -> (Self, CaptureRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self::with_sink(Sink::Capture(tx), false, mode),
            CaptureRx { rx, done: false },
        )
    }

    fn with_sink(sink: Sink, tty: bool, mode: Mode) -> Self {
        Self {
            inner: Arc::new(Inner {
                sink,
                mode,
                raw: AtomicBool::new(false),
                tty,
                hook: Mutex::new(None),
                progress: Mutex::new(Progress {
                    last_draw: None,
                    line: String::new(),
                    active: false,
                    latest: None,
                    forwarded: false,
                }),
                exec_capture: Mutex::new((Vec::new(), Vec::new())),
            }),
        }
    }

    fn is_capture(&self) -> bool {
        matches!(self.inner.sink, Sink::Capture(_))
    }

    /// The output mode chosen in `main`.
    pub fn mode(&self) -> Mode {
        self.inner.mode
    }

    /// `Human` mode on a terminal: progress lines and prompt redraws.
    fn draws(&self) -> bool {
        self.inner.tty && self.inner.mode == Mode::Human
    }

    /// A command's result: the JSON document in `Json`/`JsonStream` mode,
    /// else `human()` (which must end with its newline) as text.
    pub fn report<T: Serialize>(&self, value: &T, human: impl FnOnce() -> String) {
        match self.inner.mode {
            Mode::Json => self.emit(value),
            Mode::JsonStream => match serde_json::to_value(value) {
                Ok(value) => self.event(&Event::Result { value }),
                Err(e) => self.error_line(&ErrorOut::new(
                    crate::output::codes::INTERNAL,
                    format!("serializing result: {e}"),
                )),
            },
            Mode::Human | Mode::Plain => self.print(&human()),
        }
    }

    /// One JSON document on stdout (`Json` and `JsonStream` modes only).
    pub fn emit<T: Serialize>(&self, value: &T) {
        if !self.inner.mode.is_json() {
            return;
        }
        match serde_json::to_string(value) {
            Ok(mut line) => {
                line.push('\n');
                self.send(Op::Out(line.into_bytes()));
            }
            Err(e) => self.error_line(&ErrorOut::new(
                crate::output::codes::INTERNAL,
                format!("serializing output: {e}"),
            )),
        }
    }

    /// One NDJSON event on stdout in `JsonStream` mode. In `Json` mode a
    /// notice or error still reaches stderr; everything else is dropped.
    pub fn event(&self, ev: &Event) {
        match self.inner.mode {
            Mode::JsonStream => self.emit(ev),
            Mode::Json => match ev {
                Event::Notice { text } => {
                    self.send(Op::Err(format!("[mysh] {text}\n").into_bytes()));
                }
                Event::Error { code, message } => {
                    self.send(Op::Err(
                        format!("{}\n", ErrorOut::new(code, message.clone()).to_line())
                            .into_bytes(),
                    ));
                }
                _ => {}
            },
            Mode::Human | Mode::Plain => match ev {
                Event::Notice { text } => self.notice(text),
                Event::Error { message, .. } => self.println(&format!("error: {message}")),
                _ => {}
            },
        }
    }

    /// A failed command: `error: …` as text, an [`ErrorOut`] line on stderr
    /// in `Json` mode, an `error` event in `JsonStream` mode.
    pub fn error(&self, err: &anyhow::Error) {
        match self.inner.mode {
            Mode::Json => self.error_line(&ErrorOut::from_error(err)),
            Mode::JsonStream => {
                let out = ErrorOut::from_error(err);
                self.event(&Event::Error {
                    code: out.error.code,
                    message: out.error.message,
                });
            }
            Mode::Human | Mode::Plain => self.println(&format!("error: {err:#}")),
        }
    }

    fn error_line(&self, out: &ErrorOut) {
        self.send(Op::Err(format!("{}\n", out.to_line()).into_bytes()));
    }

    /// Session bytes collected by `write_bytes`/`write_stderr` in `Json`
    /// mode since the last call: `(stdout, stderr)`.
    pub fn take_exec_capture(&self) -> (Vec<u8>, Vec<u8>) {
        self.inner
            .exec_capture
            .lock()
            .map(|mut c| std::mem::take(&mut *c))
            .unwrap_or_default()
    }

    /// Whether stdout is a terminal.
    pub fn is_tty(&self) -> bool {
        self.inner.tty
    }

    /// Raw mode: text writes translate `\n` → `\r\n`.
    pub fn set_raw(&self, raw: bool) {
        self.inner.raw.store(raw, Ordering::Relaxed);
    }

    pub fn is_raw(&self) -> bool {
        self.inner.raw.load(Ordering::Relaxed)
    }

    /// Text to the terminal, newline-translated in raw mode.
    pub fn print(&self, text: &str) {
        self.end_progress_line();
        self.send(Op::Out(self.translate(text.as_bytes())));
    }

    /// `print` plus a newline.
    pub fn println(&self, text: &str) {
        self.end_progress_line();
        let mut bytes = self.translate(text.as_bytes());
        bytes.extend_from_slice(self.newline());
        self.send(Op::Out(bytes));
    }

    /// `[mysh] text` on its own line (stderr unless drawing on a terminal),
    /// then the prompt-redraw hook if one is installed. With a hook active
    /// in raw mode the prompt line is cleared first so the notice does not
    /// land mid-line; the hook then repaints the prompt underneath. In
    /// `JsonStream` mode the notice is an event.
    pub fn notice(&self, text: &str) {
        if self.inner.mode == Mode::JsonStream {
            self.emit(&Event::Notice {
                text: text.to_owned(),
            });
            return;
        }
        self.end_progress_line();
        let hook = self.inner.hook.lock().ok().and_then(|h| h.clone());
        let mut bytes = Vec::new();
        if hook.is_some() && self.is_raw() {
            bytes.extend_from_slice(b"\r\x1b[K");
        }
        bytes.extend(self.translate(format!("[mysh] {text}").as_bytes()));
        bytes.extend_from_slice(self.newline());
        if self.inner.tty && self.inner.mode == Mode::Human {
            self.send(Op::Out(bytes));
        } else {
            self.send(Op::Err(bytes));
        }
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Raw session output: no translation; tee'd to the log file. Collected
    /// in `Json` mode, a `stdout` event in `JsonStream` mode.
    pub fn write_bytes(&self, bytes: &[u8]) {
        match self.inner.mode {
            Mode::Json => {
                if let Ok(mut c) = self.inner.exec_capture.lock() {
                    c.0.extend_from_slice(bytes);
                }
            }
            Mode::JsonStream => self.emit(&Event::Stdout {
                data: Bytes::from(bytes),
            }),
            Mode::Human | Mode::Plain => self.send(Op::Out(bytes.to_vec())),
        }
    }

    /// Raw bytes to stderr (exec sessions without a pty); collected or an
    /// event like [`Console::write_bytes`].
    pub fn write_stderr(&self, bytes: &[u8]) {
        match self.inner.mode {
            Mode::Json => {
                if let Ok(mut c) = self.inner.exec_capture.lock() {
                    c.1.extend_from_slice(bytes);
                }
            }
            Mode::JsonStream => self.emit(&Event::Stderr {
                data: Bytes::from(bytes),
            }),
            Mode::Human | Mode::Plain => self.send(Op::Err(bytes.to_vec())),
        }
    }

    /// Bytes already in final form (control-socket relay): straight to
    /// stdout, no mode handling, no newline translation.
    pub fn write_raw(&self, bytes: &[u8]) {
        self.send(Op::Out(bytes.to_vec()));
    }

    /// [`Console::write_raw`] for stderr.
    pub fn write_raw_err(&self, bytes: &[u8]) {
        self.send(Op::Err(bytes.to_vec()));
    }

    /// Start or stop teeing terminal output to `file`.
    pub fn set_log(&self, file: Option<File>) {
        self.send(Op::SetLog(file));
    }

    /// One `\r`-redrawn status line; no-op unless drawing on a terminal. A
    /// capture console forwards every call as a `Progress` event instead,
    /// and `JsonStream` mode emits `progress` events (both throttled like
    /// the drawn line). Finish with [`Console::progress_done`].
    pub fn progress(&self, label: &str, done: u64, total: Option<u64>) {
        let stream = self.inner.mode == Mode::JsonStream;
        if !self.draws() && !self.is_capture() && !stream {
            return;
        }
        let Ok(mut p) = self.inner.progress.lock() else {
            return;
        };
        let now = Instant::now();
        let due = p
            .last_draw
            .is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL);
        p.line = format_progress(label, done, total);
        p.active = true;
        let ev = CaptureEvent::Progress {
            label: label.to_owned(),
            done,
            total,
        };
        if due {
            p.last_draw = Some(now);
            self.forward_progress(&ev);
        }
        p.forwarded = due;
        p.latest = Some(ev);
    }

    /// Deliver one progress update the way the mode and sink want it.
    fn forward_progress(&self, ev: &CaptureEvent) {
        let CaptureEvent::Progress { label, done, total } = ev else {
            return;
        };
        if self.inner.mode == Mode::JsonStream {
            self.emit(&Event::Progress {
                label: label.clone(),
                done: *done,
                total: *total,
            });
            return;
        }
        match &self.inner.sink {
            Sink::Terminal(_) => {
                let line = format_progress(label, *done, *total);
                self.send(Op::Out(format!("\r\x1b[K{line}").into_bytes()));
            }
            Sink::Capture(tx) => {
                let _ = tx.send(ev.clone());
            }
        }
    }

    /// Draw the final state of the progress line and move to a new line. A
    /// capture console (or `JsonStream` mode) forwards the last throttled
    /// update instead.
    pub fn progress_done(&self) {
        let stream = self.inner.mode == Mode::JsonStream;
        if !self.draws() && !self.is_capture() && !stream {
            return;
        }
        let Ok(mut p) = self.inner.progress.lock() else {
            return;
        };
        if p.active {
            if self.draws() && !stream {
                let mut bytes = format!("\r\x1b[K{}", p.line).into_bytes();
                bytes.extend_from_slice(self.newline());
                self.send(Op::Out(bytes));
            } else if !p.forwarded
                && let Some(ev) = p.latest.take()
            {
                self.forward_progress(&ev);
            }
        }
        p.active = false;
        p.last_draw = None;
        p.line.clear();
        p.latest = None;
        p.forwarded = false;
    }

    /// Called by [`Console::notice`] after printing, so an active prompt can
    /// redraw itself under the notice. Ignored outside `Human` mode.
    pub fn set_prompt_hook(&self, hook: Option<Hook>) {
        if let Ok(mut h) = self.inner.hook.lock() {
            *h = hook.filter(|_| self.inner.mode == Mode::Human);
        }
    }

    /// Resolves once everything queued so far has been written.
    pub async fn flush(&self) {
        let Sink::Terminal(_) = &self.inner.sink else {
            return;
        };
        let (tx, rx) = oneshot::channel();
        self.send(Op::Flush(tx));
        let _ = rx.await;
    }

    fn send(&self, op: Op) {
        // The writer only goes away when the runtime shuts down; dropping
        // output at that point is the correct behaviour.
        match &self.inner.sink {
            Sink::Terminal(tx) => {
                let _ = tx.send(op);
            }
            Sink::Capture(tx) => {
                let ev = match op {
                    Op::Out(b) => CaptureEvent::Out(b),
                    Op::Err(b) => CaptureEvent::Err(b),
                    Op::SetLog(_) => return,
                    Op::Flush(done) => {
                        let _ = done.send(());
                        return;
                    }
                };
                let _ = tx.send(ev);
            }
        }
    }

    fn newline(&self) -> &'static [u8] {
        if self.is_raw() { b"\r\n" } else { b"\n" }
    }

    fn translate(&self, bytes: &[u8]) -> Vec<u8> {
        if !self.is_raw() {
            return bytes.to_vec();
        }
        let mut out = Vec::with_capacity(bytes.len() + 8);
        let mut prev = 0u8;
        for &b in bytes {
            if b == b'\n' && prev != b'\r' {
                out.push(b'\r');
            }
            out.push(b);
            prev = b;
        }
        out
    }

    /// An in-progress status line must not be overprinted by other text.
    fn end_progress_line(&self) {
        if !self.draws() {
            return;
        }
        let Ok(mut p) = self.inner.progress.lock() else {
            return;
        };
        if p.active && p.last_draw.is_some() {
            self.send(Op::Out(b"\r\x1b[K".to_vec()));
            p.last_draw = None;
        }
    }
}

fn format_progress(label: &str, done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) if total > 0 => {
            let pct = done.saturating_mul(100) / total;
            format!("{label}  {}/{}  {pct}%", human(done), human(total))
        }
        _ => format!("{label}  {}", human(done)),
    }
}

/// The library reports through the console: session bytes, notices and
/// progress go through the mode-aware writers; results render as
/// [`Console::report`] does.
impl Reporter for Console {
    fn event(&self, ev: &Event) {
        match ev {
            Event::Stdout { data } => Console::write_bytes(self, data.as_bytes()),
            Event::Stderr { data } => Console::write_stderr(self, data.as_bytes()),
            Event::Notice { text } => Console::notice(self, text),
            Event::Progress { label, done, total } => {
                Console::progress(self, label, *done, *total);
            }
            Event::Started { .. }
            | Event::Exit { .. }
            | Event::Error { .. }
            | Event::Result { .. }
            | Event::Host { .. } => Console::event(self, ev),
        }
    }

    fn is_interactive(&self) -> bool {
        self.is_tty()
    }

    fn mode(&self) -> Mode {
        Console::mode(self)
    }

    fn print(&self, text: &str) {
        Console::print(self, text);
    }

    fn println(&self, text: &str) {
        Console::println(self, text);
    }

    fn result(&self, value: serde_json::Value, human: &mut dyn FnMut() -> String) {
        Console::report(self, &value, human);
    }

    fn emit(&self, value: serde_json::Value) {
        Console::emit(self, &value);
    }

    fn write_raw(&self, bytes: &[u8]) {
        Console::write_raw(self, bytes);
    }

    fn write_raw_err(&self, bytes: &[u8]) {
        Console::write_raw_err(self, bytes);
    }

    fn progress_done(&self) {
        Console::progress_done(self);
    }

    fn take_exec_capture(&self) -> (Vec<u8>, Vec<u8>) {
        Console::take_exec_capture(self)
    }

    fn flush(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(Console::flush(self))
    }

    fn error(&self, err: &anyhow::Error) {
        Console::error(self, err);
    }
}

/// The binary's TOFU prompt: asks on the terminal when stdout and stdin
/// are terminals and the mode is `Human`; otherwise refuses (so `--json`
/// and scripted calls fail with `trust_unknown` instead of hanging).
/// Passphrases come from [`crate::identity::passphrase_prompt`].
#[derive(Debug, Clone)]
pub struct ConsolePrompt {
    console: Console,
}

impl ConsolePrompt {
    /// Prompt on `console`.
    #[must_use]
    pub fn new(console: Console) -> Self {
        Self { console }
    }
}

impl TrustPrompt for ConsolePrompt {
    fn confirm_unknown(&self, host: &str, port: u16, fp: &Fingerprint) -> bool {
        let stdin_tty = mysh_pty::terminal::is_terminal(std::io::stdin());
        if !(self.console.is_tty() && stdin_tty && Console::mode(&self.console) == Mode::Human) {
            return false;
        }
        Console::print(
            &self.console,
            &format!(
                "The authenticity of host {host}:{port} can't be established.\n\
                 Fingerprint {fp}\n\
                 Are you sure you want to continue connecting (yes/no)? "
            ),
        );
        let console = self.console.clone();
        // The handshake is paused on this answer; block this thread rather
        // than the runtime (the prompt is only ever reached from a tty).
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(console.flush());
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map(|_| line)
        });
        answer.is_ok_and(|a| a.trim().eq_ignore_ascii_case("yes"))
    }

    fn passphrase(&self, source: &str) -> std::io::Result<String> {
        crate::identity::passphrase_prompt()(source)
    }
}

async fn writer(mut rx: mpsc::UnboundedReceiver<Op>) {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut log: Option<File> = None;
    while let Some(op) = rx.recv().await {
        match op {
            Op::Out(bytes) => {
                if let Some(f) = log.as_mut() {
                    let _ = f.write_all(&bytes);
                }
                if stdout.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = stdout.flush().await;
            }
            Op::Err(bytes) => {
                let _ = stderr.write_all(&bytes).await;
                let _ = stderr.flush().await;
            }
            Op::SetLog(file) => {
                if let Some(f) = log.as_mut() {
                    let _ = f.flush();
                }
                log = file;
            }
            Op::Flush(done) => {
                let _ = stdout.flush().await;
                let _ = stderr.flush().await;
                if let Some(f) = log.as_mut() {
                    let _ = f.flush();
                }
                let _ = done.send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn translate_only_in_raw_mode() {
        let console = Console::new();
        assert_eq!(console.translate(b"a\nb\r\nc"), b"a\nb\r\nc");
        console.set_raw(true);
        assert_eq!(console.translate(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(1023), "1023 B");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn progress_format() {
        assert_eq!(format_progress("x", 50, Some(200)), "x  50 B/200 B  25%");
        assert_eq!(format_progress("x", 50, None), "x  50 B");
        assert_eq!(format_progress("x", 5, Some(0)), "x  5 B");
    }

    #[tokio::test]
    async fn capture_events_keep_order_and_end_with_done() {
        let (console, mut rx) = Console::capture();
        assert!(!console.is_tty());
        console.println("hello");
        console.notice("note");
        console.progress("f", 10, Some(20));
        // Throttled (within PROGRESS_INTERVAL) but flushed by progress_done.
        console.progress("f", 20, Some(20));
        console.progress_done();
        console.write_stderr(b"e");
        console.flush().await;
        drop(console);
        assert_eq!(
            rx.recv().await,
            Some(CaptureEvent::Out(b"hello\n".to_vec()))
        );
        assert_eq!(
            rx.recv().await,
            Some(CaptureEvent::Err(b"[mysh] note\n".to_vec()))
        );
        assert_eq!(
            rx.recv().await,
            Some(CaptureEvent::Progress {
                label: "f".into(),
                done: 10,
                total: Some(20)
            })
        );
        assert_eq!(
            rx.recv().await,
            Some(CaptureEvent::Progress {
                label: "f".into(),
                done: 20,
                total: Some(20)
            })
        );
        assert_eq!(rx.recv().await, Some(CaptureEvent::Err(b"e".to_vec())));
        assert_eq!(rx.recv().await, Some(CaptureEvent::Done));
        assert_eq!(rx.recv().await, None);
    }
}
