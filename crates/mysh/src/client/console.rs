//! Single ordered writer for everything the client puts on the terminal:
//! session output, prompt text, notices, progress lines, and the `log` tee.
//!
//! One background task owns stdout/stderr so writes from the session
//! readers, the prompt, and meta commands never interleave mid-line. In raw
//! mode (`OPOST` off) text writes translate `\n` to `\r\n`; session bytes
//! are never translated because the remote tty already did that.

use std::{
    fs::File,
    io::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::AsyncWriteExt as _,
    sync::{mpsc, oneshot},
};

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
    raw: AtomicBool,
    tty: bool,
    hook: Mutex<Option<Hook>>,
    progress: Mutex<Progress>,
}

/// Cloneable handle to the terminal writer. See the module docs.
#[derive(Clone)]
pub struct Console {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Console {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Console")
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
    /// Spawns the writer task on the current tokio runtime.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer(rx));
        let tty = mysh_pty::terminal::is_terminal(std::io::stdout());
        Self::with_sink(Sink::Terminal(tx), tty)
    }

    /// A console that records instead of printing: every write becomes a
    /// [`CaptureEvent`] on the returned receiver. `is_tty()` is false, so
    /// notices arrive as `Err` and `progress` sends structured updates.
    #[must_use]
    pub fn capture() -> (Self, CaptureRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self::with_sink(Sink::Capture(tx), false),
            CaptureRx { rx, done: false },
        )
    }

    fn with_sink(sink: Sink, tty: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                sink,
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
            }),
        }
    }

    fn is_capture(&self) -> bool {
        matches!(self.inner.sink, Sink::Capture(_))
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

    /// `[mysh] text` on its own line (stderr when stdout is not a terminal),
    /// then the prompt-redraw hook if one is installed. With a hook active
    /// in raw mode the prompt line is cleared first so the notice does not
    /// land mid-line; the hook then repaints the prompt underneath.
    pub fn notice(&self, text: &str) {
        self.end_progress_line();
        let hook = self.inner.hook.lock().ok().and_then(|h| h.clone());
        let mut bytes = Vec::new();
        if hook.is_some() && self.is_raw() {
            bytes.extend_from_slice(b"\r\x1b[K");
        }
        bytes.extend(self.translate(format!("[mysh] {text}").as_bytes()));
        bytes.extend_from_slice(self.newline());
        if self.inner.tty {
            self.send(Op::Out(bytes));
        } else {
            self.send(Op::Err(bytes));
        }
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Raw session output: no translation; tee'd to the log file.
    pub fn write_bytes(&self, bytes: &[u8]) {
        self.send(Op::Out(bytes.to_vec()));
    }

    /// Raw bytes to stderr (exec sessions without a pty).
    pub fn write_stderr(&self, bytes: &[u8]) {
        self.send(Op::Err(bytes.to_vec()));
    }

    /// Start or stop teeing terminal output to `file`.
    pub fn set_log(&self, file: Option<File>) {
        self.send(Op::SetLog(file));
    }

    /// One `\r`-redrawn status line; no-op when stdout is not a terminal.
    /// A capture console forwards every call as a `Progress` event instead
    /// (throttled like the drawn line). Finish with [`Console::progress_done`].
    pub fn progress(&self, label: &str, done: u64, total: Option<u64>) {
        if !self.inner.tty && !self.is_capture() {
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
        match &self.inner.sink {
            Sink::Terminal(_) => {
                if due {
                    p.last_draw = Some(now);
                    self.send(Op::Out(format!("\r\x1b[K{}", p.line).into_bytes()));
                }
            }
            Sink::Capture(tx) => {
                let ev = CaptureEvent::Progress {
                    label: label.to_owned(),
                    done,
                    total,
                };
                if due {
                    p.last_draw = Some(now);
                    let _ = tx.send(ev.clone());
                }
                p.forwarded = due;
                p.latest = Some(ev);
            }
        }
    }

    /// Draw the final state of the progress line and move to a new line. A
    /// capture console forwards the last throttled update instead.
    pub fn progress_done(&self) {
        if !self.inner.tty && !self.is_capture() {
            return;
        }
        let Ok(mut p) = self.inner.progress.lock() else {
            return;
        };
        if p.active {
            match &self.inner.sink {
                Sink::Terminal(_) => {
                    let mut bytes = format!("\r\x1b[K{}", p.line).into_bytes();
                    bytes.extend_from_slice(self.newline());
                    self.send(Op::Out(bytes));
                }
                Sink::Capture(tx) => {
                    if !p.forwarded
                        && let Some(ev) = p.latest.take()
                    {
                        let _ = tx.send(ev);
                    }
                }
            }
        }
        p.active = false;
        p.last_draw = None;
        p.line.clear();
        p.latest = None;
        p.forwarded = false;
    }

    /// Called by [`Console::notice`] after printing, so an active prompt can
    /// redraw itself under the notice.
    pub fn set_prompt_hook(&self, hook: Option<Hook>) {
        if let Ok(mut h) = self.inner.hook.lock() {
            *h = hook;
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
        if !self.inner.tty {
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

/// `1.5 MiB`-style size.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
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
