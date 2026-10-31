//! Client session stack (docs/05-meta-shell.md "Session stack",
//! docs/04-sessions.md "Client terminal driver"): one reader and one writer
//! task per session, a 1 MiB ring buffer for background output, MRU order,
//! and the primary-session bookkeeping behind the process exit code.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_net::framing::{read_msg, write_msg};
use mysh_proto::{
    open::Open,
    session::{ExitStatus, SessionIn, SessionOut, SessionRequest, Signal, WinSize},
};
use tokio::{io::AsyncWriteExt as _, sync::mpsc};
use tracing::debug;

use crate::client::{conn::Connection, console::Console};

/// Background output kept per session.
pub const RING_CAP: usize = 1024 * 1024;

/// Something the main loop must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The server sent `Exited`.
    Exited { id: u32, status: ExitStatus },
    /// The session stream ended without `Exited` (connection lost).
    Lost { id: u32 },
}

/// Bounded byte buffer; the oldest bytes are dropped when full.
#[derive(Debug)]
pub struct Ring {
    buf: VecDeque<u8>,
    cap: usize,
    dropped: usize,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            cap,
            dropped: 0,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= self.cap {
            self.dropped += self.buf.len() + bytes.len() - self.cap;
            self.buf.clear();
            self.buf.extend(&bytes[bytes.len() - self.cap..]);
            return;
        }
        let overflow = (self.buf.len() + bytes.len()).saturating_sub(self.cap);
        if overflow > 0 {
            self.buf.drain(..overflow);
            self.dropped += overflow;
        }
        self.buf.extend(bytes);
    }

    /// Buffered bytes and the drop counter; both are reset.
    pub fn take(&mut self) -> (Vec<u8>, usize) {
        let dropped = std::mem::take(&mut self.dropped);
        (std::mem::take(&mut self.buf).into(), dropped)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn dropped(&self) -> usize {
        self.dropped
    }
}

/// Shared between a session's reader task and the stack. The foreground
/// flag lives under the same lock as the ring so a switch (flush ring, then
/// start writing live) cannot reorder bytes.
#[derive(Debug)]
struct Output {
    ring: Ring,
    foreground: bool,
}

/// One session as seen by the client.
#[derive(Debug)]
pub struct Session {
    pub id: u32,
    pub pid: u32,
    /// `shell` or `exec: CMD`.
    pub kind: String,
    pub tx: mpsc::UnboundedSender<SessionIn>,
    out: Arc<Mutex<Output>>,
}

impl Session {
    pub fn is_foreground(&self) -> bool {
        self.out.lock().is_ok_and(|o| o.foreground)
    }

    pub fn buffered(&self) -> usize {
        self.out.lock().map_or(0, |o| o.ring.len())
    }

    fn set_foreground(&self, fg: bool) {
        if let Ok(mut o) = self.out.lock() {
            o.foreground = fg;
        }
    }

    fn send(&self, msg: SessionIn) -> Result<()> {
        self.tx
            .send(msg)
            .map_err(|_| anyhow!("session {} is gone", self.id))
    }
}

/// `sessions` listing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u32,
    pub pid: u32,
    pub kind: String,
    pub buffered: usize,
    /// Most recently used.
    pub mru: bool,
    pub foreground: bool,
}

/// All sessions of one connection, most recently used first.
#[derive(Debug)]
pub struct Stack {
    console: Console,
    sessions: Vec<Session>,
    fg: Option<u32>,
    primary: Option<u32>,
    primary_status: Option<ExitStatus>,
    events: mpsc::UnboundedSender<Event>,
}

impl Stack {
    /// The returned receiver delivers [`Event`]s from the reader tasks.
    pub fn new(console: Console) -> (Self, mpsc::UnboundedReceiver<Event>) {
        let (events, rx) = mpsc::unbounded_channel();
        (
            Self {
                console,
                sessions: Vec::new(),
                fg: None,
                primary: None,
                primary_status: None,
                events,
            },
            rx,
        )
    }

    /// Open `Open::Session(req)`, wait for `Started`, spawn the reader and
    /// writer tasks. The new session is inserted as most recently used but
    /// not foregrounded. Returns the server's session id.
    pub async fn open_session(
        &mut self,
        conn: &Connection,
        req: SessionRequest,
        kind_label: &str,
    ) -> Result<u32> {
        let mut stream = conn
            .open(&Open::Session(req))
            .await
            .context("opening session")?;
        let started: SessionOut = read_msg(&mut stream).await.context("waiting for Started")?;
        let SessionOut::Started {
            session: id,
            pid,
            cwd_fallback,
        } = started
        else {
            bail!("session stream: expected Started, got {started:?}");
        };
        if cwd_fallback {
            self.console.notice(&format!(
                "session {id}: requested cwd unusable, started in home"
            ));
        }
        let out = Arc::new(Mutex::new(Output {
            ring: Ring::new(RING_CAP),
            foreground: false,
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        let (rd, wr) = tokio::io::split(stream);
        tokio::spawn(reader(
            id,
            rd,
            Arc::clone(&out),
            self.console.clone(),
            self.events.clone(),
        ));
        tokio::spawn(writer(id, wr, rx));
        self.sessions.insert(
            0,
            Session {
                id,
                pid,
                kind: kind_label.to_owned(),
                tx,
                out,
            },
        );
        debug!(id, pid, kind = kind_label, "session started");
        Ok(id)
    }

    fn index(&self, id: u32) -> Result<usize> {
        self.sessions
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| anyhow!("no session {id}"))
    }

    pub fn get(&self, id: u32) -> Option<&Session> {
        self.sessions.iter().find(|s| s.id == id)
    }

    /// Most recently used session id.
    pub fn mru(&self) -> Option<u32> {
        self.sessions.first().map(|s| s.id)
    }

    pub fn fg(&self) -> Option<u32> {
        self.fg
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Mark `id` as the session whose status becomes the process exit code.
    pub fn set_primary(&mut self, id: u32) {
        self.primary = Some(id);
    }

    pub fn primary(&self) -> Option<u32> {
        self.primary
    }

    /// Status of the primary session once it has exited.
    pub fn primary_status(&self) -> Option<ExitStatus> {
        self.primary_status
    }

    /// Bring `id` to the foreground: move it to the MRU head, replay its ring
    /// to the terminal (reporting dropped bytes), send `Resize(ws)`.
    pub fn foreground(&mut self, id: u32, ws: Option<WinSize>) -> Result<()> {
        let idx = self.index(id)?;
        if let Some(prev) = self.fg.take()
            && let Some(s) = self.get(prev)
        {
            s.set_foreground(false);
        }
        let session = self.sessions.remove(idx);
        self.sessions.insert(0, session);
        let session = &self.sessions[0];
        {
            let mut out = session
                .out
                .lock()
                .map_err(|_| anyhow!("session {id} output lock poisoned"))?;
            let (bytes, dropped) = out.ring.take();
            if dropped > 0 {
                self.console
                    .notice(&format!("{dropped} bytes of output dropped"));
            }
            if !bytes.is_empty() {
                self.console.write_bytes(&bytes);
            }
            out.foreground = true;
        }
        self.fg = Some(id);
        if let Some(ws) = ws {
            let _ = session.send(SessionIn::Resize(ws));
        }
        Ok(())
    }

    /// Send the foreground session (if any) to the background; its output
    /// goes to the ring from now on.
    pub fn background(&mut self) {
        if let Some(id) = self.fg.take()
            && let Some(s) = self.get(id)
        {
            s.set_foreground(false);
        }
    }

    pub fn send_stdin(&self, id: u32, bytes: &[u8]) -> Result<()> {
        self.sessions[self.index(id)?].send(SessionIn::Stdin(bytes.to_vec()))
    }

    pub fn stdin_eof(&self, id: u32) -> Result<()> {
        self.sessions[self.index(id)?].send(SessionIn::StdinEof)
    }

    pub fn resize(&self, id: u32, ws: WinSize) -> Result<()> {
        self.sessions[self.index(id)?].send(SessionIn::Resize(ws))
    }

    pub fn signal(&self, id: u32, sig: Signal) -> Result<()> {
        self.sessions[self.index(id)?].send(SessionIn::Signal(sig))
    }

    /// Rows for `sessions`, MRU first.
    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .enumerate()
            .map(|(i, s)| SessionInfo {
                id: s.id,
                pid: s.pid,
                kind: s.kind.clone(),
                buffered: s.buffered(),
                mru: i == 0,
                foreground: self.fg == Some(s.id),
            })
            .collect()
    }

    /// Apply an [`Event`]: remove the session, remember the primary's
    /// status, and (when `announce`) print the notice. Returns whether it
    /// was the foreground one.
    pub fn apply(&mut self, event: &Event, announce: bool) -> bool {
        let (id, status) = match event {
            Event::Exited { id, status } => (*id, Some(*status)),
            Event::Lost { id } => (*id, None),
        };
        let Ok(idx) = self.index(id) else {
            return false;
        };
        let session = self.sessions.remove(idx);
        let was_fg = self.fg == Some(id);
        if was_fg {
            self.fg = None;
        }
        if self.primary == Some(id) {
            self.primary_status = status;
        }
        if announce {
            match status {
                Some(st) => self.console.notice(&format!("session {id} exited: {st}")),
                None => self
                    .console
                    .notice(&format!("session {id} lost: connection closed")),
            }
        }
        debug!(id, pid = session.pid, "session removed");
        was_fg
    }
}

async fn reader(
    id: u32,
    mut rd: tokio::io::ReadHalf<mysh_net::mux::Stream>,
    out: Arc<Mutex<Output>>,
    console: Console,
    events: mpsc::UnboundedSender<Event>,
) {
    loop {
        match read_msg::<_, SessionOut>(&mut rd).await {
            Ok(SessionOut::Stdout(bytes)) => {
                let Ok(mut o) = out.lock() else { break };
                if o.foreground {
                    console.write_bytes(&bytes);
                } else {
                    o.ring.push(&bytes);
                }
            }
            Ok(SessionOut::Stderr(bytes)) => console.write_stderr(&bytes),
            Ok(SessionOut::Exited(status)) => {
                let _ = events.send(Event::Exited { id, status });
                return;
            }
            Ok(SessionOut::Started { .. } | SessionOut::Attached { .. }) => {
                debug!(id, "duplicate start message ignored");
            }
            Err(e) => {
                debug!(id, error = %e, "session stream ended");
                let _ = events.send(Event::Lost { id });
                return;
            }
        }
    }
    let _ = events.send(Event::Lost { id });
}

async fn writer(
    id: u32,
    mut wr: tokio::io::WriteHalf<mysh_net::mux::Stream>,
    mut rx: mpsc::UnboundedReceiver<SessionIn>,
) {
    while let Some(msg) = rx.recv().await {
        if let Err(e) = write_msg(&mut wr, &msg).await {
            debug!(id, error = %e, "session write failed");
            break;
        }
    }
    let _ = wr.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_caps_and_counts_drops() {
        let mut r = Ring::new(8);
        r.push(b"abcde");
        assert_eq!(r.len(), 5);
        assert_eq!(r.dropped(), 0);
        r.push(b"fghij");
        assert_eq!(r.len(), 8);
        assert_eq!(r.dropped(), 2);
        let (bytes, dropped) = r.take();
        assert_eq!(bytes, b"cdefghij");
        assert_eq!(dropped, 2);
        assert!(r.is_empty());
        assert_eq!(r.dropped(), 0);
    }

    #[test]
    fn ring_oversized_push_keeps_tail() {
        let mut r = Ring::new(4);
        r.push(b"xy");
        r.push(b"0123456789");
        let (bytes, dropped) = r.take();
        assert_eq!(bytes, b"6789");
        assert_eq!(dropped, 8);
    }

    fn fake_session(id: u32) -> Session {
        let (tx, _rx) = mpsc::unbounded_channel();
        Session {
            id,
            pid: 100 + id,
            kind: "shell".to_owned(),
            tx,
            out: Arc::new(Mutex::new(Output {
                ring: Ring::new(16),
                foreground: false,
            })),
        }
    }

    #[tokio::test]
    async fn foreground_moves_to_mru_head() {
        let (mut stack, _events) = Stack::new(Console::new());
        stack.sessions.push(fake_session(1));
        stack.sessions.push(fake_session(2));
        stack.sessions.push(fake_session(3));
        assert_eq!(stack.mru(), Some(1));
        stack
            .foreground(3, Some(WinSize::default()))
            .expect("session 3 exists");
        assert_eq!(stack.mru(), Some(3));
        assert_eq!(stack.fg(), Some(3));
        let ids: Vec<u32> = stack.list().iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![3, 1, 2]);
        assert!(stack.list()[0].mru);
        assert!(stack.list()[0].foreground);
        stack.foreground(2, None).expect("session 2 exists");
        let ids: Vec<u32> = stack.list().iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![2, 3, 1]);
        assert!(!stack.get(3).is_some_and(Session::is_foreground));
        assert!(stack.foreground(9, None).is_err());
    }

    #[tokio::test]
    async fn apply_removes_and_records_primary() {
        let (mut stack, _events) = Stack::new(Console::new());
        stack.sessions.push(fake_session(1));
        stack.sessions.push(fake_session(2));
        stack.set_primary(1);
        stack
            .foreground(1, Some(WinSize::default()))
            .expect("session 1 exists");
        let was_fg = stack.apply(
            &Event::Exited {
                id: 1,
                status: ExitStatus::Code(3),
            },
            true,
        );
        assert!(was_fg);
        assert_eq!(stack.fg(), None);
        assert_eq!(stack.primary_status(), Some(ExitStatus::Code(3)));
        assert_eq!(stack.len(), 1);
        assert!(!stack.apply(&Event::Lost { id: 2 }, false));
        assert!(stack.is_empty());
    }
}
