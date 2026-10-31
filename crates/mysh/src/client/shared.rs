//! Connection-wide state shared by the prompt, background jobs
//! (`client::jobs`) and control-socket requests (`client::ctl`): everything
//! a command may need that is not the prompt's own terminal, line editor,
//! or session stack.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use mysh_proto::session::{SessionIn, Signal};
use tokio::sync::mpsc;

use super::{
    conn::Connection,
    console::Console,
    forward::Forwards,
    jobs::Jobs,
    session::{SessionInfo, Stack},
};

/// Cheap-to-clone state behind every [`super::meta::Ctx`] of one connection.
pub struct Shared {
    pub conn: Connection,
    /// The prompt's console: notices from jobs and control requests land
    /// here, above the prompt.
    pub console: Console,
    pub forwards: Forwards,
    pub jobs: Jobs,
    /// Snapshot of the prompt's session stack for contexts that do not own
    /// it.
    pub sessions: SessionView,
    pub home: PathBuf,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("conn", &self.conn)
            .field("jobs", &self.jobs)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Shared {
    pub fn new(conn: Connection, console: Console, forwards: Forwards, home: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            conn,
            console,
            forwards,
            jobs: Jobs::new(),
            sessions: SessionView::default(),
            home,
        })
    }
}

/// A copy of the session rows plus each session's input channel, refreshed
/// by the prompt after every command and event (`Ctx::sync_sessions`), so a
/// job or a control request can run `sessions`, `kill`, `cwd` and `info`
/// without borrowing the stack.
#[derive(Debug, Clone, Default)]
pub struct SessionView {
    inner: Arc<Mutex<Vec<SessionRow>>>,
}

type SessionRow = (SessionInfo, mpsc::UnboundedSender<SessionIn>);

impl SessionView {
    /// Replace the snapshot with the stack's current rows.
    pub fn update(&self, stack: &Stack) {
        let rows = stack
            .list()
            .into_iter()
            .filter_map(|info| {
                let tx = stack.get(info.id)?.tx.clone();
                Some((info, tx))
            })
            .collect();
        if let Ok(mut v) = self.inner.lock() {
            *v = rows;
        }
    }

    /// Rows for `sessions`, MRU first.
    pub fn list(&self) -> Vec<SessionInfo> {
        self.inner
            .lock()
            .map(|v| v.iter().map(|(info, _)| info.clone()).collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |v| v.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Most recently used session id.
    pub fn mru(&self) -> Option<u32> {
        self.inner
            .lock()
            .ok()
            .and_then(|v| v.first().map(|(info, _)| info.id))
    }

    /// `SessionIn::Signal` to session `id`.
    pub fn signal(&self, id: u32, sig: Signal) -> Result<()> {
        let tx = self
            .inner
            .lock()
            .ok()
            .and_then(|v| {
                v.iter()
                    .find(|(info, _)| info.id == id)
                    .map(|(_, tx)| tx.clone())
            })
            .ok_or_else(|| anyhow!("no session {id}"))?;
        tx.send(SessionIn::Signal(sig))
            .map_err(|_| anyhow!("session {id} is gone"))
    }
}
