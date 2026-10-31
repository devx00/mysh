//! Background jobs (docs/05-meta-shell.md "Background jobs"): a prompt line
//! ending in `&` runs on its own task with a capture console. The table
//! keeps each job's command line, state, last progress and up to
//! [`OUTPUT_CAP`] bytes of what it printed; completion is announced above
//! the prompt.

use std::{
    fmt::Write as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use tokio::{sync::watch, task::AbortHandle};
use tracing::debug;

use super::{
    console::{CaptureEvent, Console, human},
    meta::{Ctx, Flow, execute},
    shared::Shared,
};
use crate::cli::MetaCommand;

/// Captured output kept per job (oldest bytes dropped).
pub const OUTPUT_CAP: usize = 64 * 1024;

/// Where a job is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    Running,
    /// The command returned; `code` is 0 unless it reported a non-zero exit
    /// (`exec`).
    Done {
        code: i32,
    },
    /// The command returned an error.
    Failed {
        msg: String,
    },
    /// `kill %ID`.
    Cancelled,
}

impl JobState {
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

impl std::fmt::Display for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => f.write_str("running"),
            Self::Done { code: 0 } => f.write_str("done"),
            Self::Done { code } => write!(f, "done (exit {code})"),
            Self::Failed { msg } => write!(f, "failed: {msg}"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

/// Last progress event of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub label: String,
    pub done: u64,
    pub total: Option<u64>,
}

/// One row of `jobs`.
#[derive(Debug, Clone)]
pub struct JobInfo {
    pub id: u32,
    /// The prompt line without its `&`.
    pub line: String,
    pub started: Instant,
    pub finished: Option<Instant>,
    pub state: JobState,
    pub progress: Option<Progress>,
}

impl JobInfo {
    pub fn elapsed(&self) -> Duration {
        self.finished
            .unwrap_or_else(Instant::now)
            .duration_since(self.started)
    }

    /// `put a b (2.9 MiB, 1.2 s)`-style summary for notices.
    pub fn summary(&self) -> String {
        let secs = self.elapsed().as_secs_f64();
        match &self.progress {
            Some(p) => format!("{} ({}, {secs:.1} s)", self.line, human(p.done)),
            None => format!("{} ({secs:.1} s)", self.line),
        }
    }
}

struct Job {
    info: JobInfo,
    output: Vec<u8>,
    abort: Option<AbortHandle>,
}

#[derive(Default)]
struct Inner {
    next_id: u32,
    jobs: Vec<Job>,
}

/// The job table; cheap to clone.
#[derive(Clone)]
pub struct Jobs {
    inner: Arc<Mutex<Inner>>,
    /// Bumped on every state change so `wait` can sleep without polling.
    changed: watch::Sender<u64>,
}

impl std::fmt::Debug for Jobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jobs")
            .field("jobs", &self.list().len())
            .finish_non_exhaustive()
    }
}

impl Default for Jobs {
    fn default() -> Self {
        Self::new()
    }
}

impl Jobs {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            changed: watch::Sender::new(0),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut inner)
    }

    fn bump(&self) {
        self.changed.send_modify(|v| *v += 1);
    }

    /// Register a job in state `Running`; ids start at 1.
    pub fn add(&self, line: &str) -> u32 {
        let id = self.with(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            inner.jobs.push(Job {
                info: JobInfo {
                    id,
                    line: line.to_owned(),
                    started: Instant::now(),
                    finished: None,
                    state: JobState::Running,
                    progress: None,
                },
                output: Vec::new(),
                abort: None,
            });
            id
        });
        self.bump();
        id
    }

    /// Give `kill %ID` a handle on the job's task.
    pub fn set_abort(&self, id: u32, abort: AbortHandle) {
        self.with(|inner| {
            if let Some(j) = inner.jobs.iter_mut().find(|j| j.info.id == id) {
                j.abort = Some(abort);
            }
        });
    }

    /// Keep captured bytes, dropping the oldest beyond [`OUTPUT_CAP`].
    pub fn append_output(&self, id: u32, bytes: &[u8]) {
        self.with(|inner| {
            let Some(j) = inner.jobs.iter_mut().find(|j| j.info.id == id) else {
                return;
            };
            j.output.extend_from_slice(bytes);
            if j.output.len() > OUTPUT_CAP {
                let drop = j.output.len() - OUTPUT_CAP;
                j.output.drain(..drop);
            }
        });
    }

    pub fn set_progress(&self, id: u32, progress: Progress) {
        self.with(|inner| {
            if let Some(j) = inner.jobs.iter_mut().find(|j| j.info.id == id) {
                j.info.progress = Some(progress);
            }
        });
    }

    /// Record the final state. Returns the row, or `None` for an unknown id.
    pub fn finish(&self, id: u32, state: JobState) -> Option<JobInfo> {
        let info = self.with(|inner| {
            let j = inner.jobs.iter_mut().find(|j| j.info.id == id)?;
            if j.info.state.is_finished() {
                return Some(j.info.clone());
            }
            j.info.state = state;
            j.info.finished = Some(Instant::now());
            j.abort = None;
            Some(j.info.clone())
        });
        self.bump();
        info
    }

    /// Abort a running job's task; its collector records `Cancelled`.
    pub fn cancel(&self, id: u32) -> Result<()> {
        let abort = self.with(|inner| {
            let j = inner
                .jobs
                .iter()
                .find(|j| j.info.id == id)
                .ok_or_else(|| anyhow!("no job {id}"))?;
            if j.info.state.is_finished() {
                bail!("job {id} is already {}", j.info.state);
            }
            Ok(j.abort.clone())
        })?;
        match abort {
            Some(h) => {
                h.abort();
                Ok(())
            }
            None => bail!("job {id} cannot be cancelled yet"),
        }
    }

    pub fn list(&self) -> Vec<JobInfo> {
        self.with(|inner| inner.jobs.iter().map(|j| j.info.clone()).collect())
    }

    /// The row and its captured output.
    pub fn get(&self, id: u32) -> Option<(JobInfo, Vec<u8>)> {
        self.with(|inner| {
            inner
                .jobs
                .iter()
                .find(|j| j.info.id == id)
                .map(|j| (j.info.clone(), j.output.clone()))
        })
    }

    pub fn running(&self) -> usize {
        self.with(|inner| {
            inner
                .jobs
                .iter()
                .filter(|j| !j.info.state.is_finished())
                .count()
        })
    }

    /// Resolve when job `id` is finished; `None` for an unknown id.
    pub async fn wait(&self, id: u32) -> Option<JobInfo> {
        let mut rx = self.changed.subscribe();
        loop {
            let (info, _) = self.get(id)?;
            if info.state.is_finished() {
                return Some(info);
            }
            if rx.changed().await.is_err() {
                return Some(info);
            }
        }
    }

    /// Resolve when no job is running.
    pub async fn wait_all(&self) {
        let mut rx = self.changed.subscribe();
        while self.running() > 0 {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// `jobs` listing.
    pub fn format_list(&self) -> String {
        let mut out = String::from("  ID   STATE      ELAPSED   COMMAND\n");
        for j in self.list() {
            let state = match &j.state {
                JobState::Running => j.progress.as_ref().map_or_else(
                    || "running".to_owned(),
                    |p| match p.total {
                        Some(t) if t > 0 => format!("{}%", p.done.saturating_mul(100) / t),
                        _ => human(p.done),
                    },
                ),
                JobState::Done { code: 0 } => "done".to_owned(),
                JobState::Done { code } => format!("exit {code}"),
                JobState::Failed { .. } => "failed".to_owned(),
                JobState::Cancelled => "cancelled".to_owned(),
            };
            let _ = writeln!(
                out,
                "  {:<4} {state:<10} {:>7.1} s  {}",
                j.id,
                j.elapsed().as_secs_f64(),
                j.line
            );
        }
        out
    }
}

/// Commands that may run as a job: nothing that needs the terminal or the
/// prompt's own state.
pub fn backgroundable(cmd: &MetaCommand) -> bool {
    matches!(
        cmd,
        MetaCommand::Put(_)
            | MetaCommand::Get(_)
            | MetaCommand::Exec { .. }
            | MetaCommand::Authorize(_)
            | MetaCommand::Ls(_)
    )
}

/// Start `cmd` as a job and return its id. The task runs `execute` with a
/// capture console; a collector keeps its output and progress in the table
/// and prints `[mysh] job N done: …` (plus the captured output) on the
/// prompt console when it finishes.
pub fn spawn(shared: &Arc<Shared>, local_cwd: PathBuf, line: &str, cmd: MetaCommand) -> u32 {
    let jobs = shared.jobs.clone();
    let id = jobs.add(line);
    let (console, mut rx) = Console::capture();
    let mut ctx = Ctx::detached(shared, console, local_cwd);
    let mut run = tokio::spawn(async move {
        let result = execute(&mut ctx, cmd, None).await;
        drop(ctx);
        result
    });
    jobs.set_abort(id, run.abort_handle());
    let notices = shared.console.clone();
    tokio::spawn(async move {
        let record = |ev: CaptureEvent| match ev {
            CaptureEvent::Out(b) | CaptureEvent::Err(b) => jobs.append_output(id, &b),
            CaptureEvent::Progress { label, done, total } => {
                jobs.set_progress(id, Progress { label, done, total });
            }
            CaptureEvent::Done => {}
        };
        // Session reader tasks hold console clones for a moment after the
        // command returns (or is cancelled), so the task's end, not the
        // channel's, decides when the job is over; queued events are kept.
        let joined = loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Some(CaptureEvent::Done) | None => break run.await,
                    Some(ev) => record(ev),
                },
                joined = &mut run => {
                    while let Some(ev) = rx.try_recv() {
                        record(ev);
                    }
                    break joined;
                }
            }
        };
        let state = match joined {
            Ok(Ok(Flow::Continue)) => JobState::Done { code: 0 },
            Ok(Ok(flow)) => JobState::Failed {
                msg: format!("unexpected outcome {flow:?}"),
            },
            Ok(Err(e)) => JobState::Failed {
                msg: format!("{e:#}"),
            },
            Err(e) if e.is_cancelled() => JobState::Cancelled,
            Err(e) => JobState::Failed {
                msg: format!("task failed: {e}"),
            },
        };
        let Some(info) = jobs.finish(id, state) else {
            return;
        };
        debug!(id, state = %info.state, "job finished");
        let mut text = format!("job {id} {}: {}", info.state, info.summary());
        if let Some((_, output)) = jobs.get(id)
            && !output.is_empty()
        {
            text.push('\n');
            text.push_str(String::from_utf8_lossy(&output).trim_end_matches('\n'));
        }
        notices.notice(&text);
    });
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions_and_output_cap() {
        let jobs = Jobs::new();
        assert_eq!(jobs.list().len(), 0);
        let a = jobs.add("put a b");
        let b = jobs.add("get c");
        assert_eq!((a, b), (1, 2));
        assert_eq!(jobs.running(), 2);
        assert_eq!(jobs.list()[0].state, JobState::Running);

        jobs.append_output(a, b"hello\n");
        jobs.append_output(a, &vec![b'x'; OUTPUT_CAP]);
        let (_, out) = jobs.get(a).expect("job a");
        assert_eq!(out.len(), OUTPUT_CAP);
        assert!(out.iter().all(|&c| c == b'x'));

        jobs.set_progress(
            a,
            Progress {
                label: "b".into(),
                done: 10,
                total: Some(20),
            },
        );
        assert!(jobs.format_list().contains("50%"));

        let info = jobs.finish(a, JobState::Done { code: 0 }).expect("row");
        assert_eq!(info.state, JobState::Done { code: 0 });
        assert!(info.finished.is_some());
        assert_eq!(jobs.running(), 1);
        // A second finish does not overwrite the first.
        let info = jobs.finish(a, JobState::Cancelled).expect("row");
        assert_eq!(info.state, JobState::Done { code: 0 });
        assert!(info.summary().starts_with("put a b (10 B, "));

        assert!(jobs.cancel(a).is_err(), "finished jobs cannot be cancelled");
        assert!(jobs.cancel(b).is_err(), "no abort handle yet");
        assert!(jobs.cancel(9).is_err());
        jobs.finish(b, JobState::Failed { msg: "boom".into() });
        assert_eq!(jobs.running(), 0);
        assert!(jobs.get(9).is_none());
        let list = jobs.format_list();
        assert!(list.contains("done") && list.contains("failed"), "{list}");
    }

    #[tokio::test]
    async fn wait_resolves_on_finish() {
        let jobs = Jobs::new();
        let id = jobs.add("exec true");
        let waiter = {
            let jobs = jobs.clone();
            tokio::spawn(async move { jobs.wait(id).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        jobs.finish(id, JobState::Done { code: 3 });
        let info = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter finishes")
            .expect("join")
            .expect("row");
        assert_eq!(info.state, JobState::Done { code: 3 });
        assert!(jobs.wait(42).await.is_none());
        jobs.wait_all().await;
    }

    #[test]
    fn backgroundable_commands() {
        let (cmd, _) = crate::cli::parse_meta_line("put a")
            .expect("parse")
            .expect("cmd");
        assert!(backgroundable(&cmd));
        let (cmd, _) = crate::cli::parse_meta_line("shell")
            .expect("parse")
            .expect("cmd");
        assert!(!backgroundable(&cmd));
    }
}
