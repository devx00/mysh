//! The facade: one host, one connection, typed results (docs/07-embedding.md).
//!
//! [`Client::connect`] resolves identities and trust exactly like
//! `mysh HOST` does; the methods then wrap the protocol calls of
//! [`crate::session_api`], [`crate::files`] and [`crate::forward`] and
//! return the same documents the CLI prints with `--json`.

use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use mysh_proto::{
    file::Attrs,
    limits::{READ_MAX, READ_WAIT_MAX},
    session::{ExitStatus, OutStream, Signal, WinSize},
};
use tokio::io::AsyncWrite;

use crate::{
    args::SyncArgs,
    config::{Paths, Target},
    conn::{Connection, connect},
    ctl,
    error::Result,
    files,
    forward::{ForwardKind, Forwards},
    identity::Baked,
    report::{Reporter, TrustPrompt},
    session_api::{self, ApiSessionRow, ExitOut, NewArgs, NewSessionOut, ReadOut},
    sync::{self, SyncOutcome},
    types::{
        Bytes, Event, ExecResult, ForwardRow, HashOut, InfoOut, LsEntry, StatOut, TransferOut,
        coded, codes,
    },
};

/// Grace between TERM and KILL when an exec times out.
const KILL_GRACE: Duration = Duration::from_secs(2);

/// Longest single `Read` wait while polling an exec.
const EXEC_POLL: Duration = Duration::from_secs(2);

/// What [`Client::exec`] runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecRequest {
    /// Command and arguments; a single word runs through the remote shell.
    pub argv: Vec<String>,
    /// Working directory (`~`-relative paths are expanded by the server).
    pub cwd: Option<String>,
    /// Environment variables to send (the server must accept them).
    pub env: Vec<(String, String)>,
    /// Run under a pty of this size (stdout and stderr are then merged).
    pub pty: Option<WinSize>,
    /// Give up after this long: TERM, then KILL after 2 s; `timed_out` is
    /// set on the result.
    pub timeout: Option<Duration>,
    /// Bytes for the process's stdin. Without a pty the stdin is closed
    /// afterwards (also when `None`, so `cat` does not hang).
    pub stdin: Option<Vec<u8>>,
}

impl ExecRequest {
    /// `argv` with everything else default.
    #[must_use]
    pub fn argv<S: Into<String>>(argv: impl IntoIterator<Item = S>) -> Self {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

/// A connection to one host with typed operations on top. Dropping it
/// leaves the connection to close on its own; [`Client::close`] is the
/// graceful way out.
pub struct Client {
    conn: Connection,
    forwards: Forwards,
    reporter: Arc<dyn Reporter>,
    /// How to dial again; `None` for an accepted connection, which the
    /// server re-establishes on its own schedule.
    dial: Option<Dial>,
}

/// What [`Client::reconnect`] needs to open the same connection again.
struct Dial {
    prompt: Arc<dyn TrustPrompt>,
    paths: Paths,
    baked: Baked,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("target", &self.conn.target().display)
            .field("closed", &self.conn.is_closed())
            .field("accepted", &self.dial.is_none())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Connect to `target` with the identities and trust rules of `mysh
    /// HOST` (docs/02-security.md): `reporter` receives notices and
    /// progress, `prompt` decides about an unknown server key.
    pub async fn connect(
        target: &Target,
        paths: &Paths,
        baked: &Baked,
        reporter: Arc<dyn Reporter>,
        prompt: Arc<dyn TrustPrompt>,
    ) -> Result<Self> {
        let conn = connect(target, paths, baked, Arc::clone(&reporter), prompt.as_ref()).await?;
        let forwards = Forwards::new(conn.clone(), Arc::clone(&reporter));
        Ok(Self {
            conn,
            forwards,
            reporter,
            dial: Some(Dial {
                prompt,
                paths: paths.clone(),
                baked: baked.clone(),
            }),
        })
    }

    /// A client on a connection that already exists: one accepted from a
    /// server in connect-back mode ([`crate::accept::Acceptor`] builds
    /// these). Such a client cannot [`Client::reconnect`]; when the
    /// connection ends, the next one arrives when the server dials again.
    #[must_use]
    pub fn from_connection(conn: Connection, reporter: Arc<dyn Reporter>) -> Self {
        let forwards = Forwards::new(conn.clone(), Arc::clone(&reporter));
        Self {
            conn,
            forwards,
            reporter,
            dial: None,
        }
    }

    /// [`Client::connect`] after honouring `target.master`
    /// (docs/05-meta-shell.md "Master mode"): with `auto`/`always` a
    /// background `mysh master` is started for the host first (via `exe`,
    /// the `mysh` binary) so that later CLI calls reuse its control socket;
    /// `always` fails when that is impossible. The client itself then opens
    /// its own connection — the control socket speaks the prompt grammar,
    /// not this API; [`crate::ctl::request`] is the way to use it.
    pub async fn connect_or_ctl(
        target: &Target,
        paths: &Paths,
        baked: &Baked,
        reporter: Arc<dyn Reporter>,
        prompt: Arc<dyn TrustPrompt>,
        exe: &Path,
    ) -> Result<Self> {
        if !target.no_ctl && target.master.spawns() {
            match ctl::ensure(paths, target, None, exe).await {
                Ok(_) => {}
                Err(e) if target.master == crate::config::MasterMode::Always => {
                    return Err(e.context("starting the master").into());
                }
                Err(e) => reporter.notice(&format!("master not started: {e:#}")),
            }
        }
        Self::connect(target, paths, baked, reporter, prompt).await
    }

    /// The connection underneath.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Whether the connection is still up.
    pub fn is_connected(&self) -> bool {
        !self.conn.is_closed()
    }

    /// Open a fresh connection to the same target after the old one was
    /// lost. Forwards do not survive: the new [`Client::forwards`] is empty.
    /// A client built by [`Client::from_connection`] fails with
    /// `connect_failed`: an accepted connection is only re-established by
    /// the server.
    pub async fn reconnect(&mut self) -> Result<()> {
        let Some(dial) = &self.dial else {
            return Err(coded(
                codes::CONNECT_FAILED,
                anyhow::anyhow!(
                    "{} is an accepted connection; the server re-establishes it on its own schedule",
                    self.conn.target().display
                ),
            )
            .into());
        };
        let conn = connect(
            self.conn.target(),
            &dial.paths,
            &dial.baked,
            Arc::clone(&self.reporter),
            dial.prompt.as_ref(),
        )
        .await?;
        self.forwards = Forwards::new(conn.clone(), Arc::clone(&self.reporter));
        self.conn = conn;
        Ok(())
    }

    /// Run `req` and collect its output.
    pub async fn exec(&self, req: ExecRequest) -> Result<ExecResult> {
        self.exec_stream(req, |_| {}).await
    }

    /// Run `req`, handing every event (`started`, `stdout`, `stderr`,
    /// `exit`) to `sink` as it happens; the result collects the same bytes.
    pub async fn exec_stream(
        &self,
        req: ExecRequest,
        mut sink: impl FnMut(Event) + Send,
    ) -> Result<ExecResult> {
        let started_at = Instant::now();
        let args = NewArgs {
            command: req.argv,
            cwd: req.cwd,
            pty: req.pty.is_some(),
            size: req.pty,
            env: req.env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        };
        let started = session_api::session_new(&self.conn, &args).await?;
        sink(Event::Started {
            session: started.id,
            pid: started.pid,
        });
        let stdin = req.stdin.unwrap_or_default();
        if !stdin.is_empty() || req.pty.is_none() {
            session_api::session_send(&self.conn, started.id, &stdin, req.pty.is_none()).await?;
        }
        let mut deadline = Deadline {
            at: req.timeout.map(|d| started_at + d),
            timed_out: false,
            killed_at: None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut offset = 0u64;
        let status: ExitStatus = loop {
            let wait = deadline.tick(&self.conn, started.id).await?;
            let reply =
                session_api::session_read(&self.conn, started.id, offset, READ_MAX, wait).await?;
            offset = reply.next;
            for chunk in reply.chunks {
                match chunk.stream {
                    OutStream::Stdout => {
                        sink(Event::Stdout {
                            data: Bytes::from(chunk.bytes.as_slice()),
                        });
                        stdout.extend_from_slice(&chunk.bytes);
                    }
                    OutStream::Stderr => {
                        sink(Event::Stderr {
                            data: Bytes::from(chunk.bytes.as_slice()),
                        });
                        stderr.extend_from_slice(&chunk.bytes);
                    }
                }
            }
            if let Some(status) = reply.exited {
                break status;
            }
            if self.conn.is_closed() {
                return Err(coded(
                    codes::CONNECT_FAILED,
                    anyhow::anyhow!(
                        "connection lost: {}",
                        self.conn.close_reason().unwrap_or_default()
                    ),
                )
                .into());
            }
        };
        let timed_out = deadline.timed_out;
        let (exit, signal) = match status {
            ExitStatus::Code(code) => (Some(code), None),
            ExitStatus::Signal { signal, .. } => (None, Some(signal)),
        };
        let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        sink(Event::Exit {
            exit,
            signal,
            duration_ms,
            timed_out,
        });
        Ok(ExecResult {
            stdout: Bytes::new(stdout),
            stderr: Bytes::new(stderr),
            exit,
            signal,
            duration_ms,
            timed_out,
        })
    }

    /// `info`: the server's facts, the connection's, and the active
    /// forwards (the `sessions` of the CLI's stack are not a thing here).
    pub async fn info(&self) -> Result<InfoOut> {
        let server = self.conn.info().await?;
        Ok(InfoOut {
            server,
            connection: self.conn.connection_out(),
            sessions: Vec::new(),
            forwards: self.forwards.list().iter().map(forward_row).collect(),
        })
    }

    /// Remote processes addressed by id (docs/05-meta-shell.md "Session
    /// command family").
    pub fn sessions(&self) -> Sessions<'_> {
        Sessions { client: self }
    }

    /// Remote files (docs/04-sessions.md "File transfer", "File primitives").
    pub fn files(&self) -> Files<'_> {
        Files { client: self }
    }

    /// Port forwards (`-L`, `-R`, `-D`).
    pub fn forwards(&self) -> &Forwards {
        &self.forwards
    }

    /// The reporter given to [`Client::connect`].
    pub fn reporter(&self) -> &Arc<dyn Reporter> {
        &self.reporter
    }

    /// Stop the forwards and close the connection gracefully.
    pub async fn close(self) {
        self.forwards.shutdown().await;
        self.conn.close().await;
    }
}

/// The `timeout` of an exec: when it passes the process gets TERM, then
/// KILL after [`KILL_GRACE`]; the read loop keeps draining until the exit.
struct Deadline {
    at: Option<Instant>,
    timed_out: bool,
    killed_at: Option<Instant>,
}

impl Deadline {
    /// Fire what is due and return how long the next read may wait.
    async fn tick(&mut self, conn: &Connection, id: u32) -> Result<Duration> {
        let now = Instant::now();
        let mut wait = EXEC_POLL.min(READ_WAIT_MAX);
        if let Some(at) = self.at
            && !self.timed_out
        {
            let left = at.saturating_duration_since(now);
            if left.is_zero() {
                self.timed_out = true;
                self.killed_at = Some(now);
                session_api::session_kill(conn, id, Signal::Term).await?;
            } else {
                wait = wait.min(left);
            }
        }
        if let Some(at) = self.killed_at
            && now.duration_since(at) >= KILL_GRACE
        {
            self.killed_at = None;
            session_api::session_kill(conn, id, Signal::Kill).await?;
        }
        if self.killed_at.is_some() {
            wait = wait.min(KILL_GRACE);
        }
        Ok(wait)
    }
}

/// `forward ls --json` row of one forward.
fn forward_row(f: &crate::forward::ForwardInfo) -> ForwardRow {
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

/// Remote processes of a [`Client`]: start one that outlives the call,
/// then address it by id (docs/03-protocol.md §10ter).
#[derive(Debug)]
pub struct Sessions<'a> {
    client: &'a Client,
}

impl Sessions<'_> {
    fn conn(&self) -> &Connection {
        &self.client.conn
    }

    /// Start a session; it keeps running until it exits or is killed.
    #[allow(clippy::new_ret_no_self)] // mirrors `session new`
    pub async fn new(&self, args: &NewArgs) -> Result<NewSessionOut> {
        Ok(session_api::session_new(self.conn(), args).await?)
    }

    /// Write `bytes` to the session's stdin; `eof` then closes it
    /// (non-pty sessions).
    pub async fn send(&self, id: u32, bytes: &[u8], eof: bool) -> Result<()> {
        Ok(session_api::session_send(self.conn(), id, bytes, eof).await?)
    }

    /// Output from byte `offset`, at most `max` bytes (capped at 1 MiB),
    /// blocking up to `wait` (capped at 30 s) for new output. The same
    /// offset returns the same bytes until they age out of the server's
    /// ring; `next` is the offset to pass next.
    pub async fn read(&self, id: u32, offset: u64, max: u32, wait: Duration) -> Result<ReadOut> {
        Ok(
            session_api::session_read(self.conn(), id, offset, max, wait)
                .await?
                .into(),
        )
    }

    /// Every session this identity owns on the server.
    pub async fn list(&self) -> Result<Vec<ApiSessionRow>> {
        Ok(session_api::session_list(self.conn())
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Signal the session's process.
    pub async fn kill(&self, id: u32, signal: Signal) -> Result<()> {
        Ok(session_api::session_kill(self.conn(), id, signal).await?)
    }

    /// Wait for the session to exit; `Ok(None)` when `timeout` passes first
    /// (the session keeps running).
    pub async fn wait(&self, id: u32, timeout: Option<Duration>) -> Result<Option<ExitOut>> {
        Ok(session_api::session_wait(self.conn(), id, timeout)
            .await?
            .map(ExitOut::from))
    }
}

/// Remote files of a [`Client`]. Relative paths resolve against the
/// remote home; `~` is expanded by the server.
#[derive(Debug)]
pub struct Files<'a> {
    client: &'a Client,
}

impl Files<'_> {
    fn conn(&self) -> &Connection {
        &self.client.conn
    }

    /// Attributes of `path`; `None` when it does not exist.
    pub async fn stat(&self, path: &str) -> Result<Option<StatOut>> {
        Ok(files::stat(self.conn(), path, None)
            .await?
            .map(|attrs| files::stat_out(path, &attrs)))
    }

    /// The entries of directory `path` (dot files only with `all`), in
    /// name order.
    pub async fn list(&self, path: &str, all: bool) -> Result<Vec<LsEntry>> {
        let mut entries = files::list_all(self.conn(), path, None).await?;
        if !all {
            entries.retain(|e| !e.name.starts_with('.'));
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries.iter().map(files::ls_entry).collect())
    }

    /// Up to `max` bytes of `path` from byte `offset` (everything when
    /// `None`), with the file's attributes.
    pub async fn read(
        &self,
        path: &str,
        offset: u64,
        max: Option<u64>,
    ) -> Result<(Attrs, Vec<u8>)> {
        Ok(files::read_range(self.conn(), path, offset, max, None).await?)
    }

    /// Copy `path` from byte `offset` into `out`; returns the attributes
    /// and the number of bytes written.
    pub async fn read_to<W: AsyncWrite + Unpin>(
        &self,
        path: &str,
        offset: u64,
        out: &mut W,
    ) -> Result<(Attrs, u64)> {
        Ok(files::get_to(self.conn(), path, offset, None, out, &mut |_, _| {}).await?)
    }

    /// Replace `path` atomically with `data` (or append); `mode` applies
    /// to a new file (default 0644). Returns the bytes written.
    pub async fn write(
        &self,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
        append: bool,
    ) -> Result<u64> {
        Ok(files::write_bytes(self.conn(), path, data, mode, append, None).await?)
    }

    /// Upload the regular file `local` as `remote`; with `checksum` an
    /// identical remote file is skipped. Progress goes to the reporter.
    pub async fn put(&self, local: &Path, remote: &str, checksum: bool) -> Result<TransferOut> {
        let reporter = Arc::clone(&self.client.reporter);
        Ok(files::put_file_simple(self.conn(), reporter, local, remote, checksum, None).await?)
    }

    /// Download the regular file `remote` to `local` (temp file + rename);
    /// with `checksum` an identical local copy is skipped.
    pub async fn get(&self, remote: &str, local: &Path, checksum: bool) -> Result<TransferOut> {
        let reporter = Arc::clone(&self.client.reporter);
        Ok(files::get_file_simple(self.conn(), reporter, remote, local, checksum, None).await?)
    }

    /// Create directory `path` (`mode` default 0755); an existing
    /// directory is not an error.
    pub async fn mkdir(&self, path: &str, mode: Option<u32>) -> Result<()> {
        Ok(files::mkdir(
            self.conn(),
            path,
            mode.unwrap_or(files::DEFAULT_DIR_MODE),
            None,
        )
        .await?)
    }

    /// Remove `path`; a directory only with `recursive`.
    pub async fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        Ok(files::remove(self.conn(), path, recursive, None).await?)
    }

    /// Rename `from` to `to` (replacing `to`).
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(files::rename(self.conn(), from, to, None).await?)
    }

    /// The canonical absolute path of `path`.
    pub async fn realpath(&self, path: &str) -> Result<String> {
        Ok(files::realpath(self.conn(), path, None).await?)
    }

    /// Size and BLAKE2s-256 digest of the regular file `path`.
    pub async fn hash(&self, path: &str) -> Result<HashOut> {
        let h = files::hash(self.conn(), path, None).await?;
        Ok(HashOut {
            path: path.to_owned(),
            algo: "blake2s256".to_owned(),
            size: h.size,
            digest: crate::fileops::hex(&h.digest),
        })
    }

    /// The last `lines` lines of `path`.
    pub async fn tail(&self, path: &str, lines: usize) -> Result<Vec<u8>> {
        Ok(files::tail_lines(self.conn(), path, lines, None).await?)
    }

    /// `sync` between a local and a remote tree (`args.pull` picks the
    /// direction); a dry run returns the plan, a real run the summary.
    /// `local_cwd` resolves the local side's relative path.
    pub async fn sync(&self, args: &SyncArgs, local_cwd: &Path) -> Result<SyncOutcome> {
        let reporter = Arc::clone(&self.client.reporter);
        Ok(sync::sync(self.conn(), reporter, args, None, local_cwd).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_request_argv() {
        let r = ExecRequest::argv(["echo", "hi"]);
        assert_eq!(r.argv, vec!["echo", "hi"]);
        assert!(r.timeout.is_none());
    }
}
