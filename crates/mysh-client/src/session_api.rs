//! Remote process API, client side (docs/03-protocol.md §10ter,
//! docs/05-meta-shell.md "Session command family"): start a session that
//! outlives the stream that opened it, then address it by id — read its
//! output from an absolute byte offset, write to its stdin, signal it, wait
//! for it.
//!
//! Every call is a short-lived stream on an existing connection, so the
//! same connection (a prompt, a master, or a one-shot CLI call) serves any
//! number of sessions.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use mysh_net::framing::read_msg;
use mysh_proto::{
    limits::{READ_MAX, READ_WAIT_MAX},
    open::Open,
    session::{
        Chunk, DetachedSession, ExitStatus, OutStream, PtyRequest, ReadReply, SessionKind,
        SessionOut, SessionRequest, Signal, WinSize,
    },
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    args::{SessionArgs, SessionCmd, SessionNewArgs, SessionReadArgs, SessionSendArgs},
    config::{Target, decode_send_text},
    conn::Connection,
    report::Reporter,
    types::{Bytes, EXIT_TIMEOUT, OkOut},
};

/// Window size for `session new --pty`; a session without a terminal has no
/// size of its own and can be resized later by an attaching client.
const API_PTY_SIZE: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

/// Default `--wait` for `session read --follow`.
const FOLLOW_WAIT: Duration = Duration::from_secs(2);

/// How long to wait for the server to acknowledge a `session send`.
const SEND_ACK: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// JSON shapes

/// `session new --json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NewSessionOut {
    /// Session id.
    pub id: u32,
    /// Pid of the remote child.
    pub pid: u32,
}

/// One chunk of `session read --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChunkOut {
    /// `stdout` or `stderr`.
    pub stream: String,
    /// The bytes.
    pub data: Bytes,
}

/// How a session ended, as JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExitOut {
    /// Exit code, when the process exited normally.
    pub exit: Option<i32>,
    /// Signal number, when a signal killed it.
    pub signal: Option<i32>,
}

impl From<ExitStatus> for ExitOut {
    fn from(status: ExitStatus) -> Self {
        match status {
            ExitStatus::Code(code) => Self {
                exit: Some(code),
                signal: None,
            },
            ExitStatus::Signal { signal, .. } => Self {
                exit: None,
                signal: Some(signal),
            },
        }
    }
}

/// `session read --json`: one object per read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReadOut {
    /// Offset of the first byte returned.
    pub offset: u64,
    /// Offset to pass next.
    pub next: u64,
    /// Oldest offset the server still has.
    pub oldest: u64,
    /// Output in order.
    pub chunks: Vec<ChunkOut>,
    /// Set once the session has ended.
    pub exited: Option<ExitOut>,
}

impl From<ReadReply> for ReadOut {
    fn from(reply: ReadReply) -> Self {
        Self {
            offset: reply.offset,
            next: reply.next,
            oldest: reply.oldest,
            chunks: reply
                .chunks
                .into_iter()
                .map(|Chunk { stream, bytes }| ChunkOut {
                    stream: stream_name(stream).to_owned(),
                    data: Bytes::new(bytes),
                })
                .collect(),
            exited: reply.exited.map(ExitOut::from),
        }
    }
}

/// One row of `session list --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApiSessionRow {
    /// Session id.
    pub id: u32,
    /// Pid of the remote child.
    pub pid: u32,
    /// `shell` or the command line.
    pub kind: String,
    /// Unix seconds.
    pub started: i64,
    /// Unix seconds; `None` while a client stream serves it.
    pub detached: Option<i64>,
    /// Whether it runs in a pty.
    pub pty: bool,
    /// Output bytes not yet handed to a session stream.
    pub buffered: u64,
    /// Total bytes the session ever produced.
    pub next: u64,
    /// Oldest offset still readable.
    pub oldest: u64,
    /// Set once the session has ended.
    pub exited: Option<ExitOut>,
}

impl From<DetachedSession> for ApiSessionRow {
    fn from(row: DetachedSession) -> Self {
        Self {
            id: row.id,
            pid: row.pid,
            kind: row.kind,
            started: row.started,
            detached: row.detached,
            pty: row.pty,
            buffered: row.buffered,
            next: row.next,
            oldest: row.oldest,
            exited: row.exited.map(ExitOut::from),
        }
    }
}

/// `session list --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionListOut {
    /// Rows, as the server listed them.
    pub sessions: Vec<ApiSessionRow>,
}

/// `session wait --json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WaitOut {
    /// Session id.
    pub id: u32,
    /// Exit code, when the process exited normally.
    pub exit: Option<i32>,
    /// Signal number, when a signal killed it.
    pub signal: Option<i32>,
    /// `timeout` passed before the session ended.
    pub timed_out: bool,
}

fn stream_name(stream: OutStream) -> &'static str {
    match stream {
        OutStream::Stdout => "stdout",
        OutStream::Stderr => "stderr",
    }
}

// ---------------------------------------------------------------------------
// Protocol calls

/// What `session_new` was asked to start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewArgs {
    /// Command and arguments; one element runs through the remote shell.
    pub command: Vec<String>,
    /// Working directory; the server falls back to home when unusable.
    pub cwd: Option<String>,
    /// Run in a pty.
    pub pty: bool,
    /// Extra `NAME[=VALUE]` items beyond the connection's environment
    /// (`NAME` alone reads this process's environment).
    pub env: Vec<String>,
    /// Window size of a `pty` session; the 80x24 default when `None`.
    pub size: Option<WinSize>,
}

impl NewArgs {
    /// From the `session new` CLI arguments (`size` stays `None`).
    #[must_use]
    pub fn from_cli(args: &SessionNewArgs) -> Self {
        Self {
            command: args.command.clone(),
            cwd: args.cwd.clone(),
            pty: args.pty,
            env: args.env.clone(),
            size: None,
        }
    }
}

/// `Open::Session` with `persist: true`: the session is registered on the
/// server, so dropping this stream leaves it running (for a PTY session
/// that drop is a detach) and `read`/`send`/`kill`/`wait` address it by id.
pub async fn session_new(conn: &Connection, args: &NewArgs) -> Result<NewSessionOut> {
    if args.command.is_empty() {
        bail!("session new: missing command");
    }
    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: args.command.clone(),
        },
        env: new_env(conn.target(), &args.env),
        pty: args.pty.then(|| PtyRequest {
            term: term_name(),
            size: args.size.unwrap_or(API_PTY_SIZE),
        }),
        cwd: args.cwd.clone(),
        persist: true,
    };
    let mut stream = conn
        .open(&Open::Session(req))
        .await
        .context("starting the session")?;
    let started: SessionOut = read_msg(&mut stream)
        .await
        .context("reading the session header")?;
    let SessionOut::Started { session, pid, .. } = started else {
        bail!("unexpected session header {started:?}");
    };
    // Dropping the stream leaves the session registered on the server.
    drop(stream);
    Ok(NewSessionOut { id: session, pid })
}

/// Environment to send: `LANG`, `LC_*`, `COLORTERM` from this process's
/// environment, plus the target's `env` items (`NAME` alone reads the
/// local value).
#[must_use]
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

/// This process's `$TERM`, or `xterm-256color` when unset or empty.
#[must_use]
pub fn term_name() -> String {
    std::env::var("TERM")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "xterm-256color".to_owned())
}

/// The connection's environment plus this command's `--env` items.
fn new_env(target: &Target, extra: &[String]) -> Vec<(String, String)> {
    let mut env = session_env(target);
    for item in extra {
        let (name, value) = match item.split_once('=') {
            Some((n, v)) => (n.to_owned(), v.to_owned()),
            None => match std::env::var(item) {
                Ok(v) => (item.clone(), v),
                Err(_) => continue,
            },
        };
        env.retain(|(k, _)| *k != name);
        env.push((name, value));
    }
    env
}

/// `Open::Read`: output from `offset`, at most `max` bytes, blocking up to
/// `wait` for new output. Idempotent: the same offset returns the same
/// bytes until they age out of the server's ring.
pub async fn session_read(
    conn: &Connection,
    id: u32,
    offset: u64,
    max: u32,
    wait: Duration,
) -> Result<ReadReply> {
    let wait_ms = u32::try_from(wait.min(READ_WAIT_MAX).as_millis()).unwrap_or(u32::MAX);
    let mut stream = conn
        .open(&Open::Read {
            session: id,
            offset,
            max: max.min(READ_MAX),
            wait_ms,
        })
        .await
        .with_context(|| format!("reading session {id}"))?;
    read_msg(&mut stream)
        .await
        .with_context(|| format!("reading session {id}"))
}

/// `Open::Write`: raw bytes to the session's stdin; `eof` then closes it
/// (non-PTY sessions).
pub async fn session_send(conn: &Connection, id: u32, bytes: &[u8], eof: bool) -> Result<()> {
    let mut stream = conn
        .open(&Open::Write { session: id, eof })
        .await
        .with_context(|| format!("writing to session {id}"))?;
    stream
        .write_all(bytes)
        .await
        .with_context(|| format!("writing to session {id}"))?;
    stream
        .shutdown()
        .await
        .with_context(|| format!("writing to session {id}"))?;
    // The server closes its side once the bytes have reached the session.
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(SEND_ACK, stream.read_to_end(&mut sink)).await;
    Ok(())
}

/// `Open::ListSessions`: every session this key owns on the server.
pub async fn session_list(conn: &Connection) -> Result<Vec<DetachedSession>> {
    let mut stream = conn
        .open(&Open::ListSessions)
        .await
        .context("listing sessions")?;
    read_msg(&mut stream).await.context("listing sessions")
}

/// `Open::Signal`: `kill(pid, signal)` on the session's child.
pub async fn session_kill(conn: &Connection, id: u32, signal: Signal) -> Result<()> {
    conn.open(&Open::Signal {
        session: id,
        signal,
    })
    .await
    .with_context(|| format!("signalling session {id}"))?;
    Ok(())
}

/// Poll `Open::Read` until the session has exited; `Ok(None)` when
/// `timeout` passes first.
pub async fn session_wait(
    conn: &Connection,
    id: u32,
    timeout: Option<Duration>,
) -> Result<Option<ExitStatus>> {
    let deadline = timeout.map(|d| Instant::now() + d);
    loop {
        let left = match deadline {
            Some(at) => {
                let left = at.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(None);
                }
                left.min(READ_WAIT_MAX)
            }
            None => READ_WAIT_MAX,
        };
        // `u64::MAX` is never available, so the call returns early only
        // when the session exits.
        let reply = session_read(conn, id, u64::MAX, 0, left).await?;
        if let Some(status) = reply.exited {
            return Ok(Some(status));
        }
    }
}

// ---------------------------------------------------------------------------
// Commands

/// Run one `session …` command, reporting its result. `stdin` carries the
/// bytes of a `send --stdin`; the library never reads the process's own
/// stdin, so a `send --stdin` without them is an error. Returns the
/// process exit code for the caller.
pub async fn run(
    conn: &Connection,
    console: &dyn Reporter,
    args: &SessionArgs,
    stdin: Option<&[u8]>,
) -> Result<i32> {
    match &args.cmd {
        SessionCmd::New(new) => {
            let out = session_new(conn, &NewArgs::from_cli(new)).await?;
            if console.mode().is_json() {
                console.emit_value(&out);
            } else {
                console.println(&format!("session {} (pid {})", out.id, out.pid));
            }
            Ok(0)
        }
        SessionCmd::Send(send) => {
            cmd_send(conn, console, send, stdin).await?;
            Ok(0)
        }
        SessionCmd::Read(read) => cmd_read(conn, console, read).await,
        SessionCmd::List => {
            let rows = session_list(conn).await?;
            if console.mode().is_json() {
                console.emit_value(&SessionListOut {
                    sessions: rows.into_iter().map(ApiSessionRow::from).collect(),
                });
            } else {
                console.print(&format_list(&rows));
            }
            Ok(0)
        }
        SessionCmd::Kill { signal, id } => {
            let signal = match signal {
                Some(name) => {
                    Signal::parse(name).ok_or_else(|| anyhow::anyhow!("unknown signal {name:?}"))?
                }
                None => Signal::Term,
            };
            session_kill(conn, *id, signal).await?;
            if console.mode().is_json() {
                console.emit_value(&OkOut::new());
            }
            Ok(0)
        }
        SessionCmd::Wait { timeout, id } => cmd_wait(conn, console, *id, *timeout).await,
    }
}

async fn cmd_send(
    conn: &Connection,
    console: &dyn Reporter,
    args: &SessionSendArgs,
    supplied: Option<&[u8]>,
) -> Result<()> {
    let bytes = if args.stdin {
        let Some(bytes) = supplied else {
            bail!("session send --stdin: no input supplied");
        };
        bytes.to_vec()
    } else if args.text.is_empty() {
        Vec::new()
    } else {
        let mut bytes = decode_send_text(&args.text.join(" "));
        bytes.push(b'\n');
        bytes
    };
    if bytes.is_empty() && !args.eof {
        bail!("session send: nothing to send (pass TEXT, --stdin, or --eof)");
    }
    session_send(conn, args.id, &bytes, args.eof).await?;
    if console.mode().is_json() {
        console.emit_value(&OkOut::new());
    }
    Ok(())
}

async fn cmd_read(
    conn: &Connection,
    console: &dyn Reporter,
    args: &SessionReadArgs,
) -> Result<i32> {
    let max = args.max.unwrap_or(READ_MAX);
    let wait = args.wait.unwrap_or(if args.follow {
        FOLLOW_WAIT
    } else {
        Duration::ZERO
    });
    let mut offset = args.since.unwrap_or(0);
    loop {
        let reply = session_read(conn, args.id, offset, max, wait).await?;
        offset = reply.next;
        let exited = reply.exited;
        let empty = reply.chunks.is_empty();
        if console.mode().is_json() {
            console.emit_value(&ReadOut::from(reply));
        } else {
            for chunk in &reply.chunks {
                match chunk.stream {
                    OutStream::Stdout => console.write_bytes(&chunk.bytes),
                    OutStream::Stderr => console.write_stderr(&chunk.bytes),
                }
            }
        }
        if !args.follow || (exited.is_some() && empty) {
            return Ok(0);
        }
    }
}

async fn cmd_wait(
    conn: &Connection,
    console: &dyn Reporter,
    id: u32,
    timeout: Option<Duration>,
) -> Result<i32> {
    let status = session_wait(conn, id, timeout).await?;
    let json = console.mode().is_json();
    if let Some(status) = status {
        if json {
            let out: ExitOut = status.into();
            console.emit_value(&WaitOut {
                id,
                exit: out.exit,
                signal: out.signal,
                timed_out: false,
            });
        } else {
            console.println(&format!("session {id} {status}"));
        }
        return Ok(status.shell_code());
    }
    if json {
        console.emit_value(&WaitOut {
            id,
            exit: None,
            signal: None,
            timed_out: true,
        });
    } else {
        console.println(&format!("session {id} still running"));
    }
    Ok(EXIT_TIMEOUT)
}

/// Table for `session list`.
fn format_list(rows: &[DetachedSession]) -> String {
    use std::fmt::Write as _;

    if rows.is_empty() {
        return "no sessions\n".to_owned();
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:>4}  {:>7}  {:<9}  {:>12}  COMMAND",
        "ID", "PID", "STATE", "NEXT"
    );
    for row in rows {
        let state = match (row.exited, row.detached) {
            (Some(status), _) => format!("{status}"),
            (None, Some(_)) => "detached".to_owned(),
            (None, None) => "attached".to_owned(),
        };
        let _ = writeln!(
            out,
            "{:>4}  {:>7}  {:<9}  {:>12}  {}",
            row.id, row.pid, state, row.next, row.kind
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(offset: u64, next: u64, chunks: Vec<Chunk>, exited: Option<ExitStatus>) -> ReadReply {
        ReadReply {
            offset,
            next,
            oldest: 0,
            chunks,
            exited,
        }
    }

    #[test]
    fn read_reply_maps_to_json_shape() {
        let out = ReadOut::from(reply(
            7,
            12,
            vec![
                Chunk {
                    stream: OutStream::Stdout,
                    bytes: b"ok\n".to_vec(),
                },
                Chunk {
                    stream: OutStream::Stderr,
                    bytes: vec![0xff],
                },
            ],
            Some(ExitStatus::Signal {
                signal: 9,
                core_dumped: false,
            }),
        ));
        assert_eq!(out.offset, 7);
        assert_eq!(out.next, 12);
        assert_eq!(out.chunks[0].stream, "stdout");
        assert_eq!(out.chunks[0].data, Bytes::Text("ok\n".to_owned()));
        assert_eq!(out.chunks[1].stream, "stderr");
        assert_eq!(out.chunks[1].data, Bytes::Binary(vec![0xff]));
        assert_eq!(
            out.exited,
            Some(ExitOut {
                exit: None,
                signal: Some(9)
            })
        );
        let text = serde_json::to_string(&out).expect("serialize");
        assert!(text.contains("\"stream\":\"stdout\""), "{text}");
    }

    #[test]
    fn exit_status_maps_both_ways() {
        assert_eq!(
            ExitOut::from(ExitStatus::Code(3)),
            ExitOut {
                exit: Some(3),
                signal: None
            }
        );
    }

    #[test]
    fn list_table_shows_state() {
        let row = DetachedSession {
            id: 2,
            pid: 99,
            kind: "cat".to_owned(),
            started: 0,
            detached: Some(1),
            buffered: 0,
            pty: false,
            next: 17,
            oldest: 0,
            exited: None,
        };
        let mut exited = row.clone();
        exited.id = 3;
        exited.exited = Some(ExitStatus::Code(0));
        let text = format_list(&[row, exited]);
        assert!(text.contains("detached"), "{text}");
        assert!(text.contains("exit 0"), "{text}");
        assert_eq!(format_list(&[]), "no sessions\n");
    }
}
