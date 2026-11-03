//! Audit log (docs/02-security.md "Audit log"): one JSON line per
//! security-relevant event, appended to a 0600 file (or stderr) by a single
//! writer task, flushed per line. `tracing` is deliberately not involved:
//! the audit log has a stable schema and is never filtered by verbosity.
//!
//! [`Audit`] is the server-wide sink; every connection gets a [`Handle`]
//! that carries the peer address and the authenticated key, so handlers only
//! supply the event kind and its detail. A server started without `--audit`
//! has a disabled sink and every emission is a no-op (the detail closure is
//! never run).

use std::{
    fmt::Write as _,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use mysh_net::handshake::Peer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt as _},
    sync::mpsc,
};
use tracing::{debug, warn};

use crate::output::rfc3339;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// Handshake completed and the key was authorized.
    Connect,
    /// The connection ended (bytes and duration are filled in).
    Disconnect,
    /// A session (PTY shell or exec) started.
    Session,
    /// A session ended (`exit` is its status).
    Exec,
    /// A file operation ran (or failed after authorization).
    File,
    /// A forward was opened: `direct`, `listen` or `forwarded`.
    Forward,
    /// A pairing attempt (docs/02-security.md "Pairing").
    Pair,
    /// Something was refused: an unauthorized key, a feature switched off
    /// by policy, a bad pairing code.
    Denied,
}

/// One line of the log, exactly as written (`ts` is stamped by the writer,
/// so lines are in non-decreasing timestamp order).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Line {
    pub ts: String,
    /// Client address `ip:port`.
    pub peer: String,
    /// `SHA256:…` fingerprint of the client's key (`"?"` before one was
    /// offered).
    pub key: String,
    /// `x25519` or `ssh-ed25519`.
    pub kind: String,
    pub event: Event,
    /// Event-specific facts; always an object.
    pub detail: Value,
    /// Exit code of an `exec` event (`None` for a signal or other events).
    pub exit: Option<i32>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub duration_ms: Option<u64>,
}

/// The optional numeric columns of a [`Line`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extra {
    pub exit: Option<i32>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub duration_ms: Option<u64>,
}

impl Extra {
    /// `duration_ms` since `started`.
    #[must_use]
    pub fn elapsed(started: Instant) -> Self {
        Self {
            duration_ms: Some(millis(started.elapsed())),
            ..Self::default()
        }
    }

    /// Transferred bytes plus the duration since `started`.
    #[must_use]
    pub fn traffic(bytes_in: u64, bytes_out: u64, started: Instant) -> Self {
        Self {
            bytes_in: Some(bytes_in),
            bytes_out: Some(bytes_out),
            duration_ms: Some(millis(started.elapsed())),
            ..Self::default()
        }
    }
}

/// Whole milliseconds, saturating.
#[must_use]
pub fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Server-wide sink; `None` inside means auditing is off.
#[derive(Debug)]
pub struct Audit {
    tx: Option<mpsc::UnboundedSender<Line>>,
}

impl Audit {
    /// No audit log: every emission is dropped.
    #[must_use]
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self { tx: None })
    }

    /// Open `path` for appending (created 0600; an existing file keeps its
    /// mode) or use stderr for `-`, and start the writer task on the current
    /// runtime.
    pub async fn open(path: &Path) -> std::io::Result<Arc<Self>> {
        let sink: Box<dyn AsyncWrite + Send + Unpin> = if path == Path::new("-") {
            Box::new(tokio::io::stderr())
        } else {
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .await?;
            Box::new(file)
        };
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer(sink, rx));
        Ok(Arc::new(Self { tx: Some(tx) }))
    }

    /// Whether lines are being written.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.tx.is_some()
    }

    /// A per-connection handle; `key` is `None` until the client offered
    /// one (a connection refused before the handshake finished).
    #[must_use]
    pub fn handle(self: &Arc<Self>, peer: SocketAddr, key: Option<&Peer>) -> Handle {
        Handle {
            sink: Arc::clone(self),
            peer: peer.to_string(),
            key: key.map_or_else(|| "?".to_owned(), |k| k.fingerprint().to_string()),
            kind: key.map_or("", Peer::kind).to_owned(),
        }
    }

    fn send(&self, line: Line) {
        if let Some(tx) = &self.tx
            && tx.send(line).is_err()
        {
            debug!("audit writer gone; line dropped");
        }
    }
}

/// Per-connection emitter: the sink plus who the peer is.
#[derive(Debug, Clone)]
pub struct Handle {
    sink: Arc<Audit>,
    peer: String,
    key: String,
    kind: String,
}

impl Handle {
    /// A handle on a disabled sink (handler tests).
    #[must_use]
    pub fn disabled(peer: SocketAddr, key: &Peer) -> Self {
        Audit::disabled().handle(peer, Some(key))
    }

    /// Whether lines are being written.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.sink.enabled()
    }

    /// Record `event` with the detail `detail()` builds; the closure runs
    /// only when the log is on.
    pub fn emit(&self, event: Event, detail: impl FnOnce() -> Value) {
        self.emit_with(event, Extra::default(), detail);
    }

    /// [`Handle::emit`] with the numeric columns filled in.
    pub fn emit_with(&self, event: Event, extra: Extra, detail: impl FnOnce() -> Value) {
        if !self.sink.enabled() {
            return;
        }
        let detail = match detail() {
            Value::Object(map) => Value::Object(map),
            other => serde_json::json!({ "value": other }),
        };
        self.sink.send(Line {
            ts: String::new(),
            peer: self.peer.clone(),
            key: self.key.clone(),
            kind: self.kind.clone(),
            event,
            detail,
            exit: extra.exit,
            bytes_in: extra.bytes_in,
            bytes_out: extra.bytes_out,
            duration_ms: extra.duration_ms,
        });
    }

    /// `denied`: `what` was refused because `why`.
    pub fn denied(&self, what: &str, why: &str) {
        self.emit(
            Event::Denied,
            || serde_json::json!({ "what": what, "why": why }),
        );
    }
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for now.
fn timestamp() -> String {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = i64::try_from(since.as_secs()).unwrap_or(i64::MAX);
    let mut ts = rfc3339(secs);
    ts.pop(); // the trailing `Z`
    let _ = write!(ts, ".{:03}Z", since.subsec_millis());
    ts
}

/// Stamp, serialize and write each line, flushing after every one.
async fn writer(
    mut sink: Box<dyn AsyncWrite + Send + Unpin>,
    mut rx: mpsc::UnboundedReceiver<Line>,
) {
    while let Some(mut line) = rx.recv().await {
        line.ts = timestamp();
        let mut text = match serde_json::to_string(&line) {
            Ok(text) => text,
            Err(e) => {
                warn!(error = %e, "audit line not serializable");
                continue;
            }
        };
        text.push('\n');
        if let Err(e) = sink.write_all(text.as_bytes()).await {
            warn!(error = %e, "audit write failed");
            continue;
        }
        if let Err(e) = sink.flush().await {
            warn!(error = %e, "audit flush failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use mysh_net::keys::SecretKey;

    use super::*;

    fn peer() -> Peer {
        Peer::Static(SecretKey::generate().public())
    }

    #[tokio::test]
    async fn writes_one_json_line_per_event_with_mode_0600() {
        let dir = std::env::temp_dir().join(format!("mysh-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let _ = std::fs::remove_file(&path);
        let audit = Audit::open(&path).await.unwrap();
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let key = peer();
        let handle = audit.handle(addr, Some(&key));
        handle.emit(Event::Connect, || serde_json::json!({ "version": 1 }));
        handle.emit_with(
            Event::Exec,
            Extra {
                exit: Some(3),
                ..Extra::default()
            },
            || serde_json::json!({ "id": 1 }),
        );
        handle.denied("file", "policy");
        // Let the writer drain.
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if std::fs::read_to_string(&path).unwrap().lines().count() == 3 {
                break;
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Line> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].event, Event::Connect);
        assert_eq!(lines[0].peer, "127.0.0.1:4242");
        assert_eq!(lines[0].key, key.fingerprint().to_string());
        assert_eq!(lines[0].kind, "x25519");
        assert_eq!(lines[1].exit, Some(3));
        assert_eq!(lines[2].detail["what"], "file");
        assert!(lines.windows(2).all(|w| w[0].ts <= w[1].ts));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_handle_runs_no_closure() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let handle = Handle::disabled(addr, &peer());
        assert!(!handle.enabled());
        handle.emit(Event::Connect, || {
            unreachable!("detail built while disabled")
        });
    }

    #[test]
    fn timestamp_is_rfc3339_with_millis() {
        let ts = timestamp();
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[19..20], ".");
    }
}
