//! Structured output for programs driving the client (docs/05-meta-shell.md
//! "Agent interface"): the output [`Mode`], the JSON result shapes every
//! `--json` command prints, the NDJSON [`Event`] stream of `--json-stream`,
//! and the stable error codes of [`ErrorOut`].
//!
//! Everything here is pure data: the console decides where a value goes and
//! the printers decide what to put in it.

use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// How the client speaks to its caller, chosen once in `main`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Terminal: banner, progress lines, prompt redraws.
    #[default]
    Human,
    /// Text without ANSI, progress or banner (`--plain`, or stdout is not a
    /// terminal).
    Plain,
    /// One JSON document per command on stdout; errors as [`ErrorOut`] on
    /// stderr.
    Json,
    /// Newline-delimited JSON events on stdout as they happen.
    JsonStream,
}

impl Mode {
    /// Mode for the flags `--json`, `--json-stream`, `--plain`; without any,
    /// `Human` on a terminal and `Plain` otherwise.
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools)] // mirrors the three flags plus the tty probe
    pub fn select(json: bool, json_stream: bool, plain: bool, stdout_tty: bool) -> Self {
        if json_stream {
            Self::JsonStream
        } else if json {
            Self::Json
        } else if plain || !stdout_tty {
            Self::Plain
        } else {
            Self::Human
        }
    }

    /// `Json` or `JsonStream`.
    #[must_use]
    pub fn is_json(self) -> bool {
        matches!(self, Self::Json | Self::JsonStream)
    }
}

/// Bytes that are a string when valid UTF-8 and `{"base64": "…"}` otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bytes {
    /// Text variant.
    Text(String),
    /// Binary data.
    Binary(Vec<u8>),
}

impl Bytes {
    #[must_use]
    /// Constructs Bytes from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        match String::from_utf8(bytes) {
            Ok(s) => Self::Text(s),
            Err(e) => Self::Binary(e.into_bytes()),
        }
    }

    /// The raw bytes either way.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(s) => s.as_bytes(),
            Self::Binary(b) => b,
        }
    }

    #[must_use]
    /// Consumes into raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Text(s) => s.into_bytes(),
            Self::Binary(b) => b,
        }
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

#[derive(Serialize, Deserialize)]
struct Base64Wrap {
    base64: String,
}

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(s) => serializer.serialize_str(s),
            Self::Binary(b) => Base64Wrap {
                base64: base64::engine::general_purpose::STANDARD.encode(b),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Text(String),
            Binary(Base64Wrap),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Text(s) => Ok(Self::Text(s)),
            Repr::Binary(w) => base64::engine::general_purpose::STANDARD
                .decode(w.base64)
                .map(Self::Binary)
                .map_err(serde::de::Error::custom),
        }
    }
}

// ---------------------------------------------------------------------------
// Results

/// `exec CMD` / `mysh HOST CMD` with `--json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExecResult {
    /// Captured stdout.
    pub stdout: Bytes,
    /// Captured stderr.
    pub stderr: Bytes,
    /// Exit code for a normal exit.
    pub exit: Option<i32>,
    /// Signal number when the process was killed by one.
    pub signal: Option<i32>,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// `--timeout` expired; the process was sent TERM (then KILL).
    pub timed_out: bool,
}

impl ExecResult {
    /// Process exit code for the caller: the shell convention, or 124 after
    /// a timeout.
    #[must_use]
    pub fn code(&self) -> i32 {
        if self.timed_out {
            return EXIT_TIMEOUT;
        }
        match (self.exit, self.signal) {
            (Some(code), _) => code,
            (None, Some(signal)) => 128 + signal,
            (None, None) => EXIT_LOST,
        }
    }
}

/// Exit code after `--timeout` fired, like `timeout(1)`.
pub const EXIT_TIMEOUT: i32 = 124;

/// Exit code when the connection drops or the ping timer fires.
pub const EXIT_LOST: i32 = 255;

/// `info --json`: the server's facts plus the connection's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InfoOut {
    /// `Open::Info` reply; `None` when the server predates it.
    pub server: Option<mysh_proto::info::Info>,
    /// Server connection details.
    pub connection: ConnectionOut,
    /// Sessions.
    pub sessions: Vec<SessionRow>,
    /// Port forwards.
    pub forwards: Vec<ForwardRow>,
}

/// Server connection details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionOut {
    /// Remote host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Peer address actually connected to.
    pub peer: String,
    /// Peer public key fingerprint.
    pub peer_fingerprint: String,
    /// How the peer was trusted.
    pub trusted_via: String,
    /// Our public key.
    pub our_key: String,
    /// Protocol version.
    pub protocol: u16,
    /// Cipher suite.
    pub cipher: String,
    /// Seconds connected.
    pub connected_secs: u64,
    /// Most recent ping round trip; `None` before the first ping.
    pub rtt_ms: Option<f64>,
    /// Bytes received.
    pub bytes_in: u64,
    /// Bytes sent.
    pub bytes_out: u64,
    /// Number of rekeying events.
    pub rekeys: u64,
}

/// One row of `sessions --json` (the client's stack).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionRow {
    /// Session ID.
    pub id: u32,
    /// Process ID.
    pub pid: u32,
    /// `shell` or `exec: CMD`.
    pub kind: String,
    /// Output bytes buffered while in the background.
    pub buffered: u64,
    /// Most recently used.
    pub mru: bool,
    /// In foreground.
    pub foreground: bool,
}

/// `sessions [-a] --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionsOut {
    /// Sessions.
    pub sessions: Vec<SessionRow>,
    /// The server's view (`-a`), `None` without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Vec<mysh_proto::session::DetachedSession>>,
}

/// One row of `jobs --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JobRow {
    /// Job ID.
    pub id: u32,
    /// `running`, `done`, `failed`, `cancelled`.
    pub state: String,
    /// Exit code of a finished `exec` job (0 for other finished jobs).
    pub exit: Option<i32>,
    /// Message of a failed job.
    pub error: Option<String>,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// The prompt line without its `&`.
    pub command: String,
    /// Current progress.
    pub progress: Option<ProgressOut>,
}

/// Progress indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProgressOut {
    /// Progress label.
    pub label: String,
    /// Bytes completed.
    pub done: u64,
    /// Total bytes, if known.
    pub total: Option<u64>,
}

/// `jobs ID --json`: the row plus the captured output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JobOut {
    #[serde(flatten)]
    /// Job details.
    pub job: JobRow,
    /// Captured output.
    pub output: Bytes,
}

/// One entry of `ls --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LsEntry {
    /// File name.
    pub name: String,
    /// `file`, `dir`, `symlink`, `other`.
    pub kind: String,
    /// File size in bytes.
    pub size: u64,
    /// Permission bits in octal, e.g. `"0644"`.
    pub mode: String,
    /// RFC 3339 UTC.
    pub mtime: String,
    /// Symlink target.
    pub target: Option<String>,
}

/// `stat --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StatOut {
    /// File path.
    pub path: String,
    /// File kind.
    pub kind: String,
    /// Size in bytes.
    pub size: u64,
    /// Permission bits.
    pub mode: String,
    /// Modification time.
    pub mtime: String,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Symlink target.
    pub target: Option<String>,
}

/// One row of `forward ls --json` (and `forward -L …` adds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ForwardRow {
    /// Forward ID.
    pub id: u32,
    /// `local`, `remote`, `dynamic`.
    pub kind: String,
    /// Listening address (`host:port`).
    pub bind: String,
    /// Destination `host:port`; `None` for dynamic forwards.
    pub target: Option<String>,
    /// Number of accepted connections.
    pub accepted: u64,
}

/// `ping --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PingOut {
    /// Round-trip times in milliseconds.
    pub rtts_ms: Vec<f64>,
    /// Minimum RTT.
    pub min: f64,
    /// Average RTT.
    pub avg: f64,
    /// Maximum RTT.
    pub max: f64,
}

/// `put`/`get --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TransferOut {
    /// Files transferred (skipped ones are not counted here).
    pub files: u64,
    /// Files left alone: complete under `-c`, or identical under
    /// `--checksum`.
    #[serde(default)]
    pub skipped: u64,
    /// Bytes transferred.
    pub bytes: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// One element of `run --json` (docs/05-meta-shell.md "Fleet"), in the
/// order the hosts were given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RunResult {
    /// The host as given (alias or address).
    pub host: String,
    /// The command ran and exited 0.
    pub ok: bool,
    /// Exit code.
    pub exit: Option<i32>,
    /// Signal number.
    pub signal: Option<i32>,
    /// Captured stdout.
    pub stdout: Bytes,
    /// Captured stderr.
    pub stderr: Bytes,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Why the command did not run (or did not finish): `connect_failed`,
    /// `trust_unknown`, `timeout`, … (the `ErrorOut` codes).
    pub error: Option<ErrorBody>,
}

impl RunResult {
    /// A host that produced no result at all because of `err`.
    #[must_use]
    pub fn failed(host: &str, err: &anyhow::Error, duration_ms: u64) -> Self {
        Self {
            host: host.to_owned(),
            ok: false,
            exit: None,
            signal: None,
            stdout: Bytes::new(Vec::new()),
            stderr: Bytes::new(Vec::new()),
            duration_ms,
            error: Some(ErrorOut::from_error(err).error),
        }
    }
}

/// One element of `put`/`get --hosts … --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TransferResult {
    /// Host name.
    pub host: String,
    /// Whether successful.
    pub ok: bool,
    /// The transfer summary when it ran.
    pub transfer: Option<TransferOut>,
    /// Error details.
    pub error: Option<ErrorBody>,
}

/// `hash REMOTE… --json` (one per path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HashOut {
    /// File path.
    pub path: String,
    /// `blake2s256`.
    pub algo: String,
    /// File size in bytes.
    pub size: u64,
    /// Lowercase hex.
    pub digest: String,
}

/// `cat`, `get REMOTE -`, `tail` with `--json`: the bytes that would have
/// gone to stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DataOut {
    /// File data.
    pub data: Bytes,
    /// Bytes transferred.
    pub bytes: u64,
}

/// `realpath REMOTE --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RealpathOut {
    /// File path.
    pub path: String,
    /// Resolved path.
    pub realpath: String,
}

/// One file `sync` would copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncEntry {
    /// Relative to the tree root.
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// `missing`, `size`, `mtime`, `content`.
    pub reason: String,
}

/// `sync --dry-run --json`: what a run would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncPlan {
    /// Files to copy.
    pub copies: Vec<SyncEntry>,
    /// Extras on the destination (`--delete`), files before directories,
    /// deepest first.
    pub deletes: Vec<String>,
    /// Number of unchanged files.
    pub unchanged: u64,
    /// Bytes the copies amount to.
    pub bytes: u64,
}

/// `sync --json` after a real run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncSummary {
    /// Copied count.
    pub copied: u64,
    /// Deleted count.
    pub deleted: u64,
    /// Unchanged count.
    pub unchanged: u64,
    /// Bytes transferred.
    pub bytes: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// `cwd --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CwdOut {
    /// Remote working directory of the MRU session; `None` without one.
    pub remote: Option<String>,
    /// Session ID.
    pub session: Option<u32>,
    /// Local bind address.
    pub local: String,
}

/// `authorize --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizeOut {
    /// `false` when the key was already present.
    pub added: bool,
}

/// `pair --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PairOut {
    /// Host name.
    pub host: String,
    /// Server fingerprint.
    pub server_fingerprint: String,
    /// Client fingerprint.
    pub client_fingerprint: String,
    /// The `authorized_keys` line the server installed.
    pub authorized_line: String,
    /// The `known_hosts` line the client installed.
    pub host_line: String,
}

/// Acknowledgement of a command with nothing else to say (`kill`,
/// `forward rm`, `log`, `detach`, `resize`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OkOut {
    /// Whether successful.
    pub ok: bool,
}

impl OkOut {
    /// Successful result.
    pub const OK: Self = Self { ok: true };

    #[must_use]
    /// Creates an ok result.
    pub fn new() -> Self {
        Self::OK
    }
}

impl Default for OkOut {
    fn default() -> Self {
        Self::OK
    }
}

// ---------------------------------------------------------------------------
// Events (`--json-stream`)

/// One line of the NDJSON stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The exec session is running.
    Started {
        /// Session ID.
        session: u32,
        /// Process ID.
        pid: u32,
    },
    /// Stdout data.
    Stdout {
        /// Data.
        data: Bytes,
    },
    /// Stderr data.
    Stderr {
        /// Data.
        data: Bytes,
    },
    /// Always the last event of an exec.
    Exit {
        /// Exit code.
        exit: Option<i32>,
        /// Signal number.
        signal: Option<i32>,
        /// Duration in milliseconds.
        duration_ms: u64,
        /// Timeout occurred.
        timed_out: bool,
    },
    /// Transfer progress (`put`/`get`).
    Progress {
        /// Progress label.
        label: String,
        /// Bytes completed.
        done: u64,
        /// Total bytes.
        total: Option<u64>,
    },
    /// What `[mysh] …` would have said.
    Notice {
        /// Text message.
        text: String,
    },
    /// A command failed; same codes as [`ErrorOut`].
    Error {
        /// Error code.
        code: String,
        /// Error message.
        message: String,
    },
    /// A command's result document (what `--json` would have printed).
    Result {
        /// JSON value.
        value: serde_json::Value,
    },
    /// One host's event in a fan-out (`run`, `put`/`get --hosts`): `data`
    /// is the event that host's own stream would have carried.
    Host {
        /// Host name.
        host: String,
        /// Nested event.
        data: Box<Event>,
    },
    /// An accepting client (`mysh accept`, [`crate::accept::Acceptor`])
    /// completed the handshake with a server that connected back.
    Accepted {
        /// The caller's name (its `callers` comment, or the fingerprint
        /// label of an unnamed one).
        name: String,
        /// The server's key fingerprint.
        fingerprint: String,
        /// The server's socket address.
        addr: String,
        /// The server's hello and the negotiated protocol version.
        server: AcceptedServer,
    },
    /// An accepted connection ended.
    Closed {
        /// The caller's name.
        name: String,
        /// The server's key fingerprint.
        fingerprint: String,
        /// Why it ended.
        reason: String,
    },
    /// An inbound connection was refused before our identity was revealed:
    /// the server's key is not a caller.
    Refused {
        /// The server's key fingerprint (empty when the handshake failed
        /// before it was known).
        fingerprint: String,
        /// The server's socket address.
        addr: String,
        /// Why.
        reason: String,
    },
}

/// The server side of an accepted connection (`Event::Accepted.server`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedServer {
    /// `ServerHello.name` (informational: the server's hostname by default).
    pub name: String,
    /// Negotiated protocol version.
    pub version: u16,
}

/// `bind` result: `{"bound": "ADDR"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindOut {
    /// The address the server's requested listener is bound at.
    pub bound: String,
}

// ---------------------------------------------------------------------------
// Errors

/// `{"error": {"code": …, "message": …}}` on stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorOut {
    /// Error body.
    pub error: ErrorBody,
}

/// Error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}
impl ErrorOut {
    #[must_use]
    /// Creates an error body.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code: code.to_owned(),
                message: message.into(),
            },
        }
    }

    /// Classify `err` with [`code_for`] and render its chain.
    #[must_use]
    pub fn from_error(err: &anyhow::Error) -> Self {
        Self::new(code_for(err), format!("{err:#}"))
    }

    /// One line of JSON (no trailing newline).
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                "{{\"error\":{{\"code\":\"internal\",\"message\":{:?}}}}}",
                self.error.message
            )
        })
    }
}

/// An error tagged with its stable code; `code_for` finds it anywhere in an
/// anyhow chain.
#[derive(Debug)]
pub struct CodedError {
    /// Error code.
    pub code: &'static str,
    /// Underlying error.
    pub source: anyhow::Error,
}

impl CodedError {
    #[must_use]
    /// Creates a coded error.
    pub fn new(code: &'static str, source: anyhow::Error) -> Self {
        Self { code, source }
    }
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for CodedError {}

/// Tag `err` with `code` (keeps its message).
#[must_use]
pub fn coded(code: &'static str, err: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(CodedError::new(code, err))
}

/// Marker for `--timeout` expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeout;

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("timed out")
    }
}

impl std::error::Error for Timeout {}

/// Stable error codes (docs/05 "Agent interface", "Error codes").
pub mod codes {
    /// Unauthorized error code.
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// Denied error code.
    pub const DENIED: &str = "denied";
    /// Not found error code.
    pub const NOT_FOUND: &str = "not_found";
    /// Unsupported error code.
    pub const UNSUPPORTED: &str = "unsupported";
    /// IO error code.
    pub const IO: &str = "io";
    /// Limit exceeded error code.
    pub const LIMIT: &str = "limit";
    /// Protocol error code.
    pub const PROTOCOL: &str = "protocol";
    /// Unknown trust error code.
    pub const TRUST_UNKNOWN: &str = "trust_unknown";
    /// Trust mismatch error code.
    pub const TRUST_MISMATCH: &str = "trust_mismatch";
    /// Connection failed error code.
    pub const CONNECT_FAILED: &str = "connect_failed";
    /// Timeout error code.
    pub const TIMEOUT: &str = "timeout";
    /// Usage error code.
    pub const USAGE: &str = "usage";
    /// Internal error code.
    pub const INTERNAL: &str = "internal";
}

/// Snake-case name of a protocol error code.
#[must_use]
pub fn code_name(code: mysh_proto::open::ErrorCode) -> &'static str {
    use mysh_proto::open::ErrorCode;
    match code {
        ErrorCode::Unauthorized => codes::UNAUTHORIZED,
        ErrorCode::Denied => codes::DENIED,
        ErrorCode::NotFound => codes::NOT_FOUND,
        ErrorCode::Unsupported => codes::UNSUPPORTED,
        ErrorCode::Io => codes::IO,
        ErrorCode::Limit => codes::LIMIT,
        ErrorCode::Protocol => codes::PROTOCOL,
    }
}

/// The stable code of an error: the first classifiable cause in the chain,
/// else `internal`.
#[must_use]
pub fn code_for(err: &anyhow::Error) -> &'static str {
    for cause in err.chain() {
        if let Some(c) = cause.downcast_ref::<CodedError>() {
            return c.code;
        }
        if cause.downcast_ref::<Timeout>().is_some()
            || cause
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        {
            return codes::TIMEOUT;
        }
        if let Some(e) = cause.downcast_ref::<mysh_net::mux::OpenError>() {
            return match e {
                mysh_net::mux::OpenError::Rejected { code, .. } => code_name(*code),
                mysh_net::mux::OpenError::Timeout => codes::TIMEOUT,
                mysh_net::mux::OpenError::Io(_) | mysh_net::mux::OpenError::Closed => codes::IO,
            };
        }
        if let Some(e) = cause.downcast_ref::<mysh_net::handshake::HandshakeError>() {
            return match e {
                mysh_net::handshake::HandshakeError::Denied { code, .. } => code_name(*code),
                mysh_net::handshake::HandshakeError::Io(_) => codes::CONNECT_FAILED,
                _ => codes::PROTOCOL,
            };
        }
        if cause.downcast_ref::<clap::Error>().is_some() {
            return codes::USAGE;
        }
    }
    codes::INTERNAL
}

/// `YYYY-MM-DDTHH:MM:SSZ` for seconds since the Unix epoch.
#[must_use]
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Proleptic Gregorian civil date from days since 1970-01-01 (UTC).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// `"0644"`-style permission bits.
#[must_use]
pub fn octal_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// Milliseconds with sub-millisecond precision.
#[must_use]
pub fn millis(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// `1.5 MiB`-style size.
#[must_use]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_serialize_text_or_base64() {
        let text = Bytes::from(b"hi\n".as_slice());
        assert_eq!(serde_json::to_string(&text).unwrap(), "\"hi\\n\"");
        let bin = Bytes::from(vec![0xff, 0x00]);
        assert_eq!(
            serde_json::to_string(&bin).unwrap(),
            "{\"base64\":\"/wA=\"}"
        );
        let back: Bytes = serde_json::from_str("{\"base64\":\"/wA=\"}").unwrap();
        assert_eq!(back, bin);
        let back: Bytes = serde_json::from_str("\"x\"").unwrap();
        assert_eq!(back, Bytes::Text("x".into()));
    }

    #[test]
    fn exec_result_code() {
        let mut r = ExecResult {
            stdout: Bytes::Text(String::new()),
            stderr: Bytes::Text(String::new()),
            exit: Some(3),
            signal: None,
            duration_ms: 0,
            timed_out: false,
        };
        assert_eq!(r.code(), 3);
        r.exit = None;
        r.signal = Some(9);
        assert_eq!(r.code(), 137);
        r.timed_out = true;
        assert_eq!(r.code(), EXIT_TIMEOUT);
    }

    #[test]
    fn code_for_walks_the_chain() {
        let e = coded(codes::TRUST_MISMATCH, anyhow::anyhow!("bad key")).context("connecting");
        assert_eq!(code_for(&e), codes::TRUST_MISMATCH);
        assert_eq!(format!("{e:#}"), "connecting: bad key");
        let e = anyhow::Error::new(mysh_net::mux::OpenError::Rejected {
            code: mysh_proto::open::ErrorCode::NotFound,
            message: "x".into(),
        })
        .context("opening");
        assert_eq!(code_for(&e), codes::NOT_FOUND);
        let e = anyhow::Error::new(Timeout).context("put");
        assert_eq!(code_for(&e), codes::TIMEOUT);
        assert_eq!(code_for(&anyhow::anyhow!("plain")), codes::INTERNAL);
        let e = anyhow::Error::new(
            clap::Command::new("x")
                .try_get_matches_from(["x", "--nope"])
                .unwrap_err(),
        );
        assert_eq!(code_for(&e), codes::USAGE);
    }

    #[test]
    fn error_out_line() {
        let line = ErrorOut::new(codes::USAGE, "missing HOST").to_line();
        assert_eq!(
            line,
            "{\"error\":{\"code\":\"usage\",\"message\":\"missing HOST\"}}"
        );
        let back: ErrorOut = serde_json::from_str(&line).unwrap();
        assert_eq!(back.error.code, "usage");
    }

    #[test]
    fn events_are_tagged() {
        let ev = Event::Exit {
            exit: Some(0),
            signal: None,
            duration_ms: 5,
            timed_out: false,
        };
        let line = serde_json::to_string(&ev).unwrap();
        assert!(line.starts_with("{\"event\":\"exit\""), "{line}");
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn rfc3339_and_mode() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(octal_mode(0o100_644), "0644");
    }

    #[test]
    fn mode_select() {
        assert_eq!(Mode::select(false, false, false, true), Mode::Human);
        assert_eq!(Mode::select(false, false, false, false), Mode::Plain);
        assert_eq!(Mode::select(false, false, true, true), Mode::Plain);
        assert_eq!(Mode::select(true, false, false, true), Mode::Json);
        assert_eq!(Mode::select(true, true, false, true), Mode::JsonStream);
    }
}
