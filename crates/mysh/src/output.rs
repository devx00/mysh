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
    Text(String),
    Binary(Vec<u8>),
}

impl Bytes {
    #[must_use]
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
    pub stdout: Bytes,
    pub stderr: Bytes,
    /// Exit code for a normal exit.
    pub exit: Option<i32>,
    /// Signal number when the process was killed by one.
    pub signal: Option<i32>,
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
            (None, None) => crate::client::EXIT_LOST,
        }
    }
}

/// Exit code after `--timeout` fired, like `timeout(1)`.
pub const EXIT_TIMEOUT: i32 = 124;

/// `info --json`: the server's facts plus the connection's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InfoOut {
    /// `Open::Info` reply; `None` when the server predates it.
    pub server: Option<mysh_proto::info::Info>,
    pub connection: ConnectionOut,
    pub sessions: Vec<SessionRow>,
    pub forwards: Vec<ForwardRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionOut {
    pub host: String,
    pub port: u16,
    /// Peer address actually connected to.
    pub peer: String,
    pub peer_fingerprint: String,
    pub trusted_via: String,
    pub our_key: String,
    pub protocol: u16,
    pub cipher: String,
    pub connected_secs: u64,
    /// Most recent ping round trip; `None` before the first ping.
    pub rtt_ms: Option<f64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rekeys: u64,
}

/// One row of `sessions --json` (the client's stack).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionRow {
    pub id: u32,
    pub pid: u32,
    /// `shell` or `exec: CMD`.
    pub kind: String,
    /// Output bytes buffered while in the background.
    pub buffered: u64,
    pub mru: bool,
    pub foreground: bool,
}

/// `sessions [-a] --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionsOut {
    pub sessions: Vec<SessionRow>,
    /// The server's view (`-a`), `None` without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Vec<mysh_proto::session::DetachedSession>>,
}

/// One row of `jobs --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JobRow {
    pub id: u32,
    /// `running`, `done`, `failed`, `cancelled`.
    pub state: String,
    /// Exit code of a finished `exec` job (0 for other finished jobs).
    pub exit: Option<i32>,
    /// Message of a failed job.
    pub error: Option<String>,
    pub elapsed_ms: u64,
    /// The prompt line without its `&`.
    pub command: String,
    pub progress: Option<ProgressOut>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProgressOut {
    pub label: String,
    pub done: u64,
    pub total: Option<u64>,
}

/// `jobs ID --json`: the row plus the captured output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JobOut {
    #[serde(flatten)]
    pub job: JobRow,
    pub output: Bytes,
}

/// One entry of `ls --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LsEntry {
    pub name: String,
    /// `file`, `dir`, `symlink`, `other`.
    pub kind: String,
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
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub mode: String,
    pub mtime: String,
    pub uid: u32,
    pub gid: u32,
    pub target: Option<String>,
}

/// One row of `forward ls --json` (and `forward -L …` adds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ForwardRow {
    pub id: u32,
    /// `local`, `remote`, `dynamic`.
    pub kind: String,
    /// Listening address (`host:port`).
    pub bind: String,
    /// Destination `host:port`; `None` for dynamic forwards.
    pub target: Option<String>,
    pub accepted: u64,
}

/// `ping --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PingOut {
    pub rtts_ms: Vec<f64>,
    pub min: f64,
    pub avg: f64,
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
    pub bytes: u64,
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
    pub exit: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Bytes,
    pub stderr: Bytes,
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
    pub host: String,
    pub ok: bool,
    /// The transfer summary when it ran.
    pub transfer: Option<TransferOut>,
    pub error: Option<ErrorBody>,
}

/// `hash REMOTE… --json` (one per path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HashOut {
    pub path: String,
    /// `blake2s256`.
    pub algo: String,
    pub size: u64,
    /// Lowercase hex.
    pub digest: String,
}

/// `cat`, `get REMOTE -`, `tail` with `--json`: the bytes that would have
/// gone to stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DataOut {
    pub data: Bytes,
    pub bytes: u64,
}

/// `realpath REMOTE --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RealpathOut {
    pub path: String,
    pub realpath: String,
}

/// One file `sync` would copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncEntry {
    /// Relative to the tree root.
    pub path: String,
    pub size: u64,
    /// `missing`, `size`, `mtime`, `content`.
    pub reason: String,
}

/// `sync --dry-run --json`: what a run would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncPlan {
    pub copies: Vec<SyncEntry>,
    /// Extras on the destination (`--delete`), files before directories,
    /// deepest first.
    pub deletes: Vec<String>,
    pub unchanged: u64,
    /// Bytes the copies amount to.
    pub bytes: u64,
}

/// `sync --json` after a real run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncSummary {
    pub copied: u64,
    pub deleted: u64,
    pub unchanged: u64,
    pub bytes: u64,
    pub duration_ms: u64,
}

/// `cwd --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CwdOut {
    /// Remote working directory of the MRU session; `None` without one.
    pub remote: Option<String>,
    pub session: Option<u32>,
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
    pub host: String,
    pub server_fingerprint: String,
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
    pub ok: bool,
}

impl OkOut {
    pub const OK: Self = Self { ok: true };

    #[must_use]
    pub fn new() -> Self {
        Self::OK
    }
}

impl Default for OkOut {
    fn default() -> Self {
        Self::OK
    }
}

/// `help --json`: the clap command tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HelpTree {
    pub command: String,
    pub about: Option<String>,
    pub args: Vec<HelpArg>,
    pub subcommands: Vec<HelpTree>,
}

#[allow(clippy::struct_excessive_bools)] // independent facts about one argument
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HelpArg {
    pub name: String,
    pub long: Option<String>,
    pub short: Option<char>,
    /// Takes a value (`--port PORT`) rather than being a switch.
    pub takes_value: bool,
    /// Positional arguments have no `long`/`short`.
    pub positional: bool,
    pub required: bool,
    pub repeatable: bool,
    pub value_name: Option<String>,
    pub default: Option<String>,
    pub help: Option<String>,
}

impl HelpTree {
    /// Build the tree of `cmd` by introspection. The automatic `help` and
    /// `version` flags are skipped; everything else is reported.
    #[must_use]
    pub fn from_clap(cmd: &clap::Command) -> Self {
        let args = cmd
            .get_arguments()
            .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
            .map(|a| {
                let positional = a.is_positional();
                let action = a.get_action();
                HelpArg {
                    name: a.get_id().to_string(),
                    long: a.get_long().map(str::to_owned),
                    short: a.get_short(),
                    takes_value: action.takes_values(),
                    positional,
                    required: a.is_required_set(),
                    repeatable: matches!(action, clap::ArgAction::Append | clap::ArgAction::Count)
                        || a.get_num_args().is_some_and(|n| n.max_values() > 1),
                    value_name: a
                        .get_value_names()
                        .and_then(|names| names.first())
                        .map(ToString::to_string),
                    default: {
                        let defaults: Vec<String> = a
                            .get_default_values()
                            .iter()
                            .map(|v| v.to_string_lossy().into_owned())
                            .collect();
                        (!defaults.is_empty()).then(|| defaults.join(","))
                    },
                    help: a.get_help().map(ToString::to_string),
                }
            })
            .collect();
        Self {
            command: cmd.get_name().to_owned(),
            about: cmd.get_about().map(ToString::to_string),
            args,
            subcommands: cmd.get_subcommands().map(Self::from_clap).collect(),
        }
    }

    /// The subtree for `name`, if it is a direct subcommand.
    #[must_use]
    pub fn subcommand(&self, name: &str) -> Option<&Self> {
        self.subcommands.iter().find(|c| c.command == name)
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
        session: u32,
        pid: u32,
    },
    Stdout {
        data: Bytes,
    },
    Stderr {
        data: Bytes,
    },
    /// Always the last event of an exec.
    Exit {
        exit: Option<i32>,
        signal: Option<i32>,
        duration_ms: u64,
        timed_out: bool,
    },
    /// Transfer progress (`put`/`get`).
    Progress {
        label: String,
        done: u64,
        total: Option<u64>,
    },
    /// What `[mysh] …` would have said.
    Notice {
        text: String,
    },
    /// A command failed; same codes as [`ErrorOut`].
    Error {
        code: String,
        message: String,
    },
    /// A command's result document (what `--json` would have printed).
    Result {
        value: serde_json::Value,
    },
    /// One host's event in a fan-out (`run`, `put`/`get --hosts`): `data`
    /// is the event that host's own stream would have carried.
    Host {
        host: String,
        data: Box<Event>,
    },
}

// ---------------------------------------------------------------------------
// Errors

/// `{"error": {"code": …, "message": …}}` on stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorOut {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl ErrorOut {
    #[must_use]
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
    pub code: &'static str,
    pub source: anyhow::Error,
}

impl CodedError {
    #[must_use]
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
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const DENIED: &str = "denied";
    pub const NOT_FOUND: &str = "not_found";
    pub const UNSUPPORTED: &str = "unsupported";
    pub const IO: &str = "io";
    pub const LIMIT: &str = "limit";
    pub const PROTOCOL: &str = "protocol";
    pub const TRUST_UNKNOWN: &str = "trust_unknown";
    pub const TRUST_MISMATCH: &str = "trust_mismatch";
    pub const CONNECT_FAILED: &str = "connect_failed";
    pub const TIMEOUT: &str = "timeout";
    pub const USAGE: &str = "usage";
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

    #[test]
    fn help_tree_from_cli() {
        use clap::CommandFactory as _;
        let tree = HelpTree::from_clap(&crate::cli::Cli::command());
        assert_eq!(tree.command, "mysh");
        assert!(tree.subcommand("serve").is_some());
        let serve = tree.subcommand("serve").unwrap();
        assert!(
            serve
                .args
                .iter()
                .any(|a| a.long.as_deref() == Some("listen"))
        );
        assert!(tree.subcommand("help").is_some());
    }
}
