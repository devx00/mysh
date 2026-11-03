//! Session stream (docs/03-protocol.md §7): PTY and exec sessions share one
//! message-mode stream in each direction.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    pub kind: SessionKind,
    /// Filtered by the server against its allow-list (docs/02-security.md).
    pub env: Vec<(String, String)>,
    pub pty: Option<PtyRequest>,
    /// Start directory; `~/` expanded, relative to home; unusable → home
    /// (reported through `Started::cwd_fallback`).
    pub cwd: Option<String>,
    /// Register the session server-side with an output ring addressable by
    /// `Open::Read`/`Open::Write` and keep it when this stream closes
    /// (the `session new` API). PTY sessions persist regardless when the
    /// server has a detach grace window.
    pub persist: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
    /// The server's login shell.
    Shell,
    /// `argv.len() == 1` runs through `$SHELL -c`; otherwise exec directly.
    Exec { argv: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyRequest {
    pub term: String,
    pub size: WinSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WinSize {
    pub cols: u16,
    pub rows: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

/// Client → server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionIn {
    Stdin(Vec<u8>),
    /// Exec: close the child's stdin. PTY: ignored.
    StdinEof,
    /// PTY only.
    Resize(WinSize),
    /// `kill(child_pid, sig)`.
    Signal(Signal),
}

/// Portable signal names; the server maps them to platform numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    Int,
    Term,
    Hup,
    Kill,
    Quit,
    Usr1,
    Usr2,
    Winch,
}

impl Signal {
    pub fn name(self) -> &'static str {
        match self {
            Self::Int => "INT",
            Self::Term => "TERM",
            Self::Hup => "HUP",
            Self::Kill => "KILL",
            Self::Quit => "QUIT",
            Self::Usr1 => "USR1",
            Self::Usr2 => "USR2",
            Self::Winch => "WINCH",
        }
    }

    /// Parse `TERM`, `SIGTERM`, `term`, or a number from the fixed set.
    pub fn parse(s: &str) -> Option<Self> {
        let upper = s.trim().to_ascii_uppercase();
        let name = upper.strip_prefix("SIG").unwrap_or(&upper);
        Some(match name {
            "INT" | "2" => Self::Int,
            "TERM" | "15" => Self::Term,
            "HUP" | "1" => Self::Hup,
            "KILL" | "9" => Self::Kill,
            "QUIT" | "3" => Self::Quit,
            "USR1" => Self::Usr1,
            "USR2" => Self::Usr2,
            "WINCH" => Self::Winch,
            _ => return None,
        })
    }
}

/// Server → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOut {
    /// Precedes any output. `cwd_fallback`: the requested cwd was unusable
    /// and the session started in home.
    Started {
        session: u32,
        pid: u32,
        cwd_fallback: bool,
    },
    Stdout(Vec<u8>),
    /// Exec without PTY only.
    Stderr(Vec<u8>),
    /// Last message; the server then closes its write side.
    Exited(ExitStatus),
    /// First message on an `Open::Attach` stream, in place of `Started`.
    /// `buffered` bytes of output captured while detached follow as
    /// `Stdout` before live traffic; `dropped` were lost to the ring cap.
    Attached {
        session: u32,
        pid: u32,
        buffered: u64,
        dropped: u64,
    },
}

/// One entry of the `Open::ListSessions` reply: a registered session,
/// attached (`detached: None`) or kept for the detach grace window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSession {
    pub id: u32,
    pub pid: u32,
    /// `"shell"` or the exec command line.
    pub kind: String,
    /// Seconds since the Unix epoch.
    pub started: i64,
    /// Seconds since the Unix epoch; `None` while a client is attached.
    pub detached: Option<i64>,
    /// Output bytes buffered while detached.
    pub buffered: u64,
    pub pty: bool,
    /// Absolute offset just past the newest byte in the ring.
    pub next: u64,
    /// Absolute offset of the oldest byte still in the ring.
    pub oldest: u64,
    /// Set once the process has exited (the entry stays for the grace window).
    pub exited: Option<ExitStatus>,
}

/// Which output stream a ring chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutStream {
    Stdout,
    Stderr,
}

/// A run of bytes from one output stream, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub stream: OutStream,
    pub bytes: Vec<u8>,
}

/// Reply to `Open::Read { session, offset, max, wait_ms }`.
///
/// Offsets are absolute byte counts over everything the session ever
/// produced (stdout and stderr interleaved in arrival order), so a reader
/// can poll idempotently: the same `offset` returns the same bytes until
/// they age out of the ring, which `oldest` reveals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReply {
    /// Offset of the first byte returned (≥ the requested offset; greater
    /// when the request fell behind `oldest`).
    pub offset: u64,
    /// Offset to pass next.
    pub next: u64,
    /// Oldest offset still available.
    pub oldest: u64,
    pub chunks: Vec<Chunk>,
    /// The process has exited; `next` is final once this is set and
    /// `chunks` is empty.
    pub exited: Option<ExitStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    Code(i32),
    Signal { signal: i32, core_dumped: bool },
}

impl ExitStatus {
    /// Shell convention: `n` for a normal exit, `128 + signal` otherwise.
    pub fn shell_code(self) -> i32 {
        match self {
            Self::Code(n) => n,
            Self::Signal { signal, .. } => 128 + signal,
        }
    }
}

impl core::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Code(n) => write!(f, "exit {n}"),
            Self::Signal {
                signal,
                core_dumped: true,
            } => write!(f, "signal {signal} (core dumped)"),
            Self::Signal {
                signal,
                core_dumped: false,
            } => write!(f, "signal {signal}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_parse_accepts_common_spellings() {
        assert_eq!(Signal::parse("TERM"), Some(Signal::Term));
        assert_eq!(Signal::parse("sigint"), Some(Signal::Int));
        assert_eq!(Signal::parse("9"), Some(Signal::Kill));
        assert_eq!(Signal::parse("STOP"), None);
    }

    #[test]
    fn exit_status_shell_code() {
        assert_eq!(ExitStatus::Code(3).shell_code(), 3);
        assert_eq!(
            ExitStatus::Signal {
                signal: 9,
                core_dumped: false
            }
            .shell_code(),
            137
        );
    }
}
