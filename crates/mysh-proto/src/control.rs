//! Control stream (docs/03-protocol.md §6): keep-alive and connection-level
//! notices. Message mode in both directions.
//!
//! Variants are append-only: both sides ignore messages they do not know.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    /// Server → client; shown on the client's stderr / prompt.
    Notice(String),
    /// Either side; the peer finishes in-flight streams, then closes.
    Shutdown {
        reason: String,
    },
    /// Client → server: bind a listener at `addr` (`host:port`) so that
    /// ordinary clients can dial the server. `idle_secs` closes it after
    /// that long without an accepted connection (0: until `Unbind` or the
    /// server exits). Answered by `Bound` or `Unbound`.
    Bind {
        addr: String,
        idle_secs: u32,
    },
    /// Server → client: the requested listener is bound at `addr`
    /// (port 0 requests resolved).
    Bound {
        addr: String,
    },
    /// Server → client: the requested listener was refused or has closed.
    Unbound {
        addr: String,
        reason: String,
    },
    /// Client → server: close the requested listener.
    Unbind,
}
