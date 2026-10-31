//! Control stream (docs/03-protocol.md §6): keep-alive and connection-level
//! notices. Message mode in both directions.

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
}
