//! TCP forwarding (docs/03-protocol.md §8). `DirectTcp` and `ForwardedTcp`
//! are raw after the prologue; `ForwardListen` carries one message.

use serde::{Deserialize, Serialize};

/// Server → client on a `ForwardListen` stream after `OpenReply::Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bound {
    /// Identifier echoed in `Open::ForwardedTcp { listener }`.
    pub listener: u32,
    /// Actual bound port (differs from the request when 0 was asked for).
    pub port: u16,
}
