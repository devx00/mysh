//! Payloads inside Noise handshake messages and the authorization verdict
//! that immediately follows (docs/03-protocol.md §2–3).

use serde::{Deserialize, Serialize};

use crate::open::ErrorCode;

/// Payload of Noise message 2 (server → client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    /// Informational server name (hostname by default).
    pub name: String,
    /// Reserved capability bits; zero in v1.
    pub caps: u32,
}

/// Payload of Noise message 3 (client → server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// Reserved capability bits; zero in v1.
    pub caps: u32,
}

/// First transport-mode message, server → client, sent as `Msg<Verdict>`
/// before any yamux frame. `Denied` is followed by connection close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accepted,
    Denied { code: ErrorCode, message: String },
}
