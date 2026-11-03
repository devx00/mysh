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

/// Domain-separation label prefixed to the handshake hash when signing
/// an [`AuthProof::Ed25519`] proof.
pub const SIG_AUTH_LABEL: &[u8] = b"mysh-sig-auth-v1";

/// Payload of Noise message 3 (client → server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// Reserved capability bits; zero in v1.
    pub caps: u32,
    /// How the client proves its identity.
    pub auth: AuthProof,
}

/// Client identity proof carried in [`ClientHello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthProof {
    /// The Noise static key is the identity (default).
    Static,
    /// `signature` = Ed25519(sk, [`SIG_AUTH_LABEL`] ‖ h2) where h2 is the
    /// Noise handshake hash after message 2; 64 bytes (a `Vec` because
    /// serde's array support stops at 32).
    Ed25519 {
        public_key: [u8; 32],
        signature: Vec<u8>,
    },
}

/// First transport-mode message, server → client, sent as `Msg<Verdict>`
/// before any yamux frame. `Denied` is followed by connection close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accepted,
    Denied {
        code: ErrorCode,
        message: String,
    },
    /// Accepted for pairing only (the client set `caps::PAIR_REQUEST` and a
    /// pairing window is open): the server accepts `Open::Control` and one
    /// `Open::Pair` stream, nothing else.
    Pairing,
}
