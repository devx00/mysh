//! Pairing (docs/02-security.md "Pairing"): first contact with a one-time
//! code. Messages on an `Open::Pair` stream, message mode, strictly in
//! this order: `ClientStart`, `ServerStart`, `ClientConfirm`,
//! `ServerConfirm`, `Done`.
//!
//! SPAKE2 (Ed25519 group) with identities = the two Noise static public
//! keys and password = the normalized code, then explicit key confirmation
//! client-first. `T` in the confirmation MACs is
//! `client_static ‖ server_static ‖ client_msg ‖ server_msg`.

use serde::{Deserialize, Serialize};

/// Words per pairing code.
pub const CODE_WORDS: usize = 6;

/// Domain-separation labels for the key-confirmation MACs.
pub const CLIENT_CONFIRM_LABEL: &[u8] = b"mysh-pair-client-v1";
pub const SERVER_CONFIRM_LABEL: &[u8] = b"mysh-pair-server-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairMsg {
    /// Client → server: SPAKE2 message A.
    ClientStart { msg: Vec<u8> },
    /// Server → client: SPAKE2 message B.
    ServerStart { msg: Vec<u8> },
    /// Client → server: `HMAC-SHA256(K, CLIENT_CONFIRM_LABEL ‖ T)`.
    ClientConfirm { mac: [u8; 32] },
    /// Server → client: `HMAC-SHA256(K, SERVER_CONFIRM_LABEL ‖ T)`; only
    /// sent after the client's MAC verified.
    ServerConfirm { mac: [u8; 32] },
    /// Server → client, last message: what was installed.
    Done {
        /// The `authorized_keys` line the server appended.
        authorized_line: String,
        /// The server's public key line for the client's `known_hosts`.
        host_line: String,
    },
    /// Either side, instead of the next expected message.
    Failed { reason: String },
}

/// Normalize a user-typed code: lowercase, words separated by single
/// hyphens, surrounding whitespace removed. Accepts spaces or hyphens.
pub fn normalize_code(input: &str) -> String {
    input
        .split(|c: char| c.is_whitespace() || c == '-')
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_spacing_and_case() {
        assert_eq!(
            normalize_code("  Apple-Bread  cat\tdog "),
            "apple-bread-cat-dog"
        );
        assert_eq!(normalize_code("a--b"), "a-b");
        assert_eq!(normalize_code(""), "");
    }
}
