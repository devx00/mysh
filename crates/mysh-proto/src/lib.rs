//! Wire protocol shared by the mysh client and server.
//!
//! This crate holds constants and `serde`/`postcard` message types only.
//! It performs no I/O and holds no secrets. The authoritative description of
//! the protocol lives in `docs/03-protocol.md`; this crate must track it.

#![forbid(unsafe_code)]

/// Cleartext preamble magic sent by both peers before the Noise handshake.
pub const MAGIC: [u8; 4] = *b"MYSH";

/// Highest protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Noise handshake pattern. Fixed; there is no cipher negotiation.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Default TCP port for `mysh serve`.
pub const DEFAULT_PORT: u16 = 7722;

/// Largest Noise transport message, including the 16-byte AEAD tag.
pub const NOISE_MAX_MESSAGE: usize = 65_535;

/// Largest framed control message inside a stream (see docs/03-protocol.md).
pub const MAX_CONTROL_MESSAGE: usize = 256 * 1024;
