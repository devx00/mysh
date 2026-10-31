//! Encrypted, authenticated, multiplexed transport for mysh.
//!
//! Responsibilities (see `docs/02-security.md` and `docs/03-protocol.md`):
//! - [`keys`]: key types, key files, fingerprints, OpenSSH ed25519 conversion
//! - [`trust`]: `authorized_keys` / `known_hosts` stores, pins
//! - [`handshake`]: version preamble, `Noise_XX_25519_ChaChaPoly_BLAKE2s`,
//!   post-handshake verdict
//! - [`noise`]: `NoiseStream`, `AsyncRead + AsyncWrite` over length-framed
//!   Noise transport messages
//! - [`framing`]: async `Msg<T>` and `Open`/`OpenReply` helpers
//! - [`mux`]: yamux multiplexing and the per-stream prologue
//! - [`agent`]: OpenSSH `ssh-agent` client (list ed25519 identities, sign)

#![forbid(unsafe_code)]

pub mod agent;
pub mod framing;
pub mod handshake;
pub mod keys;
pub mod mux;
pub mod noise;
pub mod trust;
