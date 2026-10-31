//! Encrypted, authenticated, multiplexed transport for mysh.
//!
//! Responsibilities (see `docs/02-security.md` and `docs/03-protocol.md`):
//! - key types, key files, fingerprints, OpenSSH ed25519 key conversion
//! - `authorized_keys` / `known_hosts` trust stores (mysh and OpenSSH formats)
//! - version preamble and `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake
//! - `NoiseStream`: `AsyncRead + AsyncWrite` over length-framed Noise messages
//! - yamux multiplexing and the per-stream `Open` / `OpenReply` prologue

#![forbid(unsafe_code)]
