//! Wire protocol shared by the mysh client and server.
//!
//! This crate holds constants and `serde`/`postcard` message types only.
//! It performs no I/O and holds no secrets. The authoritative description of
//! the protocol lives in `docs/03-protocol.md`; this crate must track it.
//!
//! Layout follows the protocol sections:
//! - [`handshake`]: payloads carried inside Noise messages 2/3 and the
//!   post-handshake authorization verdict;
//! - [`frame`]: `Msg<T>` length-prefixed postcard framing used inside
//!   every message-mode stream;
//! - [`open`]: the per-stream prologue (`Open` / `OpenReply`);
//! - [`control`], [`session`], [`forward`], [`file`]: per-stream-kind
//!   messages.

#![forbid(unsafe_code)]

pub mod control;
pub mod file;
pub mod forward;
pub mod frame;
pub mod handshake;
pub mod info;
pub mod open;
pub mod pair;
pub mod session;

/// Cleartext preamble magic sent by both peers before the Noise handshake.
pub const MAGIC: [u8; 4] = *b"MYSH";

/// Highest protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Noise prologue prefix; the agreed `u16-LE` version is appended.
pub const PROLOGUE_PREFIX: &[u8] = b"mysh";

/// Noise handshake pattern. Fixed; there is no cipher negotiation.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Default TCP port for `mysh serve`.
pub const DEFAULT_PORT: u16 = 7722;

/// Largest Noise transport message on the wire, including the 16-byte tag.
pub const NOISE_MAX_MESSAGE: usize = 65_535;

/// AEAD tag length; `NOISE_MAX_MESSAGE - NOISE_TAG_LEN` is the plaintext cap.
pub const NOISE_TAG_LEN: usize = 16;

/// Largest framed control/stream message body (see `frame`).
pub const MAX_CONTROL_MESSAGE: usize = 256 * 1024;

/// Largest `Stdin`/`Stdout`/`Stderr` payload per session message.
pub const SESSION_CHUNK: usize = 64 * 1024;

/// Limits enforced per connection (docs/03-protocol.md §12).
pub mod limits {
    use core::time::Duration;

    /// Concurrent yamux streams per connection.
    pub const MAX_STREAMS: usize = 512;
    /// Concurrent sessions per connection.
    pub const MAX_SESSIONS: usize = 32;
    /// Concurrent remote (`-R`) listeners per connection.
    pub const MAX_LISTENERS: usize = 32;
    /// TCP accept → end of Noise message 3.
    pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
    /// Stream accepted → `OpenReply` sent.
    pub const OPEN_REPLY_DEADLINE: Duration = Duration::from_secs(10);
    /// Client ping cadence on the control stream.
    pub const PING_INTERVAL: Duration = Duration::from_secs(30);
    /// Unanswered pings before the client declares the connection dead.
    pub const PING_DEAD_AFTER: u32 = 3;
    /// Server closes a connection with no frames at all for this long.
    pub const SERVER_IDLE: Duration = Duration::from_secs(120);
    /// Yamux receive window at stream open.
    pub const YAMUX_INITIAL_WINDOW: u32 = 256 * 1024;
    /// Yamux receive window upper bound.
    pub const YAMUX_MAX_WINDOW: u32 = 4 * 1024 * 1024;
    /// Directory listing page size.
    pub const LIST_PAGE: usize = 1000;
    /// Handshakes accepted per source IP per minute (token bucket, burst =
    /// this value). Excess connections are closed before the handshake.
    pub const HANDSHAKES_PER_MINUTE: u32 = 10;
    /// Rekey after this many plaintext bytes in one direction …
    pub const REKEY_BYTES: u64 = 1 << 30;
    /// … or after this long since the last rekey, whichever comes first.
    pub const REKEY_INTERVAL: Duration = Duration::from_secs(3600);
    /// How long the server keeps a PTY session whose client went away.
    pub const DETACH_GRACE: Duration = Duration::from_secs(600);
    /// Output buffered per detached session; older bytes are dropped.
    pub const DETACHED_RING: usize = 1024 * 1024;
    /// Agent keys tried (one connection each) before giving up.
    pub const MAX_AGENT_KEYS: usize = 5;
    /// Default pairing window.
    pub const PAIR_WINDOW: Duration = Duration::from_secs(300);
    /// Largest `Open::Read` reply body; larger `max` values are clamped.
    pub const READ_MAX: u32 = 1024 * 1024;
    /// Longest an `Open::Read` may block waiting for output.
    pub const READ_WAIT_MAX: Duration = Duration::from_secs(60);
    /// Default master idle exit.
    pub const MASTER_IDLE: Duration = Duration::from_secs(600);
}

/// `ServerHello.caps` / `ClientHello.caps` bits. Zero means none.
pub mod caps {
    /// Server: accepts ed25519 signature proofs in `ClientHello.auth`.
    pub const SIG_AUTH: u32 = 1;
    /// Server: keeps detached PTY sessions (`Open::Attach`, `ListSessions`).
    pub const PERSIST: u32 = 2;
    /// Client: this connection asks to pair (no authorization expected).
    pub const PAIR_REQUEST: u32 = 4;
}
