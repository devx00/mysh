//! `Open::Info` reply (docs/03-protocol.md §10quater): facts about the
//! server that a client — or an agent driving one — needs before running
//! anything. Pure data; the server fills it, the client prints it as JSON.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// `ServerHello.name`.
    pub name: String,
    /// mysh version string of the server binary.
    pub version: String,
    pub platform: Platform,
    /// Login shell used for `Shell` sessions.
    pub shell: String,
    pub home: String,
    pub user: String,
    /// Capability bits, as in `ServerHello.caps`.
    pub caps: u32,
    pub limits: Limits,
    /// Seconds since the server process started.
    pub uptime_secs: u64,
    /// The `authorized_keys` file the server trusts and `authorize` appends
    /// to (`--authorized-keys`, else `<config dir>/authorized_keys`),
    /// already absolute.
    pub authorized_keys: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// `std::env::consts::OS` of the server (`linux`, `macos`, `android`).
    pub os: String,
    /// `std::env::consts::ARCH` (`aarch64`, `x86_64`).
    pub arch: String,
    /// `uname -r` equivalent, best effort; empty when unknown.
    pub kernel: String,
}

/// Effective limits for this connection (per-key options applied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_sessions: u32,
    pub max_listeners: u32,
    pub max_streams: u32,
    pub detach_grace_secs: u64,
    pub idle_timeout_secs: u64,
    pub handshakes_per_minute: u32,
    /// Features switched off for this connection, by name
    /// (`pty`, `exec`, `files`, `forward-local`, `forward-remote`).
    pub denied: Vec<String>,
}
