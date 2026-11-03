//! `mysh`: client, server, and utilities. The binary in `main.rs` is a thin
//! wrapper so integration tests can drive everything through this library.
//!
//! Module layout per `docs/01-architecture.md`.

pub mod cli;
pub mod client;
pub mod config;
pub mod identity;
pub mod output;
pub mod server;
pub mod wordlist;

/// Key material compiled in with `--features baked` (docs/02-security.md).
pub mod baked {
    include!(concat!(env!("OUT_DIR"), "/baked.rs"));
}
