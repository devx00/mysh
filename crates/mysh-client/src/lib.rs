//! Everything a program needs to drive a mysh server, with no terminal
//! dependencies: connections and trust ([`conn`]), identities
//! ([`identity`]), configuration ([`config`]), remote processes
//! ([`session`]), files ([`files`]), port forwards ([`forward`]), the
//! control socket of a running `mysh` master ([`ctl`]), fleet fan-out
//! ([`fleet`]) and first-contact pairing ([`pair`]).
//!
//! [`Client`] is the facade most programs want; the modules underneath are
//! the same code the `mysh` binary runs, so behaviour matches the CLI
//! (docs/07-embedding.md).
//!
//! Output never goes to a terminal: every module reports through a
//! [`Reporter`] (progress, notices, session bytes, results) and asks a
//! [`TrustPrompt`] before trusting an unknown server key. The defaults
//! ([`NullReporter`], [`RefuseUnknown`]) are silent and refuse.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod args;
pub mod attach;
pub mod client;
pub mod config;
pub mod conn;
pub mod ctl;
pub mod error;
pub mod fileops;
pub mod files;
pub mod fleet;
pub mod forward;
pub mod identity;
pub mod pair;
pub mod report;
pub mod session;
pub mod session_api;
pub mod sync;
pub mod types;

pub use client::{Client, ExecRequest, Files, Sessions};
pub use error::{Error, Result};
pub use report::{NullReporter, RefuseUnknown, Reporter, TrustPrompt};
