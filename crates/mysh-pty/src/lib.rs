//! Platform layer for mysh. The only crate in the workspace allowed to use
//! `unsafe` (ioctls, `pre_exec`, `proc_pidinfo`).
//!
//! Supported targets: Linux (glibc/musl), macOS, Android (bionic). Everything
//! platform-specific lives here behind a uniform API so the client and server
//! stay free of `cfg(target_os)`; see `docs/04-sessions.md` and the platform
//! matrix in `docs/01-architecture.md`.
//!
//! - [`pty`]: open a pty pair, resize, foreground process group, async master
//! - [`spawn`]: spawn a child with the slave as controlling tty, or with pipes
//! - [`process`]: cwd probe, signals, exit status mapping, shell/home/user
//! - [`terminal`]: client-side raw mode guard, window size, signal plumbing

#![deny(unsafe_op_in_unsafe_fn)]

pub mod process;
pub mod pty;
pub mod spawn;
pub mod terminal;
