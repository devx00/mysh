//! Platform layer for mysh. The only crate in the workspace allowed to use
//! `unsafe` (ioctls, `pre_exec`, `proc_pidinfo`).
//!
//! Supported targets: Linux (glibc/musl), macOS, Android (bionic). Everything
//! platform-specific lives here behind a uniform API so the client and server
//! stay free of `cfg(target_os)`; see `docs/04-sessions.md` and the platform
//! matrix in `docs/01-architecture.md`.
//!
//! Server side: open a pty pair, spawn a child with the slave as its
//! controlling terminal, resize the master, probe a process's cwd.
//! Client side: raw-mode guard for the local terminal, window size queries,
//! `SIGWINCH` / `SIGTSTP` / `SIGCONT` plumbing.

#![deny(unsafe_op_in_unsafe_fn)]
