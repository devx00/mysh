# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Workspace scaffold: `mysh-proto`, `mysh-net`, `mysh-pty`, `mysh` crates;
  pinned toolchain, lints, CI, `cargo-deny` policy.
- Design documents under `docs/` (architecture, security, protocol,
  sessions, meta shell, roadmap).
- `baked` feature plumbing in `crates/mysh/build.rs`.
- `mysh serve` core: listeners with `[::]`→`0.0.0.0` fallback, handshake
  semaphore, authorization against the trust set, control stream
  (ping/pong, idle timeout, graceful `Shutdown`), stream dispatch, PTY and
  exec sessions with the env allow-list, and the cwd probe.
