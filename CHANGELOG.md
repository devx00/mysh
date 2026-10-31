# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Milestones M1–M3 of `docs/06-roadmap.md` are implemented: mysh connects,
authenticates, runs interactive and non-interactive sessions, transfers
files and forwards ports on Linux, macOS and Android.

### Added

- **Transport** (`mysh-proto`, `mysh-net`): versioned preamble bound into the
  Noise prologue, `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake with the
  server verified before the client reveals its identity, a `Verdict`
  message carrying the authorization result, `NoiseStream` over 16-bit
  length frames, yamux multiplexing with an `Open`/`OpenReply` prologue per
  stream, and postcard message types for every stream kind.
- **Identity and trust**: native X25519 key files, OpenSSH ed25519 reuse
  (including passphrase-protected keys) via the standard birational map,
  `SHA256:` fingerprints, `authorized_keys` and `known_hosts` parsers for
  both mysh and OpenSSH formats (incl. hashed hostnames), `--pin`, TOFU with
  `--accept-new`/`--strict`, and the `baked` feature that compiles an
  identity plus trusted peers into the binary (`--baked-only` ignores disk).
- **Server** (`mysh serve`): loopback-to-wildcard listeners, per-connection
  authorization, control stream with pings and shutdown notices, PTY and
  exec sessions (login shell, `$SHELL -c`, env allow-list, start directory
  with fallback), file service (stat/list/mkdir/remove/rename/setattr/
  realpath/get/put with atomic writes and resume), `-L`/`-R` forwarding with
  half-close propagation, feature denials (`--deny`), and quotas.
- **Client**: the meta shell is the home state (`mysh HOST` lands at a
  prompt); `shell` opens real PTY sessions and `Ctrl-]` returns to the
  prompt without disturbing them; session stack with 1 MiB background rings
  replayed on `fg`; built-in line editor with history; `put`, `get`, `ls`,
  `cwd`, `lcd`, `forward`, `exec`, `info`, `ping`, `resize`, `log`,
  `authorize`, `sessions`, `fg`, `kill`, `send`, `exit`, `disconnect`; the
  same commands as CLI subcommands; `-s`, `-N`, `CMD`, and scripted-stdin
  modes; `-L`/`-R`/`-D` (SOCKS5) forwards.
- **Platform layer** (`mysh-pty`): pty pairs, controlling-tty spawn, window
  size and resize, raw-mode guard, `SIGWINCH`/`SIGCONT`, cwd probe via
  `/proc` or `proc_pidinfo`, shell/home/user resolution for glibc, musl,
  macOS and bionic.
- **Control socket, background jobs, parallel transfers** (M5): an
  interactive client listens on `$XDG_RUNTIME_DIR/mysh/<host>_<port>.sock`
  and `mysh put|get|forward|authorize HOST …` reuse its connection when the
  socket is there (`--no-ctl` opts out); a prompt line ending in `&` runs as
  a job (`jobs [-w] [ID]`, `kill %ID`, completion notices above the
  prompt); `put -r`/`get -r` transfer `-j N` files at a time (default 4)
  with one aggregate progress line.
- **Verification**: 239 tests (unit plus integration against an in-process
  loopback server, including real-pty interactive tests); `scripts/
  android-build.sh` links an Android binary with the NDK clang;
  `scripts/lima-test.sh` runs the suite on Linux in a lima VM.

### Changed

- `docs/`: the meta shell became the home state with a single-byte meta key
  (`Ctrl-]`) replacing ssh-style `~` escapes; `put`/`get` use `-P`/`-F`
  because `-p`/`-L` are connection options; `snow` is built without its
  `std` feature (it pulls in `ring`); the built-in line editor replaced
  `rustyline`; TCP keep-alive is not set (tokio exposes no API).
