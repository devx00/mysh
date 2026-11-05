# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Milestones M1–M12 of `docs/06-roadmap.md` are implemented: mysh connects,
authenticates, runs interactive and non-interactive sessions that survive a
disconnect, transfers files and forwards ports on Linux, macOS and Android,
ships as static release binaries, and exposes everything to programs through
structured output, a session read/write API, a library crate and an MCP
server.

### Added

- **`cargo xtask install`**: builds the client and installs it to
  `~/.local/bin`, copies the `dist/` artifacts (`mysh-<version>-<target>`,
  `SHA256SUMS`) into the assets directory `mysh assets` reads
  (`~/.local/share/mysh`, or `--assets-dir` recorded as `[assets] dir` in
  `config.toml`), and runs `mysh skill install`; `--dist` runs
  `scripts/release.sh` first, `--dry-run` prints the plan.
- **`mysh assets`**: lists the installed per-target server binaries
  (`$MYSH_ASSETS_DIR` → `[assets] dir` → `~/.local/share/mysh`) with
  version, size and checksum; `--for "$(uname -sm)"` (or `OS/ARCH`, or a
  triple) prints the one a remote machine needs, `not_found` naming the
  target to build otherwise. New `[assets]` config table.
- **`mysh skill`**: the agent skill is embedded in the binary; `install`
  writes it for every coding agent present (`~/.agents/skills` always,
  `~/.claude`, `~/.codex`, `~/.cursor`, `~/.copilot`, `~/.openclaw` when
  found; `--to DIR`), `list` shows where and whether each copy is current,
  `show` prints it. The skill gained the deployment flow (`mysh assets
  --for`, `serve --daemon`), connect-back addressing and its own install.
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
- **Hardening** (M4): in-band rekey below yamux every 1 GiB or 1 h per
  direction; `authorized_keys` options `command=`, `no-pty`, `no-files`,
  `no-forward`, `from=` (IP, CIDR, glob, negation) and `restrict`; per-IP
  handshake rate limiting (`--handshake-rate`), `--idle-timeout`, quotas
  for sessions, listeners and streams; 16 libFuzzer targets over every
  decoder and parser (`scripts/fuzz-all.sh`).
- **Session persistence** (M5): PTY sessions outlive a disconnect for
  `--detach-grace` (default 10 min) with a 1 MiB server-side output ring;
  `mysh --attach[=ID] HOST`, prompt commands `attach`, `detach`,
  `sessions -a`; a session can only be reattached by the key that opened it.
- **Signature authentication** (M5): ed25519 keys held by an `ssh-agent`
  log in without ever leaving the agent — the client uses a fresh Noise
  static per connection and the agent signs the handshake hash
  (`ClientHello.auth`, `caps::SIG_AUTH`, `--no-signature-auth` on the
  server); `-i key.pub` picks an agent key, otherwise the key file is tried
  first and then up to five agent keys from `$SSH_AUTH_SOCK`; the server
  authorizes the ed25519 key against its `ssh-ed25519` entries and owns
  detached sessions by it. `info` shows which identity was accepted.
- **Control socket, background jobs, parallel transfers** (M5): an
  interactive client listens on `$XDG_RUNTIME_DIR/mysh/<host>_<port>.sock`
  and `mysh put|get|forward|authorize HOST …` reuse its connection when the
  socket is there (`--no-ctl` opts out); a prompt line ending in `&` runs as
  a job (`jobs [-w] [ID]`, `kill %ID`, completion notices above the
  prompt); `put -r`/`get -r` transfer `-j N` files at a time (default 4)
  with one aggregate progress line.
- **Prompt** (M5): Tab completion of local paths and `Ctrl-R` reverse
  history search.
- **Structured output** (M6): `--json` (one document per command, errors
  as `{"error": {"code", "message"}}` on stderr with stable codes),
  `--json-stream` (NDJSON `started`/`stdout`/`stderr`/`exit`/`progress`/
  `notice`/`error`/`result` events, base64 for non-UTF-8 chunks) and
  `--plain` on every HOST command and the prompt; typed result shapes in
  `mysh::output`; `--timeout DURATION` (TERM, KILL after 2 s, exit 124) and
  `--cwd DIR` for `CMD`/`exec`; `stat REMOTE`; `Open::Info` (server
  version, platform, kernel, shell, home, user, caps, limits, uptime) shown
  by `info`; `mysh help --json [CMD]` and the prompt's `help --json` print
  the clap command tree (docs/05 "Agent interface", docs/03 §10quater).
- **File primitives** (M8): `get REMOTE -` / `put - REMOTE` stream through
  stdout/stdin (`--mode`, `--mtime`); `cat`, `write [--mode] [--append]`,
  `tail [-n N] [-f] [--for D]` (server-side `FileOp::Get { follow: true }`,
  ends cleanly on Ctrl-C or a deadline), `stat REMOTE…`, `mkdir [-P] [-m]`,
  `rm [-r]`, `mv`, `realpath` and `hash` as CLI subcommands, prompt
  commands and over the control socket; `put/get --checksum` skip files
  whose size and BLAKE2s-256 digest match (`FileOp::Hash`, the summary
  gains `skipped`); `sync [--pull] [--delete] [--dry-run] [--checksum]
  [-j N] SRC DST` mirrors a tree in either direction with a `SyncPlan` /
  `SyncSummary` (docs/03 §9, docs/04 "File primitives", "sync").
- **Pairing** (M9): `mysh serve --pair [DURATION]` prints a one-time
  6-word code (BIP-39 words; `SIGUSR1` opens a new window on a running
  server) and `mysh pair HOST CODE` runs SPAKE2 (`spake2`, Ed25519 group)
  with it inside the normal Noise connection — `caps::PAIR_REQUEST`,
  `Verdict::Pairing`, `Open::Pair` + `PairMsg` — then installs the client
  key in the server's `authorized_keys` and pins the server key in
  `known_hosts`, each side only after the other's confirmation MAC
  verified. Windows are single-use and expire; a wrong code closes one.
  `--json` prints `PairOut` (docs/02 "Pairing", docs/03 §10quinquies).
- **Fleet** (M9): `mysh run [-j N] (--hosts a,b | --group NAME)… -- CMD`
  runs one command on many hosts (through a host's master or control
  socket when one serves it, else a fresh connection), prints
  `host: line` / `host! line` interleaved plus a summary table, or a
  `--json` array of `RunResult` in selection order (`--json-stream`: `host`
  events); a dead host is `connect_failed` without affecting the others;
  exit 0 iff all exited 0. `put/get --hosts …` fan the same transfer out
  (`get` lands in `LOCALDIR/<host>/`, JSON `TransferResult`).
  `[groups.NAME] hosts = [...]` in `config.toml` (docs/05 "Fleet").
- **Audit log** (M9): `mysh serve --audit PATH` (`-` = stderr) appends one
  JSON line per event — `connect`, `disconnect`, `session`, `exec`, `file`,
  `forward`, `pair`, `denied` — with peer, key fingerprint, detail, exit,
  bytes and duration, through one writer task (0600, `O_APPEND`, flushed
  per line, no rotation) (docs/02 "Audit log").
- **`mysh-client` crate** (M10): the client half of the binary — config
  and paths, identities and trust, `Connection`, the session stack and the
  remote process API, files/sync, forwards, the control-socket requester
  and master spawn, fleet fan-out, pairing, and every `--json` type — is
  now a library with no terminal dependencies. Output goes through a
  `Reporter` trait (the binary's console implements it) and unknown host
  keys through a `TrustPrompt` (refuses by default; passphrases too). The
  `Client` facade (`connect`, `exec`/`exec_stream`, `info`, `sessions()`,
  `files()`, `forwards()`, `close`) returns the same documents the CLI
  prints; `fleet::run` fans an exec out; `Error` carries the stable M6
  code. The clap request structs (`PutArgs`, `SessionArgs`, …) live in
  `mysh_client::args`; the binary re-exports everything at its old paths
  (docs/07 "Library", docs/01 crate list).
- **MCP server** (M10): `mysh mcp (--hosts a,b | --group NAME)…
  [--accept-new] [-i PATH] [--allow-local-paths]` serves the Model Context
  Protocol over stdio (JSON-RPC 2.0, newline-delimited or `Content-Length`
  framed): tools `exec`, `read_file`, `write_file`, `list_dir`, `stat`,
  `session_new/send/read/kill/list`, `put`, `get`, `info`, `hosts` with
  input and output schemas, `mysh://HOST/path` resources, one lazily opened
  connection per host reopened after a loss, the M6 error codes as
  `isError` results, TOFU only through `--accept-new` (never a prompt),
  local `put`/`get` only with `--allow-local-paths`. `contrib/mcp/` has an
  example client configuration (docs/07 "MCP server").
- **Release** (M4): `scripts/release.sh` links all five targets and writes
  `SHA256SUMS`; `.github/workflows/release.yml` does the same on tags;
  `contrib/` has a systemd unit, a launchd plist and a Termux:Boot script.
- **Build matrix** (M11): `scripts/release.sh` builds the
  required set from one target table — Linux musl `x86_64`, `aarch64`,
  `i686`, `armv7`, `arm` (v6), `riscv64gc` (static, via zig /
  `cargo zigbuild`), FreeBSD `x86_64`, `aarch64` (zig), Android `aarch64`,
  `armv7`, `x86_64` (NDK clang, API 24), macOS `aarch64`, `x86_64` and a
  `lipo` universal binary — 14 artifacts plus a verified `SHA256SUMS` and a
  summary table; `--stretch` adds 12 rows: `i686` android, `armv5te`,
  `powerpc64le`, `loongarch64`, `s390x` musl, `mipsel`/`mips` musl,
  `s390x` gnu, NetBSD `x86_64`/`aarch64` and OpenBSD `x86_64`/`aarch64`
  (tier-3 rows build std on nightly, the BSDs link through a `zig cc`
  wrapper; `mips64el` and illumos are documented as not shipped).
  `scripts/validate-dist.sh` runs every Linux artifact under docker +
  qemu-user with a keygen and loopback serve/exec round trip
  (`PASS`/`FAIL`/`SKIP` per target; 32-bit MIPS through Alpine's
  `qemu-<arch>`, `MYSH_DOCKER_LIBRARY` for a registry mirror). `cargo
  check-matrix` / `check-matrix-stretch` / `scripts/check-tier3.sh`,
  `rust-toolchain.toml` and the CI `cross-check` (+ non-blocking
  `cross-check-stretch`) matrices list the same targets; the release
  workflow builds darwin on macOS, musl/FreeBSD with zig and Android with
  the NDK on ubuntu, plus a non-blocking `stretch` job (docs/01 "Build",
  "Platform matrix").
- **Verification**: 441 tests (unit plus integration against an in-process
  loopback server, including real-pty interactive, persistence,
  control-socket, JSON, session-API, fleet, audit, pairing, library-API and
  MCP conformance tests); 23 fuzz targets; `scripts/android-build.sh` links
  an Android binary with the NDK clang; `scripts/lima-test.sh` runs the
  suite on Linux in a lima VM.
- **Connect-back (server)** (M12): `mysh serve --connect-back ADDR`
  (repeatable) dials a client that accepts connections and serves it
  through the ordinary handshake and connection path; `--connect-period`
  (default `5m`, start-to-start), `--connect-jitter` (default 10 %),
  `--connect-max` (default `30m`; the server ends the connection with a
  `Shutdown` notice). One connection per address at a time, failures backed
  off 5 s doubling up to the period; `--listen` stays optional. Control
  messages `Bind`/`Bound`/`Unbound`/`Unbind` let an authorized client ask a
  server started with `--allow-bind-request` to bind a listener (idle
  expiry, `Unbind`, process-owned). Audit lines gained
  `direction: inbound|outbound`; `RateLimiter` moved to
  `mysh-net::ratelimit`; `contrib/mysh-connect-back.service` is a second
  systemd unit (docs/03 §1 and §6, docs/05 "Server options").
- **Accepting connections (client)** (M12): `mysh accept [ADDR]
  [--callers PATH] [--accept-new] [--handshakes-per-minute N] [--json]`
  listens for servers started with `serve --connect-back` and prints
  `accepted`/`closed`/`refused` lines (NDJSON with `--json`). Callers — the
  servers allowed to connect back — live in `~/.config/mysh/callers` in
  `authorized_keys` line format and are matched by key fingerprint, never
  by address; the comment names the connection. Each accepted connection
  gets a control socket at `<runtime>/mysh/@NAME.sock`, so every command
  addresses it as `@NAME` (`mysh @host-a uptime`, `put … @host-a`,
  `run --hosts @host-a,@host-b`) and never dials. New client command `bind
  [ADDR|off] [--for D]` asks a server running with `--allow-bind-request`
  for a listener of its own (`denied` otherwise). Library:
  `mysh_client::accept::{Acceptor, AcceptOpts, Inbound}`,
  `conn::accept_connection`, `Client::from_connection`,
  `identity::{Callers, Caller}`, `Connection::bind`/`unbind`
  (docs/02 "Callers", docs/05 "Accepting connections", docs/07).
- **User guide**: `docs/guide/` (getting started, meta shell, sessions,
  files, forwarding, automation, MCP, library, keys and trust, server,
  config, platforms, troubleshooting) plus `docs/guide/cli-reference.md`
  generated from `mysh help --json` by `scripts/gen-cli-reference.py`; the
  README is a front page again; `skills/mysh/SKILL.md` for agents.
- **Fixes found while documenting**: `mysh authorize` writes to the
  `authorized_keys` the server reports in `Info` (new field; a server with
  a non-default `MYSH_CONFIG_DIR` used to leave the key untrusted);
  `mkdir -P` follows a parent that is a symlink to a directory; `error: …`
  lines go to stderr unless drawn on a terminal, and a command failing
  through a master keeps the requester's `--json` shape; `mysh master
  --daemon` detaches instead of running in the foreground.
- **`--daemon` for `serve` and `accept`**: detach (own process group, no
  terminal, log appended to `--log` or `$XDG_STATE_HOME/mysh/<cmd>.log`,
  `--pid-file`) and exit 0 only once the child is listening/accepting — or
  1 with the child's log lines if it failed first. `SIGHUP` is now really
  ignored by both (the docs said so; no handler was installed).

### Changed

- `docs/`: the meta shell became the home state with a single-byte meta key
  (`Ctrl-]`) replacing ssh-style `~` escapes; `put`/`get` use `-P`/`-F`
  because `-p`/`-L` are connection options; `snow` is built without its
  `std` feature (it pulls in `ring`); the built-in line editor replaced
  `rustyline`; TCP keep-alive is not set (tokio exposes no API).
