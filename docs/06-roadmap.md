# 06 — Roadmap, decisions, testing

## Milestones

Each milestone ends with a tagged build that works on Linux and macOS; Android
is smoke-tested from M2 onward.

### M0 — scaffold ✔

Workspace, lints, CI, this spec.

### M1 — authenticated transport + remote exec

- `mysh-proto`: constants, `Open`/`OpenReply`, control and session messages.
- `mysh-net`: key files (native + OpenSSH ed25519, encrypted), fingerprints,
  `authorized_keys`/`known_hosts` parsers (mysh + OpenSSH, hashed hosts),
  preamble, XX handshake, `NoiseStream`, yamux setup, stream prologue.
- `mysh keygen`, `mysh fingerprint`, `mysh serve`, `mysh HOST CMD` (exec, no
  PTY), TOFU prompt, `--pin`, `--accept-new`, `--strict`, `--baked-only`,
  `baked` feature end-to-end.
- Tests: handshake + authorization on loopback (authorized, unauthorized,
  wrong pin, TOFU accept/reject), key conversion vectors cross-checked
  against `age`/`ssh-keygen` output, exec exit-code propagation.

### M2 — interactive PTY

- `mysh-pty`: pty pair, controlling-tty spawn, winsize, cwd probe, raw mode
  guard, signal plumbing (all three platforms).
- Session stream: `Shell`, `Resize`, suspend/resume, meta-key interception,
  exit status including signals, `Exited` ordering after EOF.
- Shell/home/env resolution per platform table.
- Android smoke: `cross build`, `adb push`, serve from `adb shell`, connect
  from macOS, resize, `vim`.
- Tests: pty session runs `sh -c 'stty size'` and sees the requested size;
  resize mid-session is observed; exit via signal maps to `128+n`.

### M3 — meta shell, files, forwards

- The prompt as home: line editor with history, connect banner, scripted
  stdin mode, `-s`, auto-exit rules; CLI subcommands over the same
  dispatcher.
- Session stack: `shell` (login shell or `CMD` under a PTY, in the MRU
  session's cwd), `fg`, `sessions`, `kill`, `send`; background ring buffers
  with replay; `-N` stays stdin-free.
- `put`/`get`/`ls`/`cwd`/`lcd` with progress, resume, recursion, atomic
  writes; cwd probe integration.
- `-L`/`-R`/`-D`, runtime `forward` management, `-N`.
- `exec`, `info`, `ping`, `resize`, `log`, `authorize`, `disconnect`.
- Config aliases.
- Tests: file round-trips (empty, 1 byte, > window size, resume at offset,
  mode/mtime), directory recursion with symlinks, forward echo through
  `-L`/`-R`/SOCKS5, meta key inside split reads; session stack: push via
  `shell`, background output lands in the ring and is replayed on `fg`,
  drop accounting past 1 MiB, exit of a prompt-opened session vs the
  primary under `-s`, `exit` refused while sessions run, client exit code
  follows the primary, `cwd` honoured and `cwd_fallback` reported.

### M4 — hardening and release

- Handshake rate limit per source IP; idle timeouts; stream/listener quotas
  enforced with tests.
- Session rekey (`snow` `rekey` on a `Rekey` control message) every 1 GiB or
  1 h, whichever first.
- Per-key options in `authorized_keys`: `command=`, `no-pty`, `no-files`,
  `no-forward`, `from=`.
- Fuzz targets for every postcard decoder and the key/known_hosts parsers.
- Release workflow: static artifacts for the five targets, checksums,
  `contrib/` systemd unit, launchd plist, Termux:Boot script.

### M5 — quality of life

- Control socket (05-meta-shell.md) so CLI subcommands reuse a live session.
- Session persistence: server keeps the pty alive for N minutes after
  disconnect, replays a bounded output ring on reattach (`dtach` model, not
  a terminal emulator), `mysh HOST --attach`.
- Signature authentication (`NN` + ed25519 signature over the handshake
  hash) enabling `ssh-agent`, `sk-*` keys, and keys that cannot be exported.
- Background transfers (`put … &`, `jobs`), parallel recursive transfers.
- Local path completion at the prompt.
- Post-quantum hybrid (X25519 + ML-KEM) if `snow` or a successor exposes it.

## Decisions log

Defaults chosen without asking; each is cheap to change now and expensive
later.

| # | decision                                             | alternative                      | reason                                                                 |
| - | ---------------------------------------------------- | -------------------------------- | ---------------------------------------------------------------------- |
| 1 | Noise XX with X25519 statics; ssh ed25519 via conversion | signature-based auth (agent support) | one mechanism, identity hiding, proven by `age`; agent added later as a method |
| 2 | baked = identity + peers, both roles, files extend   | PSK-only (`NNpsk0`) keyless mode | same handshake code path; PSK offers no advantage once the binary is the credential |
| 3 | yamux for multiplexing                               | hand-rolled mux                  | flow control correctness; replaceable without touching messages        |
| 4 | one message-mode stream per session                  | control stream + raw data stream | ordering, simplicity, negligible overhead                              |
| 5 | single binary with `serve` subcommand                | separate `myshd`                 | one artifact per device; Android deployment                            |
| 6 | server runs as its launching user only               | multi-user login                 | removes PAM/privsep; matches personal-infra use                        |
| 7 | default port 7722                                    | 22, 2222                         | avoids colliding with sshd and common alt-ssh                          |
| 8 | meta commands are CLI subcommands before HOST (`mysh put HOST …`) | `scp`-style `host:path` | unambiguous with `mysh HOST CMD`; `connect` as escape hatch |
| 9 | config dir `~/.config/mysh` on every platform        | `~/Library/…` on macOS           | one path to remember, same as `~/.ssh`                                 |
| 10 | dual MIT/Apache-2.0                                 | MIT only                         | Rust ecosystem default                                                 |
| 11 | no rekey in v1                                      | rekey from day one               | nonce space is not reachable in practice; M4                            |
| 12 | `shell` stacks sessions on one connection; background output buffered in a 1 MiB ring and replayed | pause via backpressure; full terminal emulation (tmux) | never stalls remote work, bounded memory, no emulator; stale terminal modes when switching full-screen apps are an accepted limitation |
| 13 | `-N` reads no stdin; everything else lands at the prompt | `-N` opens the prompt on a tty | reading the tty would `SIGTTIN`-stop a backgrounded `mysh -N … &` |
| 14 | the prompt is the home state; `shell` opens a real shell; `-s` for ssh-like feel | ssh model (shell first, meta via escape) | the connection outlives any one shell; forwards, transfers and several shells are first-class, not escapes |
| 15 | single-byte meta key `Ctrl-]`, interceptable anywhere; `send` for the literal | ssh `~` line-start sequences | one keystroke, no line-start rule, no held bytes or timers; telnet precedent; collides only with vim tag jump, rebindable |

## Testing strategy

- Unit: parsers (key files, authorized_keys, known_hosts incl. hashed,
  config), meta-key interception, SOCKS5 request parsing, HOST parsing, exit
  code mapping, env allow-list.
- Integration (`crates/mysh/tests`): start a server on `127.0.0.1:0` with a
  temp config dir, connect with the library API, exercise handshake/auth,
  exec, PTY (real `/bin/sh`), files, forwards. Runs on Linux and macOS CI.
- Cross: `cargo check --target` for musl and Android on every push; linked
  Android builds in the release workflow.
- Manual Android smoke script in `scripts/` (M2): build, push, serve, connect,
  resize, transfer.
- Property/fuzz (M4): postcard decoders never panic on arbitrary input.
