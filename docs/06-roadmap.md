# 06 — Roadmap, decisions, testing

## Milestones

Each milestone ends with a tagged build that works on Linux and macOS; Android
is smoke-tested from M2 onward.

### M0 — scaffold ✔

Workspace, lints, CI, this spec.

### M1 — authenticated transport + remote exec ✔

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

### M2 — interactive PTY ✔

- `mysh-pty`: pty pair, controlling-tty spawn, winsize, cwd probe, raw mode
  guard, signal plumbing (all three platforms).
- Session stream: `Shell`, `Resize`, suspend/resume, meta-key interception,
  exit status including signals, `Exited` ordering after EOF.
- Shell/home/env resolution per platform table.
- Android smoke: `cross build`, `adb push`, serve from `adb shell`, connect
  from macOS, resize, `vim`.
- Tests: pty session runs `sh -c 'stty size'` and sees the requested size;
  resize mid-session is observed; exit via signal maps to `128+n`.

### M3 — meta shell, files, forwards ✔

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

- Handshake rate limit per source IP ✔ (`--handshake-rate`, token bucket);
  idle timeout ✔ (`--idle-timeout`); stream/listener quotas enforced with
  tests ✔ (`tests/hardening.rs`).
- Session rekey ✔: in-band empty Noise message below yamux (03 §3) every
  1 GiB or 1 h per direction, whichever first.
- Per-key options in `authorized_keys` ✔ (parsing: `command=`, `no-pty`,
  `no-files`, `no-forward`, `from=`, `restrict`; 02 "Per-key options") and
  enforcement ✔ (per-connection `Policy`, `from=` at authorization, forced
  command with `MYSH_ORIGINAL_COMMAND`).
- Fuzz targets ✔ for every postcard decoder and the key/trust/config
  parsers (`fuzz/`, 16 targets, `scripts/fuzz-all.sh`).
- Release ✔: `scripts/release.sh` links the five targets and writes
  `SHA256SUMS`; `.github/workflows/release.yml` builds the same set on
  tags; `contrib/` has the systemd unit (verified with
  `systemd-analyze`), launchd plist (`plutil -lint`) and Termux:Boot script.

### M5 — quality of life

- Control socket ✔ (05-meta-shell.md "Control socket"): an interactive
  client listens on `$XDG_RUNTIME_DIR/mysh/<host>_<port>.sock`; `mysh
  put/get/forward/authorize HOST …` try it first and fall back to a fresh
  connection; `--no-ctl` opts out. Tests: `tests/ctl.rs` (socket reuse
  under a 1/min handshake limit, error propagation, `--no-ctl`, fallback,
  socket removal on exit).
- Session persistence ✔: the server keeps a detached PTY session for
  `--detach-grace` seconds (default 600; 0 = off, advertised via
  `caps::PERSIST`), drains its output into a 1 MiB ring, and replays it on
  reattach (`dtach` model, not a terminal emulator); `mysh --attach[=ID]
  HOST`, `attach`/`detach`/`sessions -a` at the prompt; `ListSessions`/
  `Attach` streams (03 §10bis); session ids are server-wide. Tests:
  `tests/persist.rs` (library: replay, typing after reattach, exit while
  detached, other key sees nothing, grace expiry, grace 0, shutdown) and
  `tests/persist_cli.rs` (binary under a pty: `SIGKILL` + `--attach`,
  `disconnect` + `--attach=ID`, prompt `detach`/`attach`, no-persistence
  error).
- Signature authentication (`NN` + ed25519 signature over the handshake
  hash) enabling `ssh-agent`, `sk-*` keys, and keys that cannot be exported.
- Background transfers ✔ (`CMD &`, `jobs [-w] [ID]`, `kill %ID`;
  `client::jobs`, capture-mode `Console`) and parallel recursive transfers ✔
  (`put -r`/`get -r` run `-j` files at a time, default 4; 04 "File
  transfer"). Tests: `tests/ctl.rs` (jobs under a pty, 50-file tree
  round trip with `-j 4`, first error aborts the rest), unit tests for the
  `&` tokenizer rule, the job table and capture event ordering.
- Local path completion and `Ctrl-R` history search at the prompt — done
  (`client::editor`): Tab completes local paths for `put`/`lcd`/`log`/
  `authorize` and `get`'s destination, `Ctrl-R` incremental search.
- Post-quantum hybrid (X25519 + ML-KEM): deferred to a later round. `snow`
  0.10 exposes no ML-KEM; a hybrid KEX would be a separate crypto path and
  a trust-model decision in its own right.

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
| 16 | `put`/`get` use `-P` (preserve) and `-F` (follow symlinks); `put -c` stats the remote and resumes with `truncate:false, atomic:false`; `get` writes `<path>.mysh-tmp` then renames | scp's `-p`/`-L`; always-atomic writes | `-p`/`-L` are the shared `--port`/`-L` CLI options and meta commands share the clap definitions; resume cannot be atomic by definition; `ls -l` times are UTC until a tz dependency is justified |
| 17 | Tab completion is local-only and per command (`put`, `lcd`, `log`, `authorize`: every argument; `get`: arguments after the first); the editor derives the command from the first word of the line | remote completion via a `ls` round trip; completing every word | no network traffic from a keystroke, no stale remote listings; the per-command rule needs no clap introspection and is documented |
| 18 | rekey is an empty-plaintext Noise message handled inside `NoiseStream`; nonces keep counting | `Rekey` control message over yamux | the control stream is multiplexed and cannot be ordered against the raw Noise frames of other streams; an in-band marker is ordered by construction, per direction, and needs no timer task |
| 19 | per-key options narrow a per-connection copy of the server `Policy` (`deny` set + `forced_command`); handlers keep reading `ctx.policy` | option checks inside every handler | one enforcement point; `--deny` and key options compose by set union; nothing in the handlers knows about key options |
| 20 | the handshake rate limiter is a per-IP token bucket checked on `accept`, before the handshake semaphore; rejected sockets are dropped silently and logged at most once per 10 s per address | reply with a `Denied` verdict; per-connection sleep | a verdict costs a handshake (the thing being limited) and tells a scanner it is being counted; dropping is free and log-rate-limited so a flood cannot fill the log |
| 21 | the 512-stream cap is yamux's own `max_num_streams` on both ends, counting the control stream; an opener that exceeds it loses the connection (yamux 0.14 poisons it) | a mysh-level counter that rejects with `Limit` before yamux | the hard cap is already enforced below us; the client stays under it by construction (32 sessions + 32 listeners + transient file/forward streams) and the behaviour is documented in 02 and pinned by a test |
| 22 | session ids are server-wide (one counter per server process) and detached sessions live in a server-wide registry keyed by id, owned by the client key | per-connection ids plus a `(client_key, conn, id)` address | `Started.session` keeps carrying the id and `--attach=ID` means the same thing on every connection; the registry outlives the connection task, which is the whole point |
| 23 | a detached session is parked by the pump itself: the attached pump returns the session object on stream EOF, a detached pump drains the master into the ring and owns the grace timer, and `Attach` asks that task for the object back and re-enters the same attached pump | aborting tasks and sharing the master/child behind locks | one owner at a time, no lock across `select!`, the reattach and the fresh session share one code path (`serve_pty`), and expiry vs. claim is decided under the registry lock |
| 24 | `disconnect` keeps its meaning (close the connection) and sessions persist per server policy; `kill` ends one; `detach` refuses on a server with persistence off instead of silently hanging the session up | `disconnect --keep`/`--kill` flags | the server policy, not a client flag, decides what survives; a `detach` that kills is a trap |
| 25 | `--attach` takes its optional id with `=` (`--attach=3`); a bare `--attach` picks the only detached session, several print the list and exit 1 | `--attach [ID]` with a space | `mysh --attach HOST` would otherwise parse `HOST` as the id; clap's `require_equals` is the standard answer |
| 26 | the control socket is keyed by the resolved target (`<host>_<port>.sock`), not the server fingerprint | `<fingerprint>.sock` as first designed | a CLI subcommand knows the target before connecting but learns the fingerprint only by connecting, which is what the socket exists to avoid; two aliases for one server simply get two sockets |
| 27 | the control request carries prompt words (`argv`) plus the requester's cwd, and the reply is the capture console's event stream; the dispatcher's `Ctx` is split into shared state (`Arc<Shared>`: connection, forwards, jobs, a session snapshot) and prompt-only state (stack, events, history, terminal), so a request or job runs `execute` on a detached `Ctx` of its own | serializing `MetaCommand`; a message to the prompt loop asking it to run the command | one grammar and one dispatcher serve all three frontends; the prompt keeps serving while a transfer runs on another task; `sessions`/`kill` from a request read a snapshot the prompt refreshes after every command and event instead of locking the stack |
| 28 | `&` is recognised only as a final whole token; jobs are limited to `put get ls exec authorize`; a cancelled job's `exec` session gets `SIGTERM`; completion prints the notice and the captured output (64 KiB cap) in one go | shell-style `&` anywhere, backgrounding any command, output streamed live above the prompt | a glued `&` is a legal file name; the other commands need the terminal; interleaving a job's output with the prompt and foreground sessions would defeat the capture console |
| 29 | parallel recursive transfers walk first and then run files `-j` at a time behind a semaphore; the first error aborts the rest; progress is one aggregate line | pipelining the walk with the transfers; continuing past errors and summarising | directories exist before any file stream opens and `-P` post-order attributes stay correct; an aborted tree is reported as one error the user can act on, and `-c` resumes it |

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
- Fuzz (M4): `fuzz/` is a separate cargo-fuzz workspace (excluded from the
  root workspace; needs nightly). Targets cover every postcard decoder
  (`proto_*`), `frame::body_len`/`decode`, key parsers (`keys_*`),
  `authorized_keys`/`known_hosts` (`trust_*`), and the TOML/spec parsers
  (`config_*`). `scripts/fuzz-all.sh [SECONDS]` builds and runs each target
  for SECONDS (default 5) and summarises pass/fail; corpus and artifacts are
  git-ignored.
