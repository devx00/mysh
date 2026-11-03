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

### M4 — hardening and release ✔

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
  parsers (`fuzz/`, 23 targets, `scripts/fuzz-all.sh`).
- Release ✔: `scripts/release.sh` links the five targets and writes
  `SHA256SUMS`; `.github/workflows/release.yml` builds the same set on
  tags; `contrib/` has the systemd unit (verified with
  `systemd-analyze`), launchd plist (`plutil -lint`) and Termux:Boot script.

### M5 — quality of life ✔

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
- Signature authentication ✔ (02 "Signature authentication", 03 §2):
  `ssh-agent`-held ed25519 keys log in through the same `XX` handshake
  with a fresh per-connection Noise static and an agent signature over
  `SIG_AUTH_LABEL ‖ h2` carried in `ClientHello.auth`; advertised by
  `caps::SIG_AUTH`, `--no-signature-auth` disables; `-i key.pub` names an
  agent key, otherwise the key file is tried before up to five agent keys;
  the server authorizes the ed25519 key against its `ssh-ed25519` entries
  and owns sessions by it (`handshake::Peer`). Tests: `mysh-net`
  handshake unit tests (happy path, bad signature, replay into another
  handshake, server without the cap) and `tests/sigauth.rs` (throwaway
  `ssh-agent` through the binary: login with no key file, refusal,
  `--no-signature-auth`, `-i key.pub`, key file before agent, and detached
  session ownership by the ed25519 peer). `sk-*` keys remain unsupported
  (the agent only lists ed25519).
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

### M6 — M10: an interface for agents

M1–M5 make mysh a good ssh replacement for a person. The next five
milestones make it a good **remote process API** for a program — an LLM
agent or any orchestrator — without inventing a second protocol. Three
principles hold throughout:

1. **Same wire protocol.** New capabilities are new stream kinds or new
   fields; "agent mode" is structured output and a few flags, never a
   different dialect.
2. **Structured, complete, addressable output.** `--json` on every command;
   byte offsets and sequence numbers instead of truncation or pagination;
   the consumer decides how much to read.
3. **Boring defaults.** Every call bounded by a timeout, every error carries
   a stable machine-readable code, every long-running thing is a session
   with an id.

### M6 — structured I/O ✔

- `--json` ✔ on every command that prints data: `info`, `sessions`, `jobs`,
  `ls`, `stat`, `forward ls`, `ping`, `exec` and `mysh HOST CMD` (one object
  `{stdout, stderr, exit, signal, duration_ms, timed_out}`; `--json-stream`
  ✔ emits NDJSON events `{"event":"stdout","data":…}` / `stderr` / `exit`
  as they happen, base64 for non-UTF-8 chunks). Errors ✔ become
  `{"error": {"code": "unauthorized", "message": …}}` on stderr with the
  same codes as `ErrorCode` plus client-side ones (`trust_unknown`,
  `trust_mismatch`, `connect_failed`, `timeout`, `usage`, `internal`).
- `--plain` ✔: no ANSI, no progress lines, no banner, no prompt hooks
  (implied by `--json` and when stdout is not a tty).
- `--timeout DURATION` ✔ on `exec`, `CMD`, `put`, `get` (sends `Signal(Term)`
  then `Kill` after 2 s; exit code 124 like `timeout(1)`), `--cwd DIR` ✔ on
  `exec`/`CMD` (uses `SessionRequest.cwd`).
- `info --json` ✔ reports server facts without running a command: the
  `Open::Info` stream returning `{name, version, platform: {os, arch,
  kernel}, shell, home, user, caps, limits, uptime_secs}` (03-protocol.md
  §10quater); the human `info` prints them too.
- `help --json` ✔ (`mysh help --json [CMD]` and the prompt's `help --json`):
  the clap command tree with arguments, types and defaults, for tool
  discovery.
- Docs ✔: 05 "Agent interface" with every document, event and code.
- Tests ✔ (`tests/json.rs`): every `--json` output round-trips through
  `serde_json` into the typed structs of `mysh::output`; NDJSON ordering
  (`exit` last) and base64; error code mapping for each failure class;
  `--timeout` kills a `sleep 30` in ≈1 s with 124 (and a TERM-ignoring one
  after the KILL); `--cwd`; `Open::Info` fields match `uname`; `help --json`
  lists every subcommand.

### M7 — remote process API ✔

- `exec` over the control socket ✔: `mysh HOST CMD` runs in a live
  client or master when the socket answers (stdin up to 64 KiB travels
  with the request; a terminal stdin or `-t` keeps its own connection),
  and so do the `session` commands. `mysh -M HOST` / `mysh master HOST
  [--idle D] [--daemon]` ✔ holds the connection open with no prompt and no
  stdin, logs to stderr, removes its socket on the way out and exits after
  `--idle` (default 10 min) without a request, on `SIGTERM`, or when the
  connection ends. `master = "auto"` in `[defaults]`/`[hosts.NAME]` (or
  `--master auto|always`) makes a socket-less call spawn that daemon
  first — detached through `process_group(0)` and `Stdio::null()`, waited
  for up to 3 s.
- Session I/O without a terminal ✔: `mysh HOST session new [--cwd] [--pty]
  [--env] -- CMD` → `{id, pid}`; `session send ID [TEXT] [--stdin]
  [--eof]`; `session read ID [--since N] [--wait D] [--max B] [--follow]`
  → `{offset, next, oldest, chunks, exited}`; `session list`, `session
  kill ID [-s SIG]`, `session wait ID [--timeout D]` — as CLI
  subcommands, prompt commands and over the control socket. Server side ✔:
  every registered session keeps an `OutRing` with absolute offsets, fed
  whether or not a stream is attached, and three new stream kinds
  `Open::Read { session, offset, max, wait_ms }`,
  `Open::Write { session, eof }` and `Open::Signal { session, signal }`
  (03 §10ter). Reads are idempotent: the same offset returns the same
  bytes until they age out of the 1 MiB ring, and the reply says so
  (`offset`, `oldest`).
- Sessions created this way persist ✔ (`SessionRequest.persist`): they are
  registered at `Started`, survive the stream that opened them, and stay
  listed with their status for the detach grace window; `--pty` is off by
  default so stdout and stderr stay separate (`Chunk.stream`).
- Docs ✔: 03 §7 (offsets, `persist`), §10ter (`Read`/`Write`/`Signal`),
  §12; 05 (`session` command family, master mode, exec over the socket).
- Tests ✔ (`tests/procapi.rs`, plus `OutRing` units): incremental
  `read --since` reassembles `1..5` exactly once and ends in `Code(0)`;
  2 MiB of output read from 0 reports `offset == oldest > 0`; `send` to a
  `cat` session echoes and `--eof` ends it with `Code(0)`; stdout/stderr
  stay tagged without a pty and merge with one; `kill` → `Signal(15)`;
  `wait --timeout` gives up without ending the session; 200 `exec` calls
  through one master all succeed against a server limited to one handshake
  per minute; `--idle 500ms` exits within 2 s and removes its socket;
  `master = "auto"` spawns one master and the second call reuses it;
  `read --follow` streams until exit.

### M8 — files as primitives ✔

- Streaming ✔: `get REMOTE -` and `put - REMOTE` (stdout/stdin; `--mode`,
  `--mtime`), `cat`, `write REMOTE` (from stdin, atomic, `--mode`,
  `--append`), `tail [-n N] [-f] [--for D]`, `stat [REMOTE…] --json`,
  `mkdir [-P] [-m]`, `rm [-r]`, `mv`, `realpath`, `hash` as CLI subcommands,
  prompt commands and over the control socket (`put -`/`write` carry the
  request's stdin). `tail -f` adds `FileOp::Get { follow: true }`: the
  server polls the open file every 100 ms until the client closes the
  stream; Ctrl-C, `--for` and the connection's `--timeout` end it with
  exit 0.
- `put --checksum` / `get --checksum` ✔: skip files whose size and BLAKE2s
  digest match (`FileOp::Hash { path, algo }` → `Msg<FileHash>`; local
  hashes on the blocking pool); the summary gains `skipped`. `sync
  [--pull] [--delete] [--dry-run] [--checksum] [-j N] SRC DST` ✔: plan by
  size + mtime (±1 s) or digest, `--dry-run` prints a `SyncPlan`, the run
  reuses the parallel transfer machinery and reports a `SyncSummary`;
  `--delete` removes extras, files first, directories deepest first.
- Docs ✔: 03 §9 (`Hash`, `follow`), 04 "File transfer" + "File
  primitives", 05 rows and "Agent interface" documents.
- Tests ✔ (`tests/fileprims.rs`): `put -`/`get -` byte-identical through
  pipes (3 MB); `cat` concatenates; `write` replaces atomically (no temp
  left) and `--append` appends; `tail -n`; `tail -f` streams appended
  lines within 1 s and `--for` exits 0; `stat --json`; `mkdir -P`,
  `rm -r`, `mv`, `realpath`; `--checksum` skips an identical file
  (`skipped == 1`, `info` traffic counters far below the file size);
  `sync` of a 100-file tree after changing 3 files plans and transfers
  exactly 3 (97 unchanged, trees byte-identical after); `--delete`
  removes extras; `--pull`; `--dry-run` changes nothing.

### M9 — fleet ✔

- Fan-out ✔ (05-meta-shell.md "Fleet", decision 48): `mysh run [-j N]
  (--hosts a,b,c | --group NAME)… [--json] [--timeout D] [--cwd D] -- CMD`
  runs the same command on many hosts — through a host's control socket
  when a master or client serves it (`master = auto` starts one), else on
  a fresh connection — and prints `host: line` / `host! line` interleaved
  plus a summary table, or a JSON array of `RunResult` in selection order;
  `mysh put/get --hosts …` likewise (`get` lands in `LOCALDIR/<host>/`).
  `[groups.NAME] hosts = [...]` in `config.toml`; `--group` repeats and
  mixes with `--hosts`, duplicates dropped, order kept. Exit 0 iff every
  host exited 0.
- Audit log ✔ (02-security.md "Audit log", decision 49): `mysh serve
  --audit PATH` (`-` = stderr) appends JSON lines `{ts, peer, key, kind,
  event: connect|disconnect|session|exec|file|forward|pair|denied, detail,
  exit, bytes_in, bytes_out, duration_ms}` through one writer task
  (`server/audit.rs`, `O_APPEND`, 0600, flushed per line); rotated by the
  host's logrotate (no built-in rotation).
- Pairing ✔ (02-security.md "Pairing", 03-protocol.md §10quinquies,
  decisions 42–43): `mysh serve --pair [DURATION]` prints a one-time
  6-word BIP-39 code (`SIGUSR1` opens another); `mysh pair HOST CODE`
  connects with `caps::PAIR_REQUEST` to an *unverified* server key, gets
  `Verdict::Pairing`, runs SPAKE2 (`spake2` crate, Ed25519 group) with the
  code over `Open::Pair`, confirms the key both ways, and only then the
  server installs the client's public key in `authorized_keys` and the
  client pins the server key in `known_hosts`. Single use, expires, a
  wrong code closes the window.
- Docs ✔: 05 (`run`, groups, `pair`), 02 (pairing section, audit log), 06.
- Tests ✔ (`tests/fleet.rs`, `tests/audit.rs`, `tests/pairing.rs`): `run`
  across three loopback servers attributes every line and exits 0; `-j 2`
  with `sleep 0.5` takes two rounds not three; a down alias yields
  `connect_failed` while the others succeed (exit 1); `--json` parses into
  `Vec<RunResult>` in selection order with duplicates removed; `put
  --hosts` lands the file on all three and `get --hosts` fills
  `LOCALDIR/<host>/`; a `run` through a master reuses its connection
  (server admits one handshake per minute); audit lines for connect,
  disconnect, session (pty and exec), exec, file, forward and denied
  validate against a `deny_unknown_fields` schema with monotonic
  timestamps and a 0600 file; pairing round trip, wrong code, expired
  code, replayed code.

### M10 — embedding ✔

- `mysh-client` library crate ✔ (07-embedding.md "Library", decisions
  52–54): the client half (`config`, `identity`, `conn`, `session` +
  `session_api`, `files`/`fileops`/`sync`, `forward`, `ctl` requester +
  master spawn, `fleet`, `pair`, the `--json` `types`) moved out of the
  binary with no terminal dependencies; output goes through a `Reporter`
  trait and unknown host keys through a `TrustPrompt`; a `Client` facade
  (`exec`/`exec_stream`, `info`, `sessions()`, `files()`, `forwards()`)
  returns the same documents the CLI prints. The binary's `Console`
  implements both traits and its old module paths re-export the library.
- `mysh mcp [--hosts …]` ✔ (07-embedding.md "MCP server", decisions
  50–51): an MCP server over stdio (JSON-RPC 2.0, newline-delimited, also
  `Content-Length` input) exposing `exec`, `read_file`, `write_file`,
  `list_dir`, `stat`, `session_new/send/read/kill/list`, `put`, `get`,
  `info` and `hosts` as tools with hand-written input and output schemas,
  one lazily opened and reconnected connection per host, structured errors
  from M6 (`isError` + `{"error":{"code","message"}}`, never a JSON-RPC
  error for a remote failure), offsets from M7. Resources: `mysh://HOST/`
  per host and `mysh://{host}/{path}` for files (text, base64 blob, or a
  JSON listing). Trust: `--accept-new` only; never a prompt. `put`/`get`
  need `--allow-local-paths`. `contrib/mcp/` holds an example client config.
- Docs ✔: `docs/07-embedding.md` with the library API and the MCP tool
  schemas.
- Tests: the library's public API drives a loopback server through every
  `Client` method without the binary ✔ (`tests/client_api.rs`); an MCP conformance test ✔ (`tests/mcp.rs`)
  speaks the protocol over pipes: `initialize` (version echo), `tools/list`
  with both schemas, every tool with a real effect (exec, text/binary
  file round trip, directory listing, stat, `cat` session fed and read by
  offset, PTY session, put/get, info, hosts), the error mapping
  (`-32601`, `-32602`, `-32700`, exit 3 as a result, `connect_failed`,
  `trust_unknown`, `denied`), resources (text, blob, listing, `-32002`),
  `Content-Length` framing, exit 0 on stdin EOF.

Suggested order: M6 → M7 (they make everything else scriptable), M8, then
M9 and M10 in either order; pairing is the only item that needs a design
sign-off before code.

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
| 30 | signature authentication stays inside Noise `XX`: the client's static is a fresh random key, message 3's payload carries `AuthProof::Ed25519 { public_key, signature }` over `SIG_AUTH_LABEL ‖ h2` (the handshake hash after message 2), and the server authorizes the ed25519 key directly; `ClientHello` grew the `auth` field without a protocol version bump (pre-release, no deployed peers) | a separate `NN` handshake plus an `Auth` message after it; a new protocol version | one handshake code path and one `Verdict`; `h2` already binds both ephemerals and the server static so the signature cannot be replayed; the identity stays hidden from an unverified server exactly as for static keys; a cap bit is enough for a client to know whether to try an agent key before revealing anything |
| 31 | one `output::Mode` (`Human`/`Plain`/`Json`/`JsonStream`) chosen in `main` and carried by the `Console`; printers call `console.report(&doc, || text)` and the console decides whether the document, a `result` event or the text goes out; session bytes are collected (`Json`) or turned into `stdout`/`stderr` events (`JsonStream`) by the same `write_bytes`/`write_stderr` the terminal path uses | a second dispatcher or per-command `--json` flags; a `Printer` trait per command | one grammar, one dispatcher, one console: every frontend (prompt, script, job, control socket) gets JSON by constructing its console in the right mode, and the typed result structs double as the test contract |
| 32 | errors carry a stable code as a typed cause in the anyhow chain (`CodedError`), classified once by `code_for`; the wire's `ErrorCode` maps 1:1 to snake_case, trust/connect/usage/timeout are client-side codes; unclassified errors that exit 2 report `usage`, the rest `internal` | an error enum threaded through every client function | the chains already exist and stay readable; a code is attached exactly where the failure class is known (dial, trust verdict, handshake verdict, transfer deadline) and nothing else changes |
| 33 | `--timeout` is a client-side escalation: `Signal(Term)` at the deadline, `Signal(Kill)` 2 s later, stop waiting 1 s after that (the exec server reports `Exited` only once the output pipes close, so a grandchild holding them would otherwise hang the caller); exit 124, `timed_out: true` | a server-side deadline in `SessionRequest` | works against today's servers, the policy is visible in one place, and the server keeps its single "exit = reaped + drained" rule |
| 34 | `Open::Info` is assembled from the effective per-connection `Policy`, `std::env::consts` and `rustix::system::uname()` — never by running a command; `uptime` counts from `Server::bind` | `uname -a`/`sh -c` on the server | a client asking "what are you" must not need the `exec` permission, and a deterministic reply is testable (`kernel == uname -r`) |
| 35 | one `OutRing` per *registered* session (every PTY session, plus `persist: true` exec sessions) carries absolute offsets (`next`, `oldest`, plus a `sent` watermark) and is fed by the pump whether or not a stream is attached; an unregistered session gets a ring with capacity 0 | a ring only while detached, as in M5; a separate buffer per reader | one buffer answers both jobs — `Attach` replays from `sent`, `Open::Read` addresses absolute offsets — so the reattach replay and the API can never disagree, the "carry" hack of M5 disappears, and a plain `mysh HOST CMD` still allocates nothing |
| 36 | `persist: true` sessions are parked by the same machinery as a detached PTY session: the attached pump returns on stream EOF, a detached pump (one per kind) keeps draining output into the ring and serving `Open::Write`, and the entry stays listed with its status until the detach grace window passes | a reaper that unregisters a session as soon as its process exits | `session wait`/`read` must still work *after* the process ends, and one grace window (already configurable, already tested) is the only lifetime rule in the server; nothing new to tune |
| 37 | `Open::Write` grew an `eof` flag instead of relying on the stream's half-close to mean "close stdin" | EOF on the write stream always closes the child's stdin | `session send ID TEXT` is a one-shot command whose stream always ends; without the flag every write would close stdin and `send` could never be repeated. The flag is a pre-release field addition, no version bump |
| 38 | `kill` is its own stream kind (`Open::Signal`, kind 13) rather than an in-band byte on `Open::Write` or a full `Attach` | reuse `SessionIn::Signal` by attaching | `Write` is raw bytes by definition and `Attach` costs a session slot and a pty; one prologue plus one reply is the cheapest thing that can answer "did it work" |
| 39 | a `Msg<ReadReply>` is capped at the control-message limit (256 KiB less framing) even though a client may ask for `READ_MAX` (1 MiB); the reader continues from `next` | raising `MAX_CONTROL_MESSAGE`; splitting a read over several messages | the frame cap is a transport invariant the fuzzers and both peers rely on, and `next` already exists to continue a read — a short reply is a normal answer, not an error |
| 40 | the master is an ordinary client without prompt or stdin that owns the same control socket; `--daemon` and `master = auto` re-spawn the binary with `process_group(0)` and `Stdio::null()` and wait up to 3 s for the socket | `fork`+`setsid` in-process; a separate daemon binary or a socket-activated service | the safe std API is enough on Linux, macOS and Android, keeps `#![forbid(unsafe_code)]`, and reuses the socket, allow-list and capture console that M5 already tests; the master dies with its connection, so nothing outlives the server |
| 41 | `mysh HOST CMD` routes through the socket only when stdin is not a terminal and `-t` was not given, and its stdin (≤ 64 KiB) travels inside the request, read only after a socket has answered | multiplexing the session's stdin over the control socket like ssh's ControlMaster | the control protocol is one request and an event stream, not a duplex channel; a bounded, eagerly-read stdin covers scripts and agents, while an interactive or huge-input call quietly keeps its own connection instead of behaving subtly differently |
| 42 | pairing is SPAKE2 (`spake2` 0.4, Ed25519 group) run **inside** the normal Noise connection with identities = the two Noise statics and password = the normalized 6-word BIP-39 code, followed by explicit HMAC-SHA256 key confirmation client-first over `client_static ‖ server_static ‖ A ‖ B`; the server writes `authorized_keys` only after the client's tag verifies and the client writes `known_hosts` only after the server's | CPace (no maintained Rust crate with the group we already link); a bare SPAKE2 without confirmation (the shared key is never used, so nothing would prove the codes matched); a PAKE-authenticated handshake replacing Noise (a second transport path) | one connection, one trust decision per side taken after a proof, and a man-in-the-middle relaying between two Noise sessions gets two different identities and fails both confirmations; the crate pins `curve25519-dalek` which mysh-net already uses |
| 43 | a pairing window is a server-wide `Mutex<Option<PairWindow>>` that is single-use for *any* outcome: the first `Open::Pair` attempt spends it, a wrong code therefore buys one guess; `--pair [DURATION]` opens one at start, `SIGUSR1` replaces it; the handshake grants `Verdict::Pairing` only while a window is open and the client set `caps::PAIR_REQUEST`, and such a connection serves `Control` + `Pair` and nothing else | a window that survives failed attempts behind a retry counter; a pairing *mode* of the whole server; an out-of-band HTTP pairing endpoint | 2048⁶ codes make one guess per window more than enough while keeping the failure story trivial to reason about (and to test); the cap bit lets an unknown key reach the PAKE without a second handshake path, and the pairing-only dispatch keeps an unauthorized peer away from every other service |
| 44 | `sync` takes its direction from the command form (`sync LOCAL REMOTE` pushes, `sync --pull REMOTE LOCAL` pulls); a `HOST:` prefix is never parsed, and the plan compares size + mtime (±1 s) by default, digests only with `--checksum` | rsync/scp-style `host:path` arguments; always hashing | one connection is already bound to one host, so a prefix would be redundant syntax with its own ambiguities (colons in paths), while mtime comparison keeps a 100-file no-op sync at two directory walks instead of 200 hashes |
| 45 | `tail -f` is bounded by its own `--for` flag (and the connection's `--timeout` folded into it), and both end it with exit 0; `Get { follow }` is a server-side 100 ms poll on the open descriptor that restarts from 0 on truncation and ends when the client closes the stream | inotify/kqueue watching; treating the deadline as the usual `timeout` error (exit 124) | polling is portable to all three platforms and cheap at 10 Hz, and stopping a follow at a deadline is what the caller asked for, not a failure — the exit-124 convention is kept for operations that were meant to finish |
| 46 | `cat`, `get REMOTE -` and `tail` write the body with `Console::write_bytes` (plain stdout, `stdout` events in `--json-stream`, one `DataOut {data, bytes}` document in `--json`) and draw no progress line; `--checksum` skips count in a new `TransferOut.skipped` field, and `files` only counts files actually moved | a separate raw stdout path bypassing the console; keeping skipped files inside `files` | the body *is* the output, so the existing byte path gives every mode a well-defined result for free, and an agent reading `{files: 0, skipped: 1}` sees at a glance that nothing was transferred |
| 47 | the file primitives share one `FileCmd` enum between the CLI subcommands, the prompt and the control socket (`mysh HOST cat …` → `ClientCommand::File`), and the prompt-flattened structs avoid the shared CLI shorts/longs (`mkdir -P`, `tail --for`) just as `put -P` does | per-frontend arg structs; a `files` subcommand namespace (`mysh HOST files cat …`) | one clap definition per command keeps help, `to_argv` relaying and tests in one place; the capital/renamed flags are the price already paid for `put`, documented in the same table |
| 48 | a fan-out member runs the *prompt words* of its command (`exec … -- CMD`, `put …`) either over the host's control socket or on a fresh connection via the same detached `Ctx` the socket server uses, always under a capture console in a JSON mode (`--json-stream` for `run`, `--json` for transfers); the fleet code only parses those events into `RunResult`/`TransferResult` and prefixes lines. `--hosts`/`--group` live in the shared connection options, so for `put`/`get` the `HOST` positional holds the first `PATH` | a dedicated per-host exec path reading `SessionOut` directly; a `HostsAnd<T>` arg struct with an optional `HOST` positional | reusing the single-host printers means every mode, the timeout escalation, `--cwd` and error codes behave identically per host with no second implementation to drift, and the master/ctl reuse comes for free; clap cannot express "HOST is absent when `--hosts` is given" for positionals, so shifting the first value is the honest alternative to a duplicated `put`/`get` definition |
| 49 | the audit log is a server-wide `Arc<Audit>` holding an `mpsc` to one writer task that stamps `ts` at write time, serializes and flushes each line; handlers emit through a per-connection `audit::Handle` (peer + key) with the detail built by a closure that only runs when the log is on; `ServerConfig.audit: Option<PathBuf>` opens the file (`O_APPEND`, 0600) in `Server::bind` | a `tracing` layer with a JSON formatter; stamping `ts` at emit time; a synchronous `Mutex<File>` | a separate channel keeps the schema stable and independent of `-v` filters, one writer gives monotonic timestamps and no interleaving for free, the closure keeps the disabled path allocation-free, and failing `bind` on an unopenable audit file is the right default for a log that exists to be trusted |
| 50 | `mysh mcp` is a module of the binary (`crates/mysh/src/mcp/`), serves requests one at a time, and reaches the client library only through `mcp/backend.rs`; schemas are hand-written `serde_json` values that mirror the `--json` types | a separate `mysh-mcp` crate with an MCP SDK and `schemars`-derived schemas; concurrent request handling | the server is ~1500 lines over an API the binary already has, so a crate and two dependencies would buy nothing; one request at a time is the simplest thing that is correct with a per-host connection map, and the schemas double as the documented contract (a derive would leak internal field names and `Bytes`' custom serialization) |
| 51 | a remote failure is a tool *result* (`isError: true` with the M6 `{"error":{"code","message"}}` as text and `structuredContent`), a non-zero exit is a plain result, and only malformed requests, unknown methods/tools and unconfigured hosts are JSON-RPC errors; trust is `--accept-new` or `trust_unknown`, never a prompt, and `put`/`get` are off without `--allow-local-paths` | JSON-RPC errors for everything; prompting through MCP elicitation; local paths always on | agents read tool results, not transport errors, and need the stable code to decide what to do; stdin is the protocol so a prompt is impossible, and a trust decision belongs to the person who configured the client; a tool that can write anywhere on the operator's disk must be opt-in |
| 52 | the moved modules keep their shape and talk to a wide `Reporter` trait (`event` plus text/progress/result hooks with event-based defaults) that the binary's `Console` implements, instead of being rewritten to return every result; the typed surface is the `Client` facade on top of the typed protocol calls that already existed (`session_api::session_*`, the `files` primitives) | splitting every module into a pure core and a printing wrapper; a minimal `event`-only reporter with the human rendering reimplemented in the binary | the CLI-shaped runners (`put`/`get`/`ls`/`sync`/`session …`) render results in four modes and are covered by ~400 integration tests; moving them verbatim keeps that behaviour byte-identical, while a facade that returns `ExecResult`/`LsEntry`/`TransferOut`/`SyncOutcome` gives programs what they need without touching the CLI paths. `Mode` therefore lives in the library (`types::Mode`) because the control-socket request carries it |
| 53 | the clap argument structs of the file, session and connection commands move into `mysh_client::args` with their `#[derive(Args)]`, and `cli.rs` re-exports them; the library depends on `clap` | plain request structs in the library mirrored by clap structs in the binary with `From` conversions; `cfg_attr`-gated derives | one definition serves the CLI, the meta prompt, the control socket and library callers (they are plain structs with `Default`); the mirrored pair would be ~20 structs of duplicated fields that drift, and `clap` is a parser, not a terminal dependency |
| 54 | the library never prompts or spawns itself: unknown keys go to `TrustPrompt::confirm_unknown`, encrypted keys to `TrustPrompt::passphrase` (both refuse by default), the compiled-in keys arrive as `Baked::parse(identity, peers)` text, and `ctl::ensure` takes the path of the `mysh` binary to start a master with; `Client::connect_or_ctl` honours `target.master` by starting that master and then opens its own connection | reading stdin from the library when it is a tty; `current_exe()` in the library; a `Client` that speaks the prompt grammar over the control socket | a library has no business touching a terminal it does not own, and an embedding program re-spawning *itself* as `mysh master` would be wrong; the control socket speaks prompt words and renders in an output mode, so a facade on top of it would be a second, lossy protocol — `ctl::request` stays available for callers that want exactly that |
| 55 | zig (`cargo zigbuild`) is the one linker for every Linux musl/gnu and FreeBSD target, from any host; `scripts/release.sh` keeps a single target table (target, family, tier, required/stretch) and picks the linker by family (host clang for darwin, NDK clang for android); `MUSL_LINKER_*` still select a musl cross gcc for the two original musl targets | `cross` (docker images per target); one musl-cross gcc per architecture; per-target `[target.*] linker` entries in `.cargo/config.toml` | there are no C dependencies, so only a linker is needed, and zig ships every libc/CRT for every target in one package — the `cross` images are x86_64-only and need emulation on Apple silicon, and a dozen gcc toolchains would be a dozen install steps that differ per host; one table means CI, docs and the local script cannot drift |
| 56 | macOS ships a third artifact, `mysh-<v>-universal-apple-darwin`, made with `lipo -create` from the two single-arch binaries, which also ship | universal only; single-arch only | a user downloading for a Mac should not need to know the arch, while fleet install scripts that already key on `uname -m` keep the small single-arch files; `lipo` is in every Xcode command-line tools install and the step is one line |
| 57 | `scripts/validate-dist.sh` runs each Linux artifact under `docker run --platform <p>` (qemu-user via binfmt) and does a keygen + loopback `serve`/`exec` round trip inside the container; darwin, FreeBSD and Android artifacts are `SKIP`ped as having no emulator here | trusting `cargo check` + a successful link; a VM per architecture; `qemu-user` on the host without docker | a binary that links can still fault on a wrong atomic width, syscall number or struct layout, and the round trip exercises the handshake, the exec path and the key files on the real libc of that arch; docker + binfmt is one install and the same command for all eight platforms, a VM per arch is not; FreeBSD needs a real kernel and Android a device, so those stay cross-compiled and statically inspected only |

## Testing strategy

- Unit: parsers (key files, authorized_keys, known_hosts incl. hashed,
  config), meta-key interception, SOCKS5 request parsing, HOST parsing, exit
  code mapping, env allow-list.
- Integration (`crates/mysh/tests`): start a server on `127.0.0.1:0` with a
  temp config dir, connect with the library API, exercise handshake/auth,
  exec, PTY (real `/bin/sh`), files, forwards. Runs on Linux and macOS CI.
- Cross: `cargo check --target` for every required non-darwin target on every
  push (`cargo check-matrix` locally); linked builds of the whole matrix in
  the release workflow; `scripts/validate-dist.sh` runs the Linux artifacts
  under qemu-user (docker + binfmt) with a loopback serve/exec round trip.
- Manual Android smoke script in `scripts/` (M2): build, push, serve, connect,
  resize, transfer.
- Fuzz (M4, extended M9): `fuzz/` is a separate cargo-fuzz workspace
  (excluded from the root workspace; needs nightly). Targets cover every
  postcard decoder (`proto_*`, incl. `Info`, `ReadReply`, `FileHash`,
  `PairMsg`, and all `Open` kinds 0–13), `frame::body_len`/`decode`, key
  parsers (`keys_*`), `authorized_keys`/`known_hosts` (`trust_*`), the
  TOML/spec parsers (`config_*`), `--hosts`/group expansion (`cli_hosts`),
  `normalize_code` idempotence (`pair_code`) and `serde_json` round-trips of
  `ExecResult`/`RunResult` (`output_json`) — 23 targets. The audit log is
  write-only (no parser), so it has no target. `scripts/fuzz-all.sh
  [SECONDS]` builds and runs each target for SECONDS (default 5) and
  summarises pass/fail; corpus and artifacts are git-ignored.
