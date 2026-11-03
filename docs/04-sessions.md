# 04 — Sessions, PTY, forwarding, files

## PTY session (server)

Implemented in `mysh-pty` (platform calls) and `mysh::server::session`. A
connection may carry several sessions at once (the client's `shell` command,
05-meta-shell.md); the server treats them identically and independently,
up to the per-connection quota in 03-protocol.md §12.

1. **Open the pair.** `rustix::pty::openpt(O_RDWR | O_NOCTTY)`, `grantpt`,
   `unlockpt`, `ptsname`, then open the slave `O_RDWR | O_NOCTTY`. No
   `openpty(3)` (absent on old bionic) and no `forkpty(3)` (forks a
   multi-threaded runtime).
2. **Initial size.** `TIOCSWINSZ` on the master from `PtyRequest.size`
   before spawn, so the shell never sees 0×0.
3. **Spawn.** `tokio::process::Command`:
   - program: resolved shell (below) or `argv[0]` for `Exec`;
   - `arg0`: `-<basename>` for `Shell` (login shell semantics); `Exec` is
     run as `shell -c "<argv joined with shell quoting>"` when `argv.len() == 1`
     (ssh behaviour, so `mysh host 'ls | wc -l'` works), otherwise directly;
   - a key with `command="…"` (02-security.md, "Per-key options") always
     runs `shell -c "<command>"` instead, for `Shell` and `Exec` alike, with
     `MYSH_ORIGINAL_COMMAND` set to the requested argv joined by spaces
     (empty for `Shell`); the PTY request is honoured as asked;
   - `env_clear()`, then `HOME`, `USER`, `LOGNAME`, `PATH`, `SHELL`,
     `MYSH_CONNECTION="<client ip> <client port> <server ip> <server port>"`,
     `MYSH_SESSION=<id>`, `MYSH_ORIGINAL_COMMAND` under a forced command,
     plus allow-listed client env (02-security.md);
   - `current_dir`: `SessionRequest.cwd` if present and a directory (relative
     to home, `~/` expanded), else home. A missing or unusable `cwd` is not
     an error: the session starts in home and the client is told via
     `Started { cwd_fallback: true }`;
   - stdin/stdout/stderr = the slave (dup'd by `Stdio::from(OwnedFd)`);
   - `pre_exec`: `setsid()`, `ioctl(0, TIOCSCTTY, 0)`. The master is
     `CLOEXEC` and does not leak into the child.
4. **Close the slave in the parent** immediately after spawn, so master reads
   hit EOF/EIO when the last child-side descriptor closes.
5. **Pump.** Master wrapped in `tokio::io::unix::AsyncFd` (non-blocking).
   - master → `SessionOut::Stdout` in ≤ 64 KiB chunks;
   - `SessionIn::Stdin` → master write (with proper partial-write handling);
   - `SessionIn::Resize` → `TIOCSWINSZ`; the kernel delivers `SIGWINCH` to
     the foreground process group, nothing else to do;
   - `SessionIn::Signal(s)` → `kill(child_pid, s)` (the shell; for PTY
     sessions interactive signals normally arrive as control characters
     through the line discipline, this exists mainly for exec sessions).
6. **Exit.** Completion requires both: the child reaped (`child.wait()`) and
   the master at EOF (`read` → 0 or `EIO`). If the child exits while
   descendants keep the slave open (backgrounded `tail -f`), output keeps
   flowing until they close it; after the child exits the server waits at
   most 2 s for master EOF, then closes the master (which `SIGHUP`s the
   session like a terminal going away) and sends `Exited`. Exit status is the
   child's.
7. **Client gone → detach.** If the stream closes first (connection lost,
   or the client half-closed it with `detach`) and the child is still
   running, the server **detaches** the session instead of hanging it up:
   the master and the `Child` move to the server-wide registry, a pump task
   keeps reading the master into a 1 MiB ring (oldest bytes dropped, drop
   count kept) so the process never blocks on a full pty buffer, and a
   grace timer starts (`--detach-grace SECS`, default 600). The same client
   key may `ListSessions`/`Attach` it from any connection (03-protocol.md
   §10bis); the attach hands the new stream to the same pump the session
   started with, after replaying the ring. If the child exits while
   detached its status is recorded and the entry stays listable until the
   window ends, so a reattach still sees `Exited`. When the window passes
   without a reattach — or at server shutdown — the server closes the
   master; the session gets `SIGHUP` via the controlling tty; processes
   that ignore it (`nohup`) survive, as with ssh. The child is not
   force-killed. `--detach-grace 0` disables persistence: the master is
   closed as soon as the stream ends (ssh behaviour). Exec sessions never
   persist.

### Exec session (no PTY)

Pipes for stdin/stdout/stderr; `StdinEof` closes the write end; `Exited`
after both output pipes hit EOF and the child is reaped. Same env rules.
`setsid()` is still called so signals sent by `SessionIn::Signal` can target
the whole group later if needed (`kill(-pgid)` is a one-line change).

### Shell and home resolution

| step | Linux/macOS/FreeBSD/NetBSD            | Android                        |
| ---- | ------------------------------------- | ------------------------------ |
| 1    | `--shell PATH`                        | same                           |
| 2    | `$SHELL`                              | same (Termux sets it)          |
| 3    | `getpwuid(getuid()).pw_shell`         | skipped (bionic returns synthetic entries) |
| 4    | `/bin/sh`                             | `/system/bin/sh`               |

Home: `$HOME` → passwd → Android `/data/local/tmp` → `/`. `PATH` default:
the server's own `PATH` if set, else `/usr/local/bin:/usr/bin:/bin`
(`/system/bin:/system/xbin` on Android;
`/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin` on FreeBSD;
`/usr/pkg/bin:/usr/local/bin:/usr/bin:/bin:/usr/pkg/sbin:/usr/sbin:/sbin` on
NetBSD — BSD base tools such as `ifconfig` live in the sbin dirs and are
usable unprivileged).

### Cwd probe

Used by the meta shell. Target pid = `tcgetpgrp(master)` (foreground process
group leader), fallback shell pid.

| platform | method                                                   |
| -------- | -------------------------------------------------------- |
| Linux    | `readlink("/proc/<pid>/cwd")`                            |
| Android  | same; may fail under SELinux for other uids, not ours    |
| macOS    | `proc_pidinfo(pid, PROC_PIDVNODEPATHINFO)` → `pvi_cdir.vip_path` |
| FreeBSD  | `sysctl({CTL_KERN, KERN_PROC, KERN_PROC_CWD, pid})` → one `kinfo_file`, `kf_structsize` bounds the record, `kf_path` is the cwd (`mysh_pty::process::cwd_from_kinfo`, unit-tested on a synthetic buffer on every host) |
| NetBSD   | unsupported (`ErrorKind::Unsupported`; stretch target)   |
| other    | unsupported (`ErrorKind::Unsupported`)                   |

Failure → `None`; the meta shell falls back to the server home and says so.

FreeBSD and NetBSD support in `mysh-pty` is cross-compiled
(`cargo check`/`clippy --target {x86_64,aarch64}-unknown-freebsd`,
`x86_64-unknown-netbsd`) and statically inspected only; there is no BSD
runtime in CI or on the dev host. Inferred, not run: the `kern.proc.cwd`
reply shape (one `kinfo_file`, `kf_path` NUL-terminated), the NetBSD
`ptsname_r` fallback in `open_pty` (rustix has no `ptsname` there), and the
rustix `openpt`/`grantpt`/`unlockpt`/`ioctl_tiocsctty`/`tcgetpgrp` path on
both BSDs. The `kf_path` offset is a `const` assertion against libc's layout
under `cfg(target_os = "freebsd")`.

## Client terminal driver

`mysh::client::terminal` + `mysh::client::session`.

- The terminal is in raw mode (`cfmakeraw` on stdin's termios, input and
  output flags, as ssh does) for the whole interactive run — at the prompt
  and in sessions alike; the prompt's line editor handles echo and editing
  itself. Restored by a guard on normal exit, on panic (hook), and before
  suspend. `OPOST` is left off; the remote tty does output processing.
- Sessions opened with `shell` (and `-s`, and `CMD` with `-t`) request a PTY
  with `TERM` and the current `winsize` in `PtyRequest`. `mysh HOST CMD`
  without `-t` requests none and leaves the local terminal alone.
- Stdin bytes go to the foreground session verbatim except the **meta key**
  (05-meta-shell.md): a single-byte match in the stdin path that
  backgrounds the session and hands the terminal to the prompt. With no
  session foreground, stdin feeds the line editor.
- `SIGWINCH` → `SessionIn::Resize` on the **foreground** session with the
  fresh size. Coalesced: at most one in flight, latest wins. Background
  sessions get a `Resize` when they come to the foreground.
- Suspend (`Ctrl-Z` at the prompt; in a session the byte goes to the
  remote): restore termios, `kill(0, SIGTSTP)`; on `SIGCONT` re-enter raw
  mode, redraw the prompt.
- Terminal writes are the hot path: a single writer task, `write_all` on a
  `tokio::io::Stdout` with no extra buffering beyond the message chunk. The
  `log` tee hangs off this writer.
- **Session stack** (05-meta-shell.md). Each session has its own reader
  task consuming `SessionOut`. The foreground session's reader feeds the
  terminal writer; every other session's reader feeds a per-session
  1 MiB ring buffer, so remote processes are never throttled by client
  focus and client memory stays bounded (`bytes dropped` is counted and
  reported). Bringing a session to the foreground = flush its ring to the
  writer, report drops, send `Resize`. The meta shell is simply a state in
  which no session is foreground.
- Non-PTY mode: stdin is read and sent as `Stdin` until EOF (`StdinEof`);
  `Stdout`/`Stderr` are written to the local fds unmodified.

### Exit codes

The **primary** session is the one the CLI started (`CMD`, or the first
`shell` under `-s`); plain `mysh HOST` has none. Statuses of sessions opened
from the prompt are reported there only. The primary's status is remembered
if it exits while other sessions are still open.

| event                                                | client exit    |
| ---------------------------------------------------- | -------------- |
| primary `Exited(Code(n))`                            | `n`            |
| primary `Exited(Signal{signal})`                     | `128 + signal` |
| `exit`/`disconnect` at the prompt, `-N` stopped by signal | 0         |
| scripted stdin (`mysh HOST < file`): a command failed | 1             |
| connection lost / ping timeout                       | 255            |
| local usage / auth / trust error                     | 2              |

## Port forwarding

| flag                             | mechanism                                                       |
| -------------------------------- | --------------------------------------------------------------- |
| `-L [bind:]port:host:hostport`   | client listens; per accept → `DirectTcp{host,hostport}`          |
| `-R [bind:]port:host:hostport`   | `ForwardListen{bind,port}` on server; per `ForwardedTcp` → client dials `host:hostport` |
| `-D [bind:]port`                 | client SOCKS5 (CONNECT only) → `DirectTcp`                        |

- Default `bind` is `127.0.0.1`; `*` or `0.0.0.0`/`::` binds all.
- Server policy: `--deny forward-local` disables `DirectTcp`,
  `--deny forward-remote` disables `ForwardListen`. Bind addresses requested
  by the client are honoured as-is in v1 (GatewayPorts-style restrictions are
  roadmap).
- Copy loop: two `tokio::io::copy` halves with half-close propagation in both
  directions; an error on either side resets the stream and closes the
  socket. Errors are reported once per connection on the client's stderr
  (or in the meta shell if open).
- Forwards may be added and removed at runtime from the meta shell; each has
  a small integer id shown by `forward ls`.
- `-N` connects with forwards only and no session; exits on `Ctrl-C` or
  connection loss.

## File transfer

`mysh::client::files` drives the `File` streams (03-protocol.md §9). One
stream per file; recursive operations run several at a time (`-j`, below).

`put [-r] [-c] [-P] [-F] LOCAL... [REMOTE]` (`-P` preserve, `-F` follow
symlinks; `-p`/`-L` are taken by the shared connection options):

- one LOCAL and REMOTE absent → REMOTE = session cwd (probe) / `~`;
  one LOCAL and REMOTE is a directory → `REMOTE/<basename>`; several LOCAL →
  REMOTE must be a directory;
- regular file: `Put{ mode, mtime (with -P), offset: 0, truncate: true, atomic }`,
  stream, await `PutDone`;
- `-c` continue: `Stat` the remote; if it is a regular file shorter than
  local, `offset = remote size, truncate: false, atomic: false`;
- `-r`: walk local tree, `Mkdir` (ignore exists), files as above; symlinks
  are skipped with a notice unless `-F` follows them;
- progress bar per file plus totals when stderr is a terminal.

`get [-r] [-c] [-P] REMOTE... [LOCAL]` mirrors it: `Stat`/`List` first,
`Get{offset}` per file, local temp-and-rename, set mode/mtime with `-P`.

`ls [-l] [-a] [REMOTE]` → `List`, formatted like `ls -l` (mode string, size,
mtime, name).

Parallel recursive transfers (`-j N`, default 4): `put -r`/`get -r` walk
the tree first — directories created pre-order in name order, regular
files collected — then open up to `N` file streams at once (a `JoinSet`
behind a semaphore), then apply directory attributes post-order (`-P`).
Progress is one aggregate line, `NAME: n/m files  X/Y  P%`; the summary
counts the whole tree. The first failing file aborts the remaining ones
and the command returns its error (files already completed stay; `put`'s
atomic rename means no partial file is ever visible). Top-level
non-recursive arguments are still transferred one after another.

Throughput note: a single stream is bounded by the yamux window ÷ RTT
(4 MiB / 50 ms ≈ 80 MB/s) and by ChaCha20-Poly1305 (≫ 1 GB/s on these
CPUs). Good enough; no parallel chunking of one file — parallelism is per
file (`-j`), which is where directory trees spend their time.

`--checksum` (`put`, `get`, also per file under `-r`): before a regular
file is transferred, `Stat` the other side; when it is a regular file of
the same size, `Hash { Blake2s256 }` it remotely and hash the local copy
on the blocking pool (`spawn_blocking`); equal digests skip the file. The
summary separates `files` (moved) from `skipped` (`-c` on a complete file,
`--checksum` on an identical one).

### File primitives

`mysh::client::fileops` (plus `files::cat`/`put -`) gives every file
operation a one-shot CLI form (`mysh HOST cat …`), a prompt form and a
control-socket form, with one clap struct per command (`cli::FileCmd`).
Relative remote paths resolve against the MRU session's cwd at the prompt
and against the home directory elsewhere.

| command                                   | wire                                                                                   |
| ----------------------------------------- | -------------------------------------------------------------------------------------- |
| `get REMOTE… -`, `cat REMOTE…`            | `Get { offset: 0 }` per file, bodies to stdout in order; no progress line (stdout is the body); `--json` → one `DataOut {data, bytes}` |
| `put [--mode M] [--mtime T] - REMOTE`     | stdin to EOF into `Put { mode (default 0644), mtime, offset: 0, truncate: true, atomic }`; REMOTE must name a file; over the control socket the request's stdin (≤ 64 KiB) is the body, a larger one uses the caller's own connection |
| `write [--mode M] [--append] REMOTE`      | stdin to EOF; atomic replace, or after a `Stat` `Put { offset: size, truncate: false, atomic: false }` (an appended file keeps its mode unless `--mode`) |
| `tail [-n N] [-f] [--for D] REMOTE`       | `Stat`, then `Get { offset: size − window }` (64 KiB, ×4 until the window holds `N` lines or reaches 0), bytes past the stat'ed size dropped, last `N` lines printed; `-f` then opens `Get { offset: size, follow: true }` and prints as bytes arrive until Ctrl-C, `--for`, or the connection's `--timeout` (all exit 0); dropping the stream ends the server's poll |
| `stat REMOTE…`                            | `Stat` each; `--json` → `StatOut` (one path) or `[StatOut]`                              |
| `mkdir [-P] [-m MODE] REMOTE…`            | `Mkdir` (mode default 0755); `-P` walks the components with `Stat`/`Mkdir`, existing directories are fine (`-p` is the shared port option) |
| `rm [-r] REMOTE…`                         | `Remove { recursive }`                                                                  |
| `mv FROM TO`                              | `Rename`                                                                                |
| `realpath REMOTE`                         | `Realpath`; `--json` → `RealpathOut {path, realpath}`                                    |
| `hash REMOTE…`                            | `Hash`; prints `blake2s256  <hex>  <size>  <path>`; `--json` → `HashOut` or `[HashOut]`  |

### sync

`sync [--pull] [--delete] [--dry-run] [--checksum] [-j N] SRC DST`
mirrors one tree into another; exactly one side is remote and the
**command form** says which — `sync LOCAL REMOTE` pushes, `sync --pull
REMOTE LOCAL` pulls. There is no `HOST:` prefix: the connection already
names the host.

1. Plan: walk both trees (`List` pages remotely, `read_dir` locally;
   symlinks and special files are skipped with a notice on the source and
   count as extras on the destination). A source file is copied when the
   destination lacks it (`missing`), differs in size (`size`), differs in
   mtime by more than 1 s (`mtime`), or — with `--checksum`, which replaces
   the mtime test for same-size files — differs in BLAKE2s digest
   (`content`). The result is a `SyncPlan { copies: [{path, size, reason}],
   deletes: [path], unchanged, bytes }`; `--dry-run` prints it (JSON, or
   one `copy`/`delete` line per entry plus a total) and changes nothing.
2. Execute: create the missing directories pre-order (mode 0755), then
   transfer the copies with the parallel machinery above (`-j`, default
   4) **preserving mtime and mode** (so the next plan sees them as
   unchanged), then with `--delete` remove the destination's extras —
   files first, then directories deepest first. The summary is a
   `SyncSummary { copied, deleted, unchanged, bytes, duration_ms }`.
