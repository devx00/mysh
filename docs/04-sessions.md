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
   - `env_clear()`, then `HOME`, `USER`, `LOGNAME`, `PATH`, `SHELL`,
     `MYSH_CONNECTION="<client ip> <client port> <server ip> <server port>"`,
     `MYSH_SESSION=<id>`, plus allow-listed client env (02-security.md);
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
7. **Client gone.** If the stream closes first, the server closes the master;
   the session gets `SIGHUP` via the controlling tty; processes that ignore
   it (`nohup`) survive, as with ssh. The child is not force-killed.

### Exec session (no PTY)

Pipes for stdin/stdout/stderr; `StdinEof` closes the write end; `Exited`
after both output pipes hit EOF and the child is reaped. Same env rules.
`setsid()` is still called so signals sent by `SessionIn::Signal` can target
the whole group later if needed (`kill(-pgid)` is a one-line change).

### Shell and home resolution

| step | Linux/macOS                           | Android                        |
| ---- | ------------------------------------- | ------------------------------ |
| 1    | `--shell PATH`                        | same                           |
| 2    | `$SHELL`                              | same (Termux sets it)          |
| 3    | `getpwuid(getuid()).pw_shell`         | skipped (bionic returns synthetic entries) |
| 4    | `/bin/sh`                             | `/system/bin/sh`               |

Home: `$HOME` → passwd → Android `/data/local/tmp` → `/`. `PATH` default:
the server's own `PATH` if set, else `/usr/local/bin:/usr/bin:/bin`
(`/system/bin:/system/xbin` on Android).

### Cwd probe

Used by the meta shell. Target pid = `tcgetpgrp(master)` (foreground process
group leader), fallback shell pid.

| platform | method                                                   |
| -------- | -------------------------------------------------------- |
| Linux    | `readlink("/proc/<pid>/cwd")`                            |
| Android  | same; may fail under SELinux for other uids, not ours    |
| macOS    | `proc_pidinfo(pid, PROC_PIDVNODEPATHINFO)` → `pvi_cdir.vip_path` |

Failure → `None`; the meta shell falls back to the server home and says so.

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
stream per file; recursive operations issue them sequentially (parallel
transfers are roadmap).

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

Throughput note: a single stream is bounded by the yamux window ÷ RTT
(4 MiB / 50 ms ≈ 80 MB/s) and by ChaCha20-Poly1305 (≫ 1 GB/s on these
CPUs). Good enough; no parallel chunking in v1.
