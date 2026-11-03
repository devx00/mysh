# Server

`mysh serve` is the same binary as the client. It listens on one TCP port, runs as the user that started it, and serves that user's shell, home directory and network. There is no privilege separation and no `/etc` configuration: everything is flags plus the files under `~/.config/mysh`. This page explains each flag and when you want it, what a session sees, what survives a disconnect, the audit log, running as a service, and signals. Reference: [cli-reference.md](cli-reference.md#mysh-serve); design: [02-security.md](../02-security.md), [04-sessions.md](../04-sessions.md).

A minimal server:

```
mysh serve -v
```

```
INFO generated new host key path=/home/you/.config/mysh/host_key fingerprint=SHA256:I1JT…
INFO authorized client keys loaded keys=2
INFO listening addr=[::]:7722
INFO host identity fingerprint=SHA256:I1JT… source=/home/you/.config/mysh/host_key
```

It fails closed when it has nobody to trust: `no authorized client keys: add one to /home/you/.config/mysh/authorized_keys or pass --authorized-key`. Pass a key, or `--pair` to bootstrap with a code ([getting started](getting-started.md#pairing-no-copy-paste)).

## Options

### Network

| option | default | use it when |
| --- | --- | --- |
| `--listen ADDR` (repeatable) | `[::]:7722`, falling back to `0.0.0.0:7722` when IPv6 is unavailable | you want a specific interface or port: `--listen 10.0.0.5:7722 --listen [fd00::5]:7722`. `127.0.0.1:0` picks a free port and logs it (`-v`) |
| `--name NAME` | the hostname | the hostname is unhelpful (containers, duplicates); the name shows in the client's `info` and in `known_hosts` lines written by pairing |
| `--handshake-rate N` | 10 | per-source-address handshakes per minute. Raise it for a host that is the target of many scripted one-shot calls from one address; `0` disables the limit. An over-limit connection is dropped without a reply, which the client reports as `connection reset` ([troubleshooting](troubleshooting.md#connection-reset-after-a-burst-of-calls)) |
| `--idle-timeout SECS` | 120 | a connection with no control traffic for this long is closed. Clients ping every 30 s, so a healthy client never trips it; lower it on hosts that see many abandoned connections, raise it for lossy links |

### Identity and trust

| option | default | use it when |
| --- | --- | --- |
| `--key PATH` | `$MYSH_HOST_KEY`, baked, `~/.config/mysh/host_key` | you want a particular host key; `--key /etc/ssh/ssh_host_ed25519_key` presents the same identity as `sshd`, so clients verify it through `~/.ssh/known_hosts` with no new trust step (needs read access to that file; the server refuses a group- or world-readable private key) |
| `--no-generate-key` | generate on first start | a missing host key must be a deployment error, not a new identity (immutable images, fleets with baked keys) |
| `--authorized-key LINE` (repeatable) | — | one-off trust from the command line: `--authorized-key "$(cat laptop.pub)"` |
| `--authorized-keys PATH` (repeatable) | — | an extra `authorized_keys` file beyond `~/.config/mysh/authorized_keys` (a shared team file, a file managed by configuration management). Must exist at start |
| `--no-ssh-authorized-keys` | read `~/.ssh/authorized_keys` | the ssh keys on this machine should *not* open mysh |
| `--no-signature-auth` | accept agent keys | you want to refuse `ssh-agent`-held ed25519 keys and accept only keys the client holds as files; clients with agent keys only are told the server does not support them |
| `--pair [DURATION]` | no window | first contact without copying keys: prints a one-time code valid for `DURATION` (default `5m`) and lets the server start with an empty trusted set. `SIGUSR1` opens another window later |
| `--baked-only` | files extend baked keys | a binary built with `--features baked` must trust *only* its compiled-in peers and ignore `authorized_keys` files |

How the trusted set is assembled and what per-key options do is in [keys and trust](keys-and-trust.md#server-trust-who-may-connect). All key files are re-read on every connection.

### Sessions and policy

| option | default | use it when |
| --- | --- | --- |
| `--shell PATH` | `$SHELL`, then the passwd entry, then `/bin/sh` (`/system/bin/sh` on Android) | the login shell is wrong for remote use (a restricted shell, a missing `$SHELL` under a service manager). Sets both the program `shell` sessions run and `$SHELL` in every session |
| `--accept-env NAME` (repeatable) | `TERM`, `LANG`, `LC_*`, `COLORTERM` | clients may set more variables with `--env`: `--accept-env EDITOR --accept-env 'GIT_*'` (a trailing `*` matches a prefix). Anything not accepted is dropped silently |
| `--deny FEATURE` (repeatable) | everything allowed | this host must not offer a feature at all: `pty` (interactive shells, `-t`), `exec` (non-PTY commands), `files` (every file command *and* `authorize`), `forward-local` (`-L` and `-D`), `forward-remote` (`-R`). Per-key `authorized_keys` options narrow further per client |
| `--detach-grace SECS` | 600 | how long a PTY session whose client went away is kept for `--attach`; `0` turns persistence off entirely (the client is told, `--attach` exits 2) |
| `--audit PATH` | off | you need a record of who did what: one JSON line per event appended to `PATH` (created 0600), or `-` for stderr. Format below |

### Logging

`-v` logs connections, sessions and the listening address at `info`; `-vv` adds handshake and stream events; `-vvv` traces. Without `-v` only warnings appear (unauthorized keys, rate limiting, pairing failures). `RUST_LOG` overrides all of it. Logs go to stderr, colored only when stderr is a terminal.

## What a session gets

The server builds every session's environment from scratch rather than inheriting its own:

| variable | value |
| --- | --- |
| `HOME`, `USER`, `LOGNAME` | the serving user's |
| `PATH` | the server's own `PATH`, or a platform default (`/usr/local/bin:/usr/bin:/bin` on Linux and macOS; the BSDs add their sbin dirs; `/system/bin:/system/xbin` on Android) |
| `SHELL` | the resolved shell (`--shell`, else the login shell) |
| `MYSH_CONNECTION` | `<client ip> <client port> <server ip> <server port>`, like `SSH_CONNECTION` |
| `MYSH_SESSION` | the session id (server-wide counter; what `sessions -a` and `--attach=ID` show) |
| `MYSH_ORIGINAL_COMMAND` | under a `command="…"` key option only: what the client asked to run |
| `TERM`, `LANG`, `LC_*`, `COLORTERM` | sent by the client, if it sent them |
| anything else | only if sent with `--env` *and* listed in `--accept-env` |

`MYSH_*` names are always set by the server and never taken from the client.

A `shell` session runs the shell as a login shell (`-zsh`) under a PTY sized to the client's terminal. `mysh HOST CMD` runs `CMD` directly when it has several words and through `shell -c` when it is one word, like `ssh`; `-t` gives it a PTY. The working directory is the home, or `--cwd DIR` (`~`-relative) when it exists; a missing `--cwd` is not an error, the session starts in home and the client is told.

Sessions are not sandboxed: a client that can open a shell has everything the serving user has. Run the server as the user whose access you mean to grant.

## What persists across disconnects

- **PTY sessions** whose client disappeared (connection lost, `detach`, `disconnect`) stay alive for `--detach-grace` seconds (default 10 minutes). Output produced meanwhile is kept in a 1 MiB ring and replayed on `--attach`; no screen state is kept, so full-screen programs redraw on the resize that follows reattachment, or on `Ctrl-L`. A detached session belongs to the client *key* that opened it; another key cannot see or attach it. See [sessions](sessions.md).
- **Exec sessions** (`mysh HOST CMD`, `session new`) do not persist. The `session` family is the way to run something that outlives one command; see [automation](automation.md).
- **Remote forwards** (`-R`) close with the connection.
- **Trust files** are plain files, re-read per connection; `authorize` and pairing append to them.
- Nothing else is stored. There is no session database, no history on the server side.

## Audit log

`--audit PATH` appends one JSON object per line, flushed per line, independent of `-v`. The schema is stable; the human log is not.

```json
{"ts":"2026-11-03T10:38:52.187Z","peer":"127.0.0.1:52987","key":"SHA256:6gIaFXtDcamPupzTf4VYouZGpo4JGabwg75BzbOFs/8","kind":"x25519","event":"session","detail":{"argv":["zsh","-c","uname"],"cwd":"/home/you","id":1,"pid":7123,"program":"/bin/zsh","pty":false},"exit":null,"bytes_in":null,"bytes_out":null,"duration_ms":null}
{"ts":"2026-11-03T10:38:52.194Z","peer":"127.0.0.1:52987","key":"SHA256:6gIaFXtDcamPupzTf4VYouZGpo4JGabwg75BzbOFs/8","kind":"x25519","event":"exec","detail":{"id":1,"pid":7123,"pty":false,"signal":null},"exit":0,"bytes_in":null,"bytes_out":null,"duration_ms":6}
{"ts":"2026-11-03T10:38:59.634Z","peer":"127.0.0.1:53005","key":"SHA256:gsjra7HBOBslnk8qw2IX7A2dP2mfgaJ8oWmzJllsTcI","kind":"x25519","event":"denied","detail":{"what":"handshake","why":"key not authorized"},"exit":null,"bytes_in":null,"bytes_out":null,"duration_ms":null}
```

| field | meaning |
| --- | --- |
| `ts` | RFC 3339 UTC with milliseconds, stamped when written |
| `peer` | client `ip:port` |
| `key`, `kind` | the client's fingerprint and `x25519` or `ssh-ed25519` (`"?"`/`""` when refused before any key was offered) |
| `event` | `connect`, `disconnect`, `session`, `exec`, `file`, `forward`, `pair`, `denied` |
| `detail` | event-specific, always present: `{version, pairing}` for `connect`; `{id, pid, pty, program, argv, cwd}` for `session`; `{id, pid, pty, signal}` for `exec`; `{op, path, to?, error?}` for `file`; `{kind, host, port, …}` for `forward`; `{what, why}` for `denied` |
| `exit` | exit code of an `exec` (`null` when killed by a signal) |
| `bytes_in`, `bytes_out` | where known: the whole connection on `disconnect`, the transfer on `file` |
| `duration_ms` | where known |

The log is the server's view only: no session output, no file contents. Every line carries the authenticated key, so `jq 'select(.key == "SHA256:…")' audit.log` reconstructs one client's activity. There is no rotation; use copy-truncate, or restart with a new path.

## Running as a service

Ready-made units are in `contrib/`. Each runs `mysh serve --listen [::]:7722` and relies on the host key being generated on first start; authorize clients in the config directory's `authorized_keys` before or after.

### systemd (Linux)

```
install -m 755 mysh /usr/local/bin/mysh
install -m 644 contrib/mysh.service /etc/systemd/system/mysh.service
systemctl daemon-reload && systemctl enable --now mysh
```

The unit runs a dedicated dynamic `mysh` user with `HOME=/var/lib/mysh` and `MYSH_CONFIG_DIR=/var/lib/mysh/.config/mysh`, so keys live in `/var/lib/mysh/.config/mysh/` and `authorize` lands in the same file. Sessions are shells of that user; change `User=` (and drop `DynamicUser`) for a root shell. `ProtectSystem=strict` with `ReadWritePaths=/var/lib/mysh /tmp` means sessions cannot write elsewhere; widen it if the host is meant to be administered through mysh. Stop is `SIGTERM` with a 10 s timeout.

### launchd (macOS)

```
install -m 755 mysh /usr/local/bin/mysh
cp contrib/com.mysh.serve.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mysh.serve.plist
```

A launch agent, so it serves the logged-in user and uses `~/.config/mysh`. Output goes to `/tmp/mysh.log`. For a daemon that runs without a login session, put the plist in `/Library/LaunchDaemons` and add a `UserName` key.

### Termux:Boot (Android)

```
mkdir -p ~/.termux/boot
cp contrib/termux-boot/mysh.sh ~/.termux/boot/
chmod +x ~/.termux/boot/mysh.sh
```

Install and open the Termux:Boot app once so Android allows it. The script expects the binary at `~/bin/mysh` (`MYSH_BIN` overrides), listens on `MYSH_LISTEN` (default `[::]:7722`), takes a wake lock, and logs to `~/.config/mysh/serve.log`. Per-platform notes: [platforms](platforms/README.md).

### Where `authorize` writes

`mysh authorize` appends to `~/.config/mysh/authorized_keys` on the server, resolving `~` against the serving user's `HOME`. The server itself reads `$MYSH_CONFIG_DIR/authorized_keys`. The two coincide unless you point `MYSH_CONFIG_DIR` (or `XDG_CONFIG_HOME`) somewhere other than `$HOME/.config/mysh`; if you do, also pass `--authorized-keys ~/.config/mysh/authorized_keys` so authorized keys are picked up, or install keys by hand.

## Signals

| signal | effect |
| --- | --- |
| `SIGTERM`, `SIGINT` | graceful stop: tells every client to shut down, waits up to 5 s for sessions to end, hangs up detached sessions, exits 0 |
| `SIGHUP` | ignored. Key files are re-read on every connection, so there is nothing to reload |
| `SIGUSR1` | opens a new 5-minute pairing window (replacing any open one) and prints its code to stderr |

Before `SIGUSR1` is useful under a service manager, make sure you can read the server's stderr (the journal, `/tmp/mysh.log`, `serve.log`): the code appears nowhere else.
