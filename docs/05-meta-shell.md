# 05 — Meta shell and CLI

The meta shell is the client-side command interpreter that drives everything
a session can do besides typing into the remote shell. It has three
frontends over one dispatcher (`mysh::client::meta`):

1. the in-session escape (`~:`), interactive;
2. CLI subcommands (`mysh put HOST …`) that open a connection, run one
   command, exit;
3. (roadmap) a control socket so a second terminal can reuse a live
   connection.

## Escape sequences

Modelled on ssh: the escape character (default `~`) is recognised only at the
start of a line (after Enter, or at session start). The `~` is held until the
next key; if that key is not a command the client sends both bytes.

| keys     | action                                           |
| -------- | ------------------------------------------------ |
| `~~`     | send a literal `~`                               |
| `~.`     | disconnect immediately (exit 255 if a session was live, else 0) |
| `~^Z`    | suspend the client (04-sessions.md)              |
| `~:`     | open the meta shell                              |
| `~?`     | print this table                                 |
| `~i`     | print one-line connection info, stay in session  |

`-e CHAR` changes the character, `-e none` disables escapes (for nested
sessions or binary protocols over stdin). The state machine lives in
`client::terminal` and is unit-tested against: start-of-session, after
`\r`, after `\n`, mid-line (`~` forwarded), double escape, unknown second
byte.

## Meta shell session

- Prompt `mysh> ` printed on the same terminal; the terminal is switched to
  cooked mode for native line editing; remote output is paused via
  backpressure (not dropped, not buffered client-side).
- Enter on an empty line, `exit`, or `Ctrl-D` returns to the session, which
  resumes exactly where it was; a `Resize` is sent on return in case the
  window changed.
- `Ctrl-C` cancels the running meta command (e.g. a `put`), not the remote
  shell.
- Tokenizer: POSIX-like quoting via `shlex` (`put "my file.txt"`). Local
  paths get `~` expansion on the client; remote paths on the server.
- Commands run on the live connection as new yamux streams; the session
  stream is untouched.
- Every command has `-h`; `help` lists them. Each command is a small
  `clap` parser so CLI subcommands and in-session commands share one
  definition.

## Commands (v1)

| command     | synopsis                                                        | notes                                                                 |
| ----------- | --------------------------------------------------------------- | --------------------------------------------------------------------- |
| `help`      | `help [CMD]`                                                    |                                                                       |
| `put`       | `put [-r] [-c] [-p] [-L] LOCAL... [REMOTE]`                     | default REMOTE = session cwd (probe) → `~`; progress bar               |
| `get`       | `get [-r] [-c] [-p] REMOTE... [LOCAL]`                          | default LOCAL = client cwd                                             |
| `ls`        | `ls [-l] [-a] [REMOTE]`                                         | remote listing; default = session cwd                                  |
| `cwd`       | `cwd`                                                           | print remote cwd (probe source: fg process / shell / fallback) and local cwd |
| `lcd`       | `lcd [DIR]`                                                     | change the client's working directory used by the meta shell           |
| `forward`   | `forward -L SPEC` · `-R SPEC` · `-D SPEC` · `forward ls` · `forward rm ID` | same SPEC grammar as the CLI flags; ids are stable per connection |
| `exec`      | `exec CMD...`                                                   | run a non-PTY exec session; stream output into the meta shell; prints exit code. For quick checks without disturbing the interactive shell |
| `info`      | `info`                                                          | server name, address, protocol version, peer fingerprint + how it was trusted, cipher, uptime, bytes in/out, RTT, session pid, pty size, active forwards |
| `ping`      | `ping [-c N]`                                                   | control-stream pings, RTT min/avg/max                                  |
| `resize`    | `resize`                                                        | re-send the current terminal size                                      |
| `log`       | `log FILE` · `log off`                                          | tee raw remote output to FILE from now on (`script`-like)              |
| `authorize` | `authorize [PUBKEY_FILE]`                                       | append the client's public key (default: the identity in use) to the server's `~/.config/mysh/authorized_keys` via `File` ops; creates the dir `0700`; skips if already present. Equivalent of `ssh-copy-id` |
| `disconnect`| `disconnect`                                                    | same as `~.`                                                           |
| `exit`      | `exit` / empty line / `Ctrl-D`                                  | back to the session                                                    |

Output formats are plain text, one record per line, suitable for eyes; there
is no machine-readable mode in v1.

## CLI

```
mysh [OPTIONS] HOST [--] [CMD ...]      connect (interactive if no CMD and stdin is a tty)
mysh connect [OPTIONS] HOST [CMD ...]   same; escape hatch when HOST collides with a subcommand name
mysh serve [OPTIONS]
mysh keygen [-o PATH] [-C COMMENT]
mysh fingerprint [FILE]                 key file (private or public, either format); `-` for stdin
mysh put    [OPTIONS] HOST LOCAL... [REMOTE]
mysh get    [OPTIONS] HOST REMOTE... [LOCAL]
mysh forward [OPTIONS] HOST (-L|-R|-D SPEC)...     = connect -N with forwards
mysh authorize [OPTIONS] HOST [PUBKEY_FILE]
```

Subcommand names are reserved words that cannot be used as bare `HOST`; use
`mysh connect NAME` for a host literally named `serve`.

Connection options (shared by every HOST-taking command):

| option                | meaning                                                   |
| --------------------- | --------------------------------------------------------- |
| `-p PORT`             | port (default 7722, or from `HOST:PORT`)                  |
| `-i PATH`             | identity file (02-security.md order)                      |
| `--pin KEY`           | expected server key or fingerprint                        |
| `--accept-new` / `--strict` | TOFU policy                                         |
| `-t` / `-T`           | force / forbid PTY                                        |
| `-N`                  | no session (forwards only)                                |
| `-L/-R/-D SPEC`       | forwards, repeatable                                      |
| `-e CHAR|none`        | escape character                                          |
| `--env NAME[=VALUE]`  | send an environment variable (server must accept it)      |
| `--baked-only`        | ignore files on disk                                      |
| `-v`                  | repeatable; `-vv` includes handshake and stream events    |

`HOST` forms: `host`, `host:port`, `[v6addr]:port`, `v6addr` (bare), or a
config alias (below).

Server options:

| option                              | meaning                                                   |
| ----------------------------------- | --------------------------------------------------------- |
| `--listen ADDR`                     | repeatable; default `[::]:7722` (dual-stack) with fallback to `0.0.0.0:7722` |
| `--key PATH`, `--no-generate-key`   | identity                                                  |
| `--authorized-keys PATH`, `--authorized-key KEY`, `--no-ssh-authorized-keys` | trust               |
| `--shell PATH`                      | override shell resolution                                 |
| `--accept-env NAME`                 | repeatable; extra env names accepted from clients         |
| `--deny FEATURE`                    | `pty`, `exec`, `files`, `forward-local`, `forward-remote` |
| `--name NAME`                       | name sent in `ServerHello` (default hostname)             |
| `--baked-only`                      | ignore files on disk                                      |
| `-v`                                | log level                                                 |

Signals: `SIGTERM`/`SIGINT` → send `Shutdown` on every connection, wait up
to 5 s for sessions to end, exit. `SIGHUP` is ignored (files are re-read per
connection anyway).

## Config file (v1, minimal)

`~/.config/mysh/config.toml`, optional, aliases only:

```toml
[hosts.pi]
host = "pi.lan"
port = 7722
identity = "~/.ssh/id_ed25519"
pin = "SHA256:…"
forward = ["-L 8080:localhost:80"]
env = ["LANG"]
```

Flags override the alias; the alias overrides defaults. No `Match` blocks,
no includes.

## Control socket (roadmap, designed now)

`$XDG_RUNTIME_DIR/mysh/<server-fingerprint>.sock` (falls back to
`~/.cache/mysh/`), created by interactive clients. A CLI subcommand for the
same host connects to it if present and sends the meta command line; the
interactive client executes it on its connection and streams back output.
The dispatcher already takes an abstract "output sink", which is what makes
this a transport change rather than a feature rewrite.
