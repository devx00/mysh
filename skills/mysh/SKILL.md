---
name: mysh
description: Run commands, manage long-lived sessions, and move files on remote hosts through the mysh CLI against an already-running mysh server. Use whenever a task needs to execute something on a machine that is reachable over mysh (not ssh); prefer it over `mysh mcp` when you already have a shell.
---

# mysh from the command line

mysh is an encrypted remote shell. Every command below talks to a server
that is already running (`mysh serve` on the remote). Nothing here starts
servers or installs keys except the "First contact" section.

Three rules that make it agent-safe:

1. **Always pass `--json`** (or `--json-stream`) and parse stdout. Errors are
   one JSON line on stderr: `{"error":{"code":"…","message":"…"}}`. Never
   scrape human output.
2. **Always bound long operations**: `--timeout 30s` on commands, `--wait`
   on session reads. A remote command that exceeds `--timeout` is killed
   (TERM, then KILL after 2 s), the result carries `"timed_out": true`, and
   the exit code is 124.
3. **Reuse one connection** for many calls: start a master once
   (`mysh master HOST --idle 10m &`), and every later `mysh HOST …` goes
   through its socket without a new handshake. Masters exit by themselves
   after `--idle`. This is not optional at scale: servers rate-limit
   handshakes per source IP (default 10/min), so a burst of socket-less
   calls starts failing with `connect_failed` ("connection reset").
   Every process that shares your `$XDG_RUNTIME_DIR` uses the master's
   socket — and therefore the master's identity — regardless of its own
   `-i`; use `--no-ctl` to force a connection of your own.

`HOST` is `host`, `host:port`, or an alias from `~/.config/mysh/config.toml`.
Default port 7722.

## Quick reference

| task | command | stdout shape |
| --- | --- | --- |
| run a command | `mysh --json --timeout 30s HOST 'cmd args'` | `{"stdout","stderr","exit","signal","duration_ms","timed_out"}` |
| run with cwd | `mysh --json --cwd /srv HOST 'ls'` | same |
| stream output as it happens | `mysh --json-stream HOST 'make'` | NDJSON events: `started`, `stdout`, `stderr`, `exit` (last) |
| facts about the host | `printf 'info\n' \| mysh --json HOST` | `{"server":{"platform":{"os","arch","kernel"},"shell","home","user","limits",…},…}` |
| start a long-running process | `mysh session HOST --json new -- cmd args` | `{"id":N,"pid":P}` |
| read its output (idempotent) | `mysh session HOST --json read N --since OFFSET --wait 5s` | `{"chunks":[{"stream":"stdout"\|"stderr","data":"…"}],"next","oldest","offset","exited"}` |
| write to its stdin | `mysh session HOST send N 'text'` · `--eof` closes stdin | — |
| list / stop / wait | `mysh session HOST --json list` · `kill N [-s INT]` · `wait N --timeout 1m` | list: array of `{id,pid,kind,started,detached,buffered,pty,next,oldest,exited}` |
| read a file | `mysh cat HOST ~/path` (raw bytes to stdout) · `mysh stat HOST --json ~/path` | file bytes · `{"kind","size","mode","mtime","uid","gid","target"}` |
| write a file | `printf 'content' \| mysh write HOST ~/path [--mode 644] [--append]` | — |
| follow a log | `mysh tail HOST -f --for 30s ~/app.log` | lines as they arrive, exits 0 at the deadline |
| copy files | `mysh put HOST local ~/remote` · `mysh get HOST ~/remote local` · `put -`/`get … -` for stdin/stdout | summary line |
| mirror a tree | `mysh sync HOST --json [--dry-run] [--delete] [--pull] LOCAL ~/REMOTE` | `{"copies":[{"path","size","reason"}],"deletes":[],"unchanged":N,"bytes"}` |
| same command on many hosts | `mysh run --json [-j 4] --hosts a,b,c -- 'cmd'` (or `--group NAME`) | array of `{"host","ok","exit","stdout","stderr","duration_ms","error"}` |
| keep a connection open | `mysh master HOST --idle 10m &` | — (socket under `$XDG_RUNTIME_DIR/mysh/`) |
| the full command tree | `mysh help --json` | clap tree with args and defaults |

Exit codes: the remote command's exit code for `mysh HOST CMD`; 124 on
`--timeout`; 2 for usage/trust/connect errors (details in the JSON error);
255 when the connection dropped.

Error codes (`error.code`): `unauthorized`, `denied`, `not_found`,
`unsupported`, `io`, `limit`, `protocol`, `trust_unknown`, `trust_mismatch`,
`connect_failed`, `timeout`, `usage`, `internal`.

## Patterns

**Run and parse** — exit is inside the document; a non-zero exit is data,
not an error:

```sh
out=$(mysh --json --timeout 60s box 'systemctl is-active nginx') || true
echo "$out" | jq -r '.stdout'      # "active\n"
echo "$out" | jq '.exit'           # 0 / 3
```

**Long-running process with incremental reads** — offsets are absolute byte
counts over everything the session ever printed; the same `--since` returns
the same bytes until they age out of the 1 MiB ring (`oldest` tells you if
you fell behind). Loop on `next`:

```sh
id=$(mysh session box --json new -- make -j4 2>&1 | jq .id)
off=0
while :; do
  r=$(mysh session box --json read "$id" --since "$off" --wait 5s)
  echo "$r" | jq -r '.chunks[] | select(.stream=="stdout") | .data' | tr -d '\n' ; echo
  off=$(echo "$r" | jq .next)
  [ "$(echo "$r" | jq '.exited != null')" = true ] && break
done
```

`--follow` does the loop for you when you just want the stream printed.
Non-PTY sessions keep stdout and stderr separate; `--pty` merges them (use it
only for programs that insist on a terminal).

**Interactive program (REPL, `python`, `psql`)** — `session new` with the
program, `session send ID 'line\n'`, then `session read`. `send --eof`
closes stdin when you are done.

**Files without a shell round trip** — `cat`/`write`/`stat`/`mkdir -P`/`rm
-r`/`mv`/`realpath`/`hash` exist so you never need `cat <<EOF` quoting
games. `write` is atomic (temp file + rename) unless `--append`.

**Many hosts** — `run` keeps output attributed and never lets one dead host
block the others; a dead host yields `"error":{"code":"connect_failed"}`
and the overall exit code is 1.

## Trust and first contact

- An unknown server key fails with `trust_unknown` when stdin is not a
  terminal (agents never get a prompt). Add `--accept-new` **once** to record
  it, or pin it: `--pin SHA256:…`. A changed key is `trust_mismatch` and has
  no override flag by design — stop and surface it.
- Your identity: `~/.config/mysh/id` (made by `mysh keygen`), or
  `~/.ssh/id_ed25519`, or any ed25519 key in `$SSH_AUTH_SOCK`; `-i PATH`
  selects one.
- If your key is not authorized yet (`unauthorized`) and someone can run
  `mysh serve --pair` (or send the server `SIGUSR1`) to print a one-time
  code: `mysh pair HOST word-word-word-word-word-word` installs your key
  there and the server's key here. Everything else needs a human.

## Prompt commands over scripted stdin

Any prompt command runs non-interactively by piping it in; the global
`--json` applies to all of them (do **not** put `--json` after the command):

```sh
printf 'info\nsessions -a\nforward ls\n' | mysh --json box
```

Each command prints one JSON document; the run stops at the first failing
command with exit 1.

## Don'ts

- Don't use `mysh -s HOST` or bare `mysh HOST` (interactive prompt) from an
  agent — they expect a terminal.
- Don't `--accept-new` on every call; record once, then let `trust_mismatch`
  mean something.
- Don't poll `session read` without `--wait`; it blocks up to the wait for
  new output and returns immediately when the process has exited.
- Don't pass `--hosts` to commands other than `run`, `put`, `get` — it is a
  usage error.
