# Automation

mysh is meant to be driven by programs as much as by people. Three global
flags switch every command from human output to machine output, and nothing
else about the command changes.

| flag | stdout | stderr |
| --- | --- | --- |
| `--json` | one JSON document per command | `{"error": {...}}` lines |
| `--json-stream` | newline-delimited events, as they happen | nothing of mysh's |
| `--plain` | text with no ANSI, progress, banner or prompt redraws | notices (`[mysh] …`) |

`--plain` is implied by both JSON modes and whenever stdout is not a
terminal. In a JSON mode `mysh HOST` never starts the line editor: stdin is
read as a script of prompt commands even on a terminal, and each prints its
document in turn.

Two more flags matter everywhere:

- `--timeout DURATION` (`500ms`, `10s`, `2m`, `1h`; a bare number is
  seconds) bounds a command, a transfer or a `tail -f`. A command gets
  `TERM`, then `KILL` 2 s later; the result says `timed_out: true` and the
  process exits 124.
- `--cwd DIR` sets the working directory for `CMD`, with `~` expanded by the
  server.

## Running a command

```
$ mysh --json --timeout 10s box 'echo hi; echo err >&2; exit 3'
{"stdout":"hi\n","stderr":"err\n","exit":3,"signal":null,"duration_ms":6,"timed_out":false}
$ echo $?
3
```

A non-zero exit is **data**, not an error: the document is printed and the
process exits with the remote status. Compare with a timeout:

```
$ mysh --json --timeout 1s box 'sleep 5'
{"stdout":"","stderr":"","exit":null,"signal":15,"duration_ms":1004,"timed_out":true}
$ echo $?
124
```

and with a failure to even start:

```
$ mysh --json box 'sleep 5' --timeout 1s
{"error":{"code":"not_found","message":"opening session: not found: sleep 5: command not found"}}
```

(That one is a reminder that `--timeout` is a connection option: put it
before `CMD`, or everything after `CMD` becomes its arguments.)

### Streaming

`--json-stream` gives you the output as it is produced instead of one
document at the end:

```
$ mysh --json-stream box 'echo a; echo b >&2'
{"event":"started","session":4,"pid":6301}
{"event":"stdout","data":"a\n"}
{"event":"stderr","data":"b\n"}
{"event":"exit","exit":0,"signal":null,"duration_ms":5,"timed_out":false}
```

| event | fields | when |
| --- | --- | --- |
| `started` | `session`, `pid` | the exec session is running |
| `stdout` / `stderr` | `data` | a chunk, in order |
| `exit` | `exit`, `signal`, `duration_ms`, `timed_out` | always the last event of an exec |
| `progress` | `label`, `done`, `total` | transfer progress (~10/s; the final state is always sent) |
| `notice` | `text` | what `[mysh] …` would have said |
| `error` | `code`, `message` | a command failed — on stdout in this mode, so one stream tells the whole story |
| `result` | `value` | the `--json` document of a command that has one |
| `host` | `host`, `data` | a fan-out: `data` is the event that host's own stream would carry |

### Scripted prompt commands

Pipe prompt commands in to get several documents from one connection. The
global `--json` applies to all of them — do not put `--json` after the
command name:

```
$ printf 'info\nping -c 2\ncwd\nsessions\njobs\nforward ls\n' | mysh --json box
```

The script stops at the first failing command and exits 1:

```
$ printf 'cat ~/nope\nping -c 1\n' | mysh --json box
{"error":{"code":"not_found","message":"get ~/nope: not found: No such file or directory (os error 2)"}}
$ echo $?
1
```

## Documents

Field names are `snake_case` and omitted optional fields are `null`. A
`bytes` value is a JSON string when the data is valid UTF-8 and
`{"base64": "…"}` otherwise — accept both.

| command | document |
| --- | --- |
| `mysh HOST CMD`, prompt `exec` | `{stdout, stderr, exit, signal, duration_ms, timed_out}` |
| `info` | `{server, connection, sessions, forwards}`; `server` is null on a server that does not answer |
| `sessions [-a]` | `{sessions: [...], server?: [...]}` — `server` only with `-a` |
| `jobs` / `jobs [-w] ID` | job rows / one row plus `output` |
| `ls [-l] [-a] [REMOTE]` | `[{name, kind, size, mode, mtime, target}]` |
| `stat REMOTE...` | one object, or an array for several paths |
| `cat`, `get ... -`, `tail` | `{data, bytes}` |
| `write`, `mkdir`, `rm`, `mv`, `kill`, `forward rm`, `log`, `resize`, `detach` | `{"ok": true}` |
| `realpath` | `{path, realpath}` |
| `hash REMOTE...` | one object, or an array |
| `sync --dry-run` / `sync` | `{copies, deletes, unchanged, bytes}` / `{copied, deleted, unchanged, bytes, duration_ms}` |
| `forward ls`, `forward -L/-R/-D` | `[{id, kind, bind, target, accepted}]` |
| `ping [-c N]` | `{rtts_ms, min, avg, max}` |
| `put`, `get` | `{files, skipped, bytes, duration_ms}` |
| `run` | `[{host, ok, exit, signal, stdout, stderr, duration_ms, error}]` |
| `put/get --hosts` | `[{host, ok, transfer, error}]` |
| `cwd` | `{remote, session, local}` |
| `authorize` | `{added}` |
| `pair` | `{host, server_fingerprint, client_fingerprint, authorized_line, host_line}` |
| `help [CMD]`, `mysh help --json` | the clap command tree with every argument and default |

A few of them, live:

```
$ mysh ping --json box
{"rtts_ms":[0.149083,0.296084],"min":0.149083,"avg":0.222583,"max":0.296084}
$ mysh --json box ls -l '~/tree'
[{"kind":"file","mode":"0644","mtime":"2026-11-03T10:38:46Z","name":"a.txt","size":4,"target":null},
 {"kind":"dir","mode":"0755","mtime":"2026-11-03T10:38:46Z","name":"sub","size":96,"target":null}]
$ mysh stat --json box '~/a.txt'
{"gid":0,"kind":"file","mode":"0644","mtime":"2026-11-03T10:38:46Z","path":"/tmp/home/a.txt","size":4,"target":null,"uid":501}
$ mysh authorize --json box
{"added":true}
$ mysh authorize --json box
{"added":false}
```

`info` is the one to call first from a script: its `server` block carries the
platform, shell, home, user and the limits — including `denied`, which tells
you which features this server has switched off.

```
$ printf 'info\n' | mysh --json box | jq '.server.limits'
{"max_sessions":32,"max_listeners":32,"max_streams":512,"detach_grace_secs":120,
 "idle_timeout_secs":120,"handshakes_per_minute":10,"denied":[]}
```

`lcd`, `exit` and `disconnect` print nothing, and anything needing the
terminal (`shell`, `fg`, `attach`) is refused in scripted mode.

## Errors and codes

One line on stderr, and the message is for humans — match on `code`, which
is stable:

```json
{"error": {"code": "trust_unknown", "message": "host key verification failed: …"}}
```

| code | meaning |
| --- | --- |
| `unauthorized` | the server refused every identity |
| `denied` | the feature is switched off by policy (`--deny`, key options) |
| `not_found` | no such path, session or forward |
| `unsupported` | the server does not implement that |
| `io` | server-side I/O failure, or the connection went away mid-command |
| `limit` | a per-connection quota (sessions, listeners, streams) |
| `protocol` | malformed or out-of-order message |
| `trust_unknown` | unknown server key and no way to ask |
| `trust_mismatch` | the key differs from `known_hosts`/`--pin` — never bypassable |
| `connect_failed` | DNS, TCP connect, or handshake timeout |
| `timeout` | `--timeout` expired on a transfer (an exec reports it in its result) |
| `usage` | bad command line, missing HOST, bad config |
| `internal` | anything else |

Exit codes: the remote status for `mysh HOST CMD`; 1 for a failing command;
2 for usage, trust, connection and authorization failures; 124 after a
timeout; 255 when the connection dropped.

## Masters

Every socket-less `mysh` call is a full handshake, and servers rate-limit
handshakes per source address (10 per minute by default). A burst of calls
starts failing with `connect_failed`. The fix is one long-lived connection
that short calls borrow.

```
$ mysh master box --daemon --idle 10m
```

`--daemon` re-spawns mysh detached — its own process group, no standard
streams — and returns 0 once the socket answers; an already-running master
counts. Without `--daemon` the master stays in the foreground, so background
it yourself (`mysh master box --idle 10m &`). `-M` on any command is the same
as `mysh master HOST`.

A master connects, serves a unix socket, and exits when `--idle` passes
without a request (default 10 m), on `SIGTERM`/`SIGINT`, or when the
connection ends. Its socket is removed on the way out.

```
$ ls "$XDG_RUNTIME_DIR/mysh/"
box_7722.sock
$ mysh stat --json box '~/a.txt'     # no handshake; runs inside the master
```

- The socket lives at `$XDG_RUNTIME_DIR/mysh/<host>_<port>.sock`, falling
  back to `$XDG_CACHE_HOME/mysh/` then `~/.cache/mysh/`. Directory `0700`,
  socket `0600`.
- An **interactive** client serves the same socket for its own host, so
  `mysh put box ...` from a second terminal reuses the connection you are
  sitting in. It prints `[mysh] ctl: put …` above its prompt when it does.
- Commands that travel over the socket: `put get cat write tail ls stat
  mkdir rm mv realpath hash sync cwd forward exec session info ping sessions
  kill jobs authorize help`, plus `mysh HOST CMD` itself. Anything needing
  the serving client's terminal (`shell`, `fg`, `attach`, `log`, …) is
  refused, as is `lcd` and a trailing `&`.
- Stdin travels with the request up to 64 KiB (`put -`, `write`, `session
  send --stdin`); a larger input falls back to a connection of the caller's
  own, and no bytes are lost in the switch.
- `--master auto` (or `[defaults] master = "auto"`, or per host) starts that
  daemon automatically for a socket-less call; `always` fails the call if a
  master cannot be used; `never` is the default. The daemon inherits the
  resolved port, identity, pin and trust policy, so it makes the decisions
  the call would have made — which means an unknown host key without
  `--accept-new` keeps a master from coming up, since nothing can answer a
  prompt.
- `--no-ctl` opts out on both sides: a call always makes its own connection,
  an interactive client never listens. Note that every process sharing your
  `$XDG_RUNTIME_DIR` uses the master's socket, and therefore the master's
  identity, whatever its own `-i` says; `--no-ctl` is how you force your own.

## Fleet

`mysh run` runs one command on several hosts; `put` and `get` take the same
host selection.

```
mysh run [-j N] (--hosts a,b | --group NAME)... [--json] [--timeout D] [--cwd D] -- CMD...
```

```
$ mysh run --hosts box,nas -- 'echo from $(hostname -s)'
box: from box
nas: from nas
host  exit  duration
box   0     10 ms
nas   0     8 ms
```

Output is attributed as it arrives: `host: line` for stdout on stdout,
`host! line` for stderr and notices on stderr, then a summary table.

- Selection: `--hosts` entries first (split on commas, repeatable), then each
  `--group NAME` from `[groups.NAME]` of the config file, in order.
  Duplicates are dropped, order is preserved. An unknown group or an empty
  selection is a usage error (exit 2) before anything runs.
- `-j N` (default 4) hosts run at a time. For transfers, 4 hosts run at a
  time and `-j` still means file streams per host.
- One host failing does not affect the others. `--timeout` and `--cwd` apply
  per host. The overall exit is 0 only if every host ran and exited 0.
- A host with a live control socket runs through it, so starting a master per
  host turns a fleet command into one handshake per host.

With `--json` you get one array in selection order and nothing else:

```
$ mysh run --json --hosts box,nas,10.255.255.1:1 --timeout 3s -- 'echo hi'
[{"host":"box","ok":true,"exit":0,"signal":null,"stdout":"hi\n","stderr":"","duration_ms":7,"error":null},
 {"host":"nas","ok":true,"exit":0,"signal":null,"stdout":"hi\n","stderr":"","duration_ms":6,"error":null},
 {"host":"10.255.255.1:1","ok":false,"exit":null,"signal":null,"stdout":"","stderr":"","duration_ms":5001,
  "error":{"code":"connect_failed","message":"10.255.255.1:1: connect timed out"}}]
```

`--json-stream` wraps each host's events and ends with the array:

```
{"event":"host","host":"box","data":{"event":"started","session":22,"pid":24351}}
{"event":"host","host":"box","data":{"event":"stdout","data":"s\n"}}
{"event":"host","host":"box","data":{"event":"exit","exit":0,"signal":null,"duration_ms":6,"timed_out":false}}
...
{"event":"result","value":[...]}
```

Transfers fan out the same way; see [files](files.md#several-hosts-at-once).
`--hosts` and `--group` are accepted by `run`, `put` and `get` only — passing
them elsewhere is a usage error.

## Long-running work

For anything that outlives a single call, use the session API rather than
holding a connection: `mysh session HOST new/send/read/kill/wait`, with
absolute byte offsets so reads are idempotent and a crashed reader resumes
exactly where it stopped. It is documented in
[sessions](sessions.md#the-session-api-for-programs).

## The agent skill

`skills/mysh/SKILL.md` in this repository is a ready-made skill file for
LLM agents: the three rules (always `--json`, always bound long operations,
reuse one master), a quick-reference table of command-to-shape, the polling
loop for `session read`, trust and first-contact handling, and a "don'ts"
list. Point an agent at it, or read it as a condensed version of this page.

For an MCP-native integration instead of a CLI one, see [mcp](mcp.md). The
full catalogue of flags is [cli-reference](cli-reference.md); the design
discussion is in [docs/05-meta-shell.md](../05-meta-shell.md) under "Agent
interface", "Master mode" and "Fleet".
