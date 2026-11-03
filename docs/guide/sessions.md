# Sessions

A **session** is one remote process with its streams. A connection can carry
several at once, and on a server that keeps them, a session can outlive the
connection that started it.

There are two kinds.

| | PTY session | exec session |
| --- | --- | --- |
| started by | `shell`, `mysh -s`, `mysh -t HOST CMD`, `session new --pty` | `exec`, `mysh HOST CMD`, `session new` |
| terminal | real pty: line editing, job control, `$TERM`, window size | pipes |
| streams | stdout and stderr merged by the pty | stdout and stderr kept apart |
| signals | arrive as control characters, as on a terminal | `kill -s SIG` |
| survives a lost connection | yes, for the server's grace window | no |

Use a PTY for anything interactive or anything that insists on a terminal.
Use an exec session for everything a program consumes, because the two
streams stay separate and nothing inserts `\r`.

## Persistence

The server keeps a PTY session whose client went away — connection lost,
`disconnect`, or an explicit `detach` — for `--detach-grace` seconds
(default 600; `0` turns persistence off). While detached it drains the
session's output into a 1 MiB ring so the process never blocks on a full
pty.

This is the `dtach` model, not a multiplexer: no screen state is kept. A
full-screen program redraws from the resize mysh sends right after
reattaching, or from your `Ctrl-L`.

Detached sessions belong to your **client key**: another key cannot list or
attach them. Session ids are server-wide, which is what makes `--attach=ID`
meaningful from a different connection.

### Detaching and reattaching

```
mysh box> detach
[mysh] session 12 detached; reattach with: mysh --attach=12 box
mysh box> sessions -a
no sessions
server:
  ID   PID     KIND             STATE               BUFFERED
  12   21376   shell            detached 0s ago     -
```

From anywhere, with the same key:

```
$ mysh --attach=12 box
```

`--attach` without an id picks the only detached session. With several it
prints them and exits 1:

```
$ mysh --attach box
error: 5 detached sessions; pass an id:
  ID   PID     KIND             STATE               BUFFERED
  8    18907   sleep 100        detached 1m10s ago  -
  ...
```

With none it says so and exits 1; against a server that keeps no sessions it
says that and exits 2. An attached session is the client's primary session:
the client auto-exits when it ends, with its status, exactly like `-s`.
Attaching replays what the session printed while you were gone — markers,
build output, anything — before handing you the live stream.

A session attached by one connection cannot be attached by another. Detach
it there first, or wait for that connection to go away.

If the process exits while detached, the entry stays listed until the window
closes, and attaching replays the ring and reports the exit.

### Surviving a killed client

The grace window is not only for deliberate detaches. If the client is
`SIGKILL`ed — terminal closed, laptop asleep, process reaped — the server
sees the stream end and detaches the session rather than hanging it up.
`mysh box --attach` relists it, replays the ring, and your typing goes back
where it was.

`disconnect` has the same effect on purpose: it closes the connection and
leaves PTY sessions attachable. `kill ID` is how you actually end one.

With `--detach-grace 0` the server closes the pty as soon as the stream ends
(ssh behaviour), `detach` is refused, and `session new` is refused too.

## The session API for programs

`mysh session` drives remote processes with no terminal anywhere in the
picture. Sessions are addressed by id, so one process can start something and
a completely different process can read it later.

```
mysh session HOST new [--cwd DIR] [--pty] [--env K=V] -- CMD...
mysh session HOST send ID [TEXT...] [--stdin] [--eof]
mysh session HOST read ID [--since N] [--wait D] [--max BYTES] [-f]
mysh session HOST list
mysh session HOST kill ID [-s SIG]
mysh session HOST wait ID [--timeout D]
```

Note the argument order: `HOST` comes before the subcommand.

### Starting and watching

```
$ mysh session box new -- cat
session 5 (pid 14294)
$ mysh session box --json new -- sh -c 'echo out; echo err >&2; sleep 1; echo done; exit 4'
{"id":6,"pid":14296}
```

A single-word command runs through the remote shell; several words are an
argv and are executed directly. The session is registered on the server and
outlives the connection that made it.

```
$ mysh session box --json read 6 --wait 3s
{"chunks":[{"data":"out\n","stream":"stdout"},{"data":"err\n","stream":"stderr"}],"exited":null,"next":8,"offset":0,"oldest":0}
```

Without `--pty`, stdout and stderr stay apart and every chunk says which it
is. With `--pty` they are merged by the terminal, as they would be on your
screen, and the session can be `attach`ed from the meta shell.

### Absolute offsets

`read` is addressed by **byte offset into everything the session has ever
printed**, never by "what is new":

| field | meaning |
| --- | --- |
| `--since N` | start here (default 0) |
| `offset` | where the reply actually starts — higher than `--since` if older bytes aged out of the 1 MiB ring |
| `next` | pass this as the next `--since` |
| `oldest` | the furthest back the server can still go |
| `exited` | `null` while running, else `{exit, signal}` |

Reads are therefore idempotent: the same `--since` returns the same bytes.

```
$ mysh session box --json read 7 --since 0
{"chunks":[{"data":"out\n","stream":"stdout"},{"data":"err\n","stream":"stderr"}],"exited":null,"next":8,"offset":0,"oldest":0}
$ mysh session box --json read 7 --since 4
{"chunks":[{"data":"err\n","stream":"stderr"}],"exited":null,"next":8,"offset":4,"oldest":0}
```

A reader that crashes resumes exactly where it stopped. If `oldest` has
passed your saved offset, you fell behind and lost bytes.

`--wait D` blocks up to `D` (the server caps it at 60 s) for new output and
returns at once when the process has already exited — that is how you poll
without burning CPU. `--follow` does the whole loop and prints until the
session exits:

```
$ mysh session box read 10 --follow
1
2
3
```

`--max BYTES` caps one reply (default and ceiling: 1 MiB).

### Feeding stdin

```
$ mysh session box send 5 hello world
$ mysh session box --json read 5 --wait 1s
{"chunks":[{"data":"hello world\n","stream":"stdout"}],"exited":null,"next":12,"offset":0,"oldest":0}
$ mysh session box send 5 --eof
$ mysh session box wait 5 --timeout 5s
session 5 exit 0
```

Words are joined with single spaces and a newline is appended; `^C` and
`\xNN` are decoded. `--stdin` sends this command's own standard input
verbatim instead, and `--eof` closes the session's stdin afterwards — how a
`cat` or a REPL ends. A `--pty` session ignores EOF, as a terminal does.

### Listing, signalling, waiting

```
$ mysh session box list
  ID      PID  STATE              NEXT  COMMAND
   5    14294  exit 0               12  cat
   8    18907  signal 15             0  sleep 100
  10    18925  exit 0                6  sh -c for i in 1 2 3; do echo $i; sleep 0.3; done
```

Exited sessions stay listed, with their status, until the grace window
passes.

`kill` defaults to `TERM`; `-s KILL`, `-s INT`, numbers all work. `wait`
blocks and exits with the session's own code:

```
$ mysh session box kill 8
$ mysh session box --json wait 8
{"exit":null,"id":8,"signal":15,"timed_out":false}
$ echo $?
143
```

With `--timeout` and no exit in time, `wait` prints `session 9 still running`
and exits 124 — the session is untouched.

### A worked loop

Start a build, stream it to a file, and exit with the build's status:

```sh
host=box
id=$(mysh session "$host" --json new -- make -j4 | jq .id)
off=0
while :; do
  r=$(mysh session "$host" --json read "$id" --since "$off" --wait 5s)
  jq -r '.chunks[] | select(.stream=="stdout") | .data' <<<"$r" | tr -d '\n'
  jq -r '.chunks[] | select(.stream=="stderr") | .data' <<<"$r" >&2
  off=$(jq .next <<<"$r")
  [ "$(jq '.exited != null' <<<"$r")" = true ] && break
done
mysh session "$host" wait "$id"
```

Nothing here keeps a connection or a local process alive between iterations:
kill the loop, restart it with the saved `$off`, and you pick up the same
byte. Start a [master](automation.md#masters) first so the iterations share
one handshake.

## Exit codes

| what happened | client exit |
| --- | --- |
| the primary session exited normally | its code |
| the primary session was killed by a signal | `128 + signal` |
| `exit` or `disconnect` at the prompt, `-N` stopped by a signal | 0 |
| a scripted prompt command failed | 1 |
| nothing (or several things) to `--attach` | 1 |
| usage, trust or authentication failure; server keeps no sessions to attach | 2 |
| `--timeout` expired | 124 |
| the connection was lost | 255 |

The *primary* session is the one the command line started: `CMD`, the first
`shell` under `-s`, or the attached session. Plain `mysh HOST` has none;
sessions opened from the prompt report their status there only.

Background on how the server builds a pty, resolves the shell and probes the
working directory is in [docs/04-sessions.md](../04-sessions.md); the wire
protocol for sessions and the remote process API is in
[docs/03-protocol.md](../03-protocol.md) §7, §10bis and §10ter.
