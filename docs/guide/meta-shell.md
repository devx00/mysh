# The meta shell

`mysh HOST` does not drop you into a remote shell. It connects and leaves you
at a prompt of its own:

```
$ mysh box
connected to box (SHA256:sgwa7AML0Ye0jV9qILMNjt6y5+OPZ+Uy52B1uk3yQvE, trusted via ~/.config/mysh/known_hosts:1); type "shell" for a shell, "help" for commands
mysh box>
```

That prompt is the **meta shell**. It runs locally, on the live connection,
and it is where every non-shell thing happens: copying files, adding port
forwards, starting and listing sessions, asking the server what it is. A
remote shell is one of the things you can ask it for, not the only thing the
connection is good for.

`-q` suppresses the connect banner.

## The meta key

`shell` gives you a real remote shell. While that shell is in the foreground,
the client forwards every byte you type to the remote verbatim — `Ctrl-C`,
`Ctrl-Z`, `Ctrl-D`, `~`, all of it — with exactly one exception: the **meta
key**, `Ctrl-]` by default.

Pressing it sends nothing to the remote. It moves the session to the
background and hands the terminal back to the prompt. Pressing it again at
the prompt is `fg`, so `Ctrl-]` toggles:

```
mysh box> shell
box$ tail -f /var/log/syslog
          <Ctrl-]>
mysh box> ls /etc
...
mysh box>  <Ctrl-]>
box$       (still tailing, output replayed)
```

There is no ssh-style `~` escape sequence, no "must be at the start of a
line", no second byte. It is a single-byte match.

| you want | do this |
| --- | --- |
| a different key | `-e '^^'`, `-e '^\'`, or any single character |
| no interception at all | `-e none` — then `exit`ing the remote shell is the only way back |
| the remote to see a literal `Ctrl-]` (vim tag jump) | `send '^]'` from the prompt, or rebind with `-e` |

`-e none` is the right choice when the remote end is a binary protocol that
may legitimately contain `0x1D`.

## Prompt commands

Every command takes `-h`; `help` lists them all. They run on the live
connection as new streams, so they never disturb a running session.

### Sessions

| command | what it does |
| --- | --- |
| `shell [--home] [CMD...]` | start a new PTY session and foreground it: the login shell, or `CMD` under a PTY (`shell htop`). Starts in the most recently used session's cwd unless `--home` |
| `fg [ID]` | foreground a session (default: most recently used), replaying its buffered output |
| `sessions [-a]` | list this connection's sessions; `-a` also asks the server for sessions detached from any connection of yours |
| `attach [ID]` | reattach a session detached on the server and foreground it |
| `detach [ID]` | leave a session running on the server and drop it from the stack |
| `kill [-s SIG] ID` | signal a session (default `TERM`). `kill %ID` cancels a background *job* instead |
| `send TEXT...` | write TEXT to the MRU session and foreground it; `^C`, `^]` and `\xNN` are decoded |
| `resize` | re-send the current terminal size to the MRU session |

See [sessions](sessions.md) for what detach, attach and the session API buy
you.

### Files

`put get ls cat write tail stat mkdir rm mv realpath hash sync cwd lcd` —
all documented in [files](files.md). Two prompt-specific notes:

- Relative remote paths resolve against the **most recently used session's
  working directory**. `cwd` tells you what that is:

  ```
  mysh box> cwd
  remote: /private/tmp (session 12)
  local:  /Users/me/src/app
  ```

  With no session open it says `remote: ~ (no session; server home)`.
- `lcd DIR` changes the *client's* directory, the one local path arguments
  and Tab completion use.
- `write` and `put -` read standard input, which the prompt owns, so they are
  available from the command line and over the control socket but not at the
  prompt itself.

### Forwards

`forward -L SPEC`, `-R SPEC`, `-D SPEC`, `forward ls`, `forward rm ID` —
same spec grammar as the command-line flags, added and removed while the
connection is up. See [forwarding](forwarding.md).

### Everything else

| command | what it does |
| --- | --- |
| `exec [--timeout D] [--cwd DIR] CMD...` | run a command without a PTY, stream its output here, print its exit code. The quick check that does not need a shell |
| `info` | connection facts (peer fingerprint, how it was trusted, cipher, bytes, RTT, sessions, forwards) then the server's own (version, platform, kernel, shell, home, user, limits, denied features) |
| `ping [-c N]` | control-stream round trips: `rtt min/avg/max = 0.26 ms/0.30 ms/0.34 ms` |
| `log FILE` / `log off` | tee everything written to the terminal — including session output and replays — to FILE, `script`-style |
| `authorize [PUBKEY_FILE]` | append your public key to the server's `authorized_keys`; `ssh-copy-id` without the ssh. Prints `added` or says it was already there |
| `jobs [-w] [ID]` | background jobs, below |
| `help [CMD]` | the command list, or one command's help |
| `exit` / `Ctrl-D` | close the connection — refused while a session is running |
| `disconnect` | close the connection now; PTY sessions stay on the server for its detach grace window |

`exec` in practice:

```
mysh box> exec uname -s
Darwin
[exit 0]
mysh box> exec --timeout 1s sleep 5
[mysh] timed out
[exit 124]
mysh box> exec --cwd /tmp pwd
/private/tmp
[exit 0]
```

## The session stack

One connection can carry several PTY sessions. The client keeps them in a
most-recently-used list and gives the terminal to at most one of them, the
foreground session; when none is foreground, the prompt is.

```
mysh box> sessions
  ID  PID    KIND            BUFFERED
* 1   4242   shell           -
  2   4310   exec: htop      12.3 KiB
```

- **Background sessions keep running.** Each has its own reader; a
  background session's output goes into a 1 MiB ring buffer (oldest bytes
  dropped, and you are told how many). The remote process is never stalled
  because you are looking elsewhere.
- **Switching** to a session replays that ring, then sends the current
  terminal size so full-screen programs redraw.
- Stdin and window-size changes go to the foreground session only.
- When a session exits you get `[mysh] session 16 exited: exit 0` and it
  leaves the list. If it was foreground, the prompt returns — the client
  never auto-switches to another session.
- `exit` refuses to close a connection with sessions on it, so a stray
  `Ctrl-D` cannot kill three shells:

  ```
  mysh box> exit
  error: exit: 1 session(s) still running:
    ID   PID     KIND             BUFFERED
  * 12   21376   shell            -
  use `fg` to return to one, or `disconnect` to end them
  ```

`mysh -s HOST` runs `shell` immediately — the ssh feel — and the client exits
when the last session ends, with that first shell's status. The prompt is
still there behind the meta key, and `shell` can still open more.

mysh is not a terminal multiplexer: it does not emulate the terminal, so
switching between two full-screen programs can leave the previous one's modes
(alternate screen, mouse reporting) in place. The redraw on switch covers the
common cases; `Ctrl-L` or `reset` covers the rest.

## Background jobs

A prompt line ending in a lone `&` runs as a job and returns the prompt at
once:

```
mysh box> exec sleep 1 &
[1] started
mysh box> jobs
  ID   STATE      ELAPSED   COMMAND
  1    running        0.1 s  exec sleep 1
mysh box> jobs -w 1
[mysh] job 1 done: exec sleep 1 (1.0 s)
[exit 0]
```

- Only `put`, `get`, `ls`, `exec` and `authorize` can be backgrounded; the
  rest need the terminal. `&` must be its own token — `put a&` is a file
  called `a&`.
- `jobs` lists id, state (`running` or a progress percentage, `done`,
  `exit N`, `failed`, `cancelled`), elapsed time and the command.
- `jobs ID` prints the job's state and its captured output (last 64 KiB,
  stdout and stderr interleaved); `jobs -w ID` waits first.
- `kill %ID` cancels a running job.
- Completion is announced above the prompt, followed by the captured output.

## Line editing

The terminal is in raw mode for the whole run, which is what makes the meta
key bindable at the prompt; the prompt's own small line editor does echo and
editing.

- Printable insert, Backspace/Delete, Left/Right, Home/End, `Ctrl-A`/`Ctrl-E`,
  `Ctrl-U`/`Ctrl-K`/`Ctrl-W`, Up/Down through history, `Ctrl-L` redraw.
- History lives in `~/.local/state/mysh/history`, last 1000 lines.
- `Ctrl-R` searches history backwards: the prompt becomes
  `(reverse-i-search)'query': match`, typing refines it, `Ctrl-R` again goes
  further back (`failed` when there is none), Enter runs the match, `Esc` or
  `Ctrl-G` restores the line you were editing.
- Tab completes the local path under the cursor for every argument of `put`,
  `lcd`, `log` and `authorize`, and for `get` arguments after the first (the
  local destination). One match completes it; several complete the common
  prefix and a second Tab lists them above the prompt. Dot files appear only
  when the name already starts with `.`.
- Quoting is POSIX-like: `put "my file.txt"` works. Local paths get `~`
  expansion on the client, remote paths on the server.
- `Ctrl-C` cancels the running command or clears the line; it never reaches a
  remote session from the prompt. `Ctrl-Z` suspends the client, and the
  prompt redraws on resume.
- Notices print above the prompt as they happen, prefixed `[mysh]`.

## Scripted stdin

Pipe prompt commands in and mysh runs them without a prompt or line editor,
one after another, stopping at the first failure:

```
$ printf 'info\nsessions -a\nforward ls\n' | mysh box
$ printf 'cat ~/nope\nping -c 1\n' | mysh box
error: get ~/nope: not found: No such file or directory (os error 2)
$ echo $?
1
```

`ping -c 1` never ran. Add `--json` and each command prints one JSON document
instead — that mode forces scripted behaviour even on a terminal. See
[automation](automation.md) for the document shapes, and
[getting-started](getting-started.md) if you have not connected yet.
