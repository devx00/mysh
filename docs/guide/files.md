# Files

Every file operation is a command of its own. You never need a remote shell,
a heredoc, or `base64` quoting games to move bytes around: `mysh cat`,
`mysh write`, `mysh put`, `mysh sync` talk to the server's file streams
directly. Each exists in three forms — a command line (`mysh cat box FILE`),
a meta-shell command (`cat FILE`), and over the
[control socket](automation.md#masters) — with the same flags.

## Where relative paths land

| context | a relative remote path resolves against |
| --- | --- |
| at the prompt, with a session open | that session's working directory |
| at the prompt, with no session | the server home |
| command line, control socket | the server home |

`cwd` at the prompt tells you which:

```
mysh box> cwd
remote: /private/tmp (session 12)
local:  /Users/me/src/app
```

so `mysh box> ls` lists `/private/tmp` after you `cd /tmp` in a shell
session. Local paths use the client's directory, which `lcd` changes.
`~` is expanded by the server for remote paths and by the client for local
ones.

## put and get

```
mysh put [OPTIONS] HOST LOCAL... [REMOTE]
mysh get [OPTIONS] HOST REMOTE... [LOCAL]
```

```
$ mysh put box ./report.pdf '~/reports/'
1 file, 4 B, 0.0 s
$ mysh get box '~/reports/report.pdf' .
```

With one source and no destination, `put` defaults to the most recently used
session's cwd then `~`, and `get` defaults to the client's current
directory. With several sources the destination must be a directory.

| flag | `put` | `get` | meaning |
| --- | --- | --- | --- |
| `-r, --recursive` | yes | yes | copy directories |
| `-c, --continue` | yes | yes | resume a partial file |
| `-P, --preserve` | yes | yes | keep modification times and modes |
| `-F, --follow-symlinks` | yes | — | follow links instead of copying them as links |
| `-j, --jobs N` | yes | yes | file streams at a time under `-r` (default 4) |
| `--checksum` | yes | yes | skip files whose size and BLAKE2s digest already match |
| `--mode MODE` | `put - REMOTE` only | — | mode of the file written from stdin (octal, default 0644) |
| `--mtime SECS` | `put - REMOTE` only | — | mtime of the file written from stdin |

`-P` and `-F` are capitals because `-p` is the shared port option and `-L` is
a local forward.

### Streaming through stdin and stdout

`-` is the stream:

```
$ echo via-stdin | mysh put --mode 0600 box - '~/stdin.txt'
1 file, 10 B, 0.0 s
$ mysh stat box '~/stdin.txt'
-rw-------         10 2026-11-03 10:40 file /tmp/home/stdin.txt
$ mysh get box '~/a.txt' -
one
```

`put - REMOTE` needs an explicit REMOTE naming a file. `get REMOTE... -`
prints the files in order and is exactly what `mysh cat` does.

### Resuming and skipping

`-c` stats the other side first; if the destination is a shorter regular
file, the transfer starts at that offset instead of from zero. `--checksum`
stats, then hashes both sides with BLAKE2s when the sizes match, and skips
identical files:

```
$ mysh put --json --checksum box report.pdf '~/report.pdf'
[mysh] /tmp/home/report.pdf: unchanged (checksum), skipped
{"bytes":0,"duration_ms":0,"files":0,"skipped":1}
```

The summary always separates `files` (actually moved) from `skipped`.

### Recursive transfers

`-r` walks the tree first — directories created in order, then up to `-j`
file streams at once — and applies directory attributes at the end under
`-P`. Progress collapses to one aggregate line. The first failing file
aborts the rest and the command reports that error; files already finished
stay, and because `put` writes through a temporary file and renames, a
partial file is never visible under its real name.

Symlinks are skipped with a notice unless `put -F` follows them.

### Several hosts at once

`put` and `get` take `--hosts a,b` and `--group NAME`, in which case the
first path argument takes the place of `HOST`:

```
$ mysh put --hosts box,nas ./a.txt '~/fleet.txt'
box: 1 file, 4 B, 0.0 s
nas: 1 file, 4 B, 0.0 s
$ mysh get --hosts box,nas '~/fleet.txt' ./out
$ find ./out
./out/box/fleet.txt
./out/nas/fleet.txt
```

`get` fans out into one subdirectory per host. See
[automation](automation.md#fleet) for the rest of fan-out.

## The file primitives

| command | what it does |
| --- | --- |
| `cat REMOTE...` | print remote files to stdout, in order |
| `write [--mode M] [--append] REMOTE` | stdin into a remote file |
| `tail [-n N] [-f] [--for D] REMOTE` | the last N lines (default 10), optionally following |
| `stat REMOTE...` | mode, size, mtime, kind, owner, symlink target |
| `mkdir [-P] [-m MODE] REMOTE...` | create directories (default 0755) |
| `rm [-r] REMOTE...` | remove files, or trees with `-r` |
| `mv FROM TO` | rename (replacing TO) |
| `realpath REMOTE` | resolve `~`, `..` and symlinks |
| `hash REMOTE...` | BLAKE2s-256 of regular files |

```
$ printf 'l1\nl2\nl3\n' | mysh write box '~/w.txt'
/tmp/home/w.txt: 9 bytes written
$ printf 'l4\n' | mysh write --append box '~/w.txt'
/tmp/home/w.txt: 3 bytes written
$ mysh tail -n 2 box '~/w.txt'
l3
l4
$ mysh hash box '~/w.txt'
blake2s256  94fde0e9055e374abdc185924c5eab14c3e2c943665b6e05e8125614cb7f9ca4  12  /tmp/home/w.txt
$ mysh realpath box '~/tree/../a.txt'
/private/tmp/home/a.txt
```

- **`write` is atomic**: it writes a temporary file and renames it, so a
  reader sees either the old file or the new one, never a half-written one.
  `--append` is the exception — it stats the file and writes past the end,
  keeping the file's own mode unless you pass `--mode`.
- `mkdir -P` creates missing parents and does not complain when the
  directory already exists (`-P` not `-p`, which is the port option).
- `tail -f` keeps printing as the file grows until `Ctrl-C`, `--for D`, or
  the connection's `--timeout`; all three exit 0.
- `stat` and `hash` take several paths; with `--json` one path gives an
  object and several give an array.
- A missing path is an error with code `not_found` and exit 1:

  ```
  $ mysh stat box '~/d1'
  error: stat /tmp/home/d1: not found
  ```

## sync

```
mysh sync [--pull] [--delete] [--dry-run] [--checksum] [-j N] HOST SRC DST
```

`sync` mirrors one tree into another. Exactly one side is remote, and the
command form says which: `sync HOST LOCAL REMOTE` pushes, `sync --pull HOST
REMOTE LOCAL` pulls. There is no `HOST:` prefix on a path — the connection
already names the host.

It plans first, then executes.

```
$ mysh sync --dry-run box ./tree '~/tree'
copy    c.txt  (missing, 6 B)
1 to copy (6 B), 0 to delete, 2 unchanged
$ mysh sync box ./tree '~/tree'
1 copied, 2 unchanged, 0 deleted, 6 B, 0.0 s
```

A source file is copied when the destination:

| reason | test |
| --- | --- |
| `missing` | the destination has no such file |
| `size` | the sizes differ |
| `mtime` | the modification times differ by more than 1 s |
| `content` | with `--checksum`, same-size files whose BLAKE2s digests differ |

`--checksum` replaces the mtime test for same-size files — use it when
timestamps are unreliable, and accept that both sides get read.

"Unchanged" means a file that passed those tests, so it was not transferred
and not counted in `bytes`. Because `sync` preserves mtime and mode on
everything it copies, the second run of the same `sync` reports everything
unchanged:

```
$ mysh sync --json box ./tree '~/tree'
{"bytes":0,"copied":0,"deleted":0,"duration_ms":1,"unchanged":3}
```

`--dry-run` prints the plan and changes nothing; with `--json` it is a
`SyncPlan`:

```
$ mysh sync --dry-run --json box ./tree '~/tree'
{"bytes":6,"copies":[{"path":"c.txt","reason":"missing","size":6}],"deletes":[],"unchanged":2}
```

`--delete` removes what the source does not have — files first, then
directories deepest first. Always look at `--dry-run --delete` before
running it:

```
$ mysh sync --delete --dry-run box ./tree '~/tree'
delete  c.txt
0 to copy (0 B), 1 to delete, 2 unchanged
$ mysh sync --delete box ./tree '~/tree'
0 copied, 2 unchanged, 1 deleted, 0 B, 0.0 s
```

`--pull` reverses the direction with everything else unchanged:

```
$ mysh sync --pull box '~/tree' ./local-copy
2 copied, 0 unchanged, 0 deleted, 8 B, 0.0 s
```

Symlinks and special files are skipped on the source with a notice and count
as extras on the destination. `-j N` (default 4) sets how many files move at
once.

## Progress and output

When stderr is a terminal, `put`/`get`/`sync` draw a progress line — per
file, or one aggregate line for a tree. With `--plain`, in a JSON mode, or
when stdout is not a terminal, progress is suppressed, and `--json-stream`
reports it as `progress` events instead. `cat` and `get ... -` never draw
progress, because stdout is the file body.

Every one of these commands has a `--json` document; they are listed in
[automation](automation.md#documents). The design details — wire messages,
offsets, the parallel walk — are in
[docs/04-sessions.md](../04-sessions.md) under "File transfer" and "File
primitives".
