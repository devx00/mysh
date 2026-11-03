# NetBSD and OpenBSD

Both are **stretch** targets: built only by `scripts/release.sh --stretch`,
never executed, and the least-exercised code in the tree. Use them with
that expectation.

## Artifacts

| OS | arch | artifact | Rust tier | built against | validation |
| --- | --- | --- | --- | --- | --- |
| NetBSD | amd64 | `mysh-<v>-x86_64-unknown-netbsd` | 2 | NetBSD 10.1 libc | link only |
| NetBSD | arm64 | `mysh-<v>-aarch64-unknown-netbsd` | 3 (nightly, `build-std`) | NetBSD 10.1 libc | link only |
| OpenBSD | amd64 | `mysh-<v>-x86_64-unknown-openbsd` | 3 | OpenBSD 7.8 libc | link only |
| OpenBSD | arm64 | `mysh-<v>-aarch64-unknown-openbsd` | 3 | OpenBSD 7.8 libc | link only |

All four are position-independent ELF executables linked dynamically
against the base libc (`/libexec/ld.elf_so` on NetBSD, `/usr/libexec/ld.so`
on OpenBSD) through zig's libc stubs for those releases. That has two
consequences:

- **NetBSD**: binaries built against the 10.1 stubs run on 10.1 and, by
  NetBSD's compatibility policy, later releases.
- **OpenBSD**: binaries are bound to the release they were built for
  (OpenBSD does not keep a stable libc ABI across releases). The shipped
  artifacts are for **OpenBSD 7.8**; rebuild for another release.

"Link only" means `file`/`readelf` show the right arch, ABI and interpreter
and nothing else was checked. There is no NetBSD or OpenBSD host or
emulator in the release environment, so the pty fallbacks and the cwd
probes below compile but have never run
([docs/08](../../08-platform-matrix.md#runtime-notes-per-family)).

## Install

```sh
install -m 755 mysh-0.1.0-x86_64-unknown-netbsd /usr/local/bin/mysh   # NetBSD
install -m 755 mysh-0.1.0-x86_64-unknown-openbsd /usr/local/bin/mysh  # OpenBSD
mysh --version
```

No service script is shipped for either system. The server is an ordinary
unprivileged process; on OpenBSD the usual route is an `rc.d(8)` script
with `daemon="/usr/local/bin/mysh"` and `daemon_flags="serve"`, on NetBSD
an `rc.d` script modelled on `/etc/rc.d/sshd`. Neither has been written or
tested here.

## Platform behaviour

| | NetBSD | OpenBSD |
| --- | --- | --- |
| shell | `--shell` → `$SHELL` → passwd → `/bin/sh` | same |
| home | `$HOME` → passwd → `/` | same |
| default `PATH` | `/usr/pkg/bin:/usr/local/bin:/usr/bin:/bin:/usr/pkg/sbin:/usr/sbin:/sbin` | `/usr/local/bin:/usr/bin:/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/sbin:/sbin` |
| pty slave name | `ptsname_r` | `ptsname` (OpenBSD has no `ptsname_r`) |
| cwd tracking | **unsupported** — the meta prompt shows the server home after `cd` | `sysctl kern.proc_cwd.<pid>` (compiled, not run) |
| config dir | `~/.config/mysh` | `~/.config/mysh` |

The default `PATH` applies only when the server's own `PATH` is unset; a
server started from a login shell passes that shell's `PATH` on.

NetBSD's cwd probe is unsupported because the `libc` crate does not expose
the `KERN_PROC_CWD` sub-op of `kern.proc_args`; the meta shell's directory
tracking degrades to "home", everything else (sessions, files, forwards)
is unaffected. See [docs/04 "Cwd probe"](../../04-sessions.md#cwd-probe).

## Related

[FreeBSD](freebsd.md) (required set), [building](building.md) — these
targets need zig, and the tier-3 ones nightly Rust with `rust-src`.
