# Getting started

mysh is a small remote shell: one static binary that is both the client and the server, speaking an encrypted transport ([Noise XX](../02-security.md#primitives)) over a single TCP port. You get an interactive PTY shell, one-shot commands, file transfer, port forwarding and detachable sessions, authenticated by keys you already have (OpenSSH ed25519) or by keys it generates for you.

This page takes you from an empty machine to a working connection. The pages linked at the end cover each area in depth.

## Install

Release artifacts are single files named `mysh-<version>-<target>`, as produced by `scripts/release.sh` (for example `mysh-0.1.0-x86_64-unknown-linux-musl`, `mysh-0.1.0-aarch64-apple-darwin`, `mysh-0.1.0-universal-apple-darwin`, `mysh-0.1.0-aarch64-linux-android`; `dist/SHA256SUMS` lists them all). Pick the one for your platform, rename it and put it on your `PATH`:

```
install -m 755 mysh-0.1.0-x86_64-unknown-linux-musl /usr/local/bin/mysh
mysh --version
```

```
mysh 0.1.0
```

Or build from source (a Rust toolchain, no C dependencies):

```
cargo build --release -p mysh
install -m 755 target/release/mysh /usr/local/bin/mysh
```

The same binary goes on every machine, server and client alike. See [platforms](platforms/README.md) for the target list and per-OS notes.

## Make a client key

```
mysh keygen
```

```
Your identification has been saved in /home/you/.config/mysh/id
Your public key has been saved in /home/you/.config/mysh/id.pub
The key fingerprint is:
SHA256:6gIaFXtDcamPupzTf4VYouZGpo4JGabwg75BzbOFs/8
```

`id` is the private key (mode 0600), `id.pub` the one-line public key you hand to servers:

```
mysh-x25519 W9geInxPZucRR38hOpArX57ZarWPh7q3v0luV7VcyRM=
```

If you already have `~/.ssh/id_ed25519`, you can skip this step: mysh uses it when no mysh key exists, and `ssh-agent` keys work too. See [keys and trust](keys-and-trust.md).

## Start a server

On the machine you want to reach (call it `box`):

```
mysh serve --listen [::]:7722 --authorized-key "mysh-x25519 W9geInxPZucRR38hOpArX57ZarWPh7q3v0luV7VcyRM=" -v
```

```
INFO generated new host key path=/home/you/.config/mysh/host_key fingerprint=SHA256:I1JTosiEZOcK6moI+X7CAIuAYfU0CaHliYezhlCYDwk
INFO authorized client keys loaded keys=1
INFO listening addr=[::]:7722
INFO host identity fingerprint=SHA256:I1JTosiEZOcK6moI+X7CAIuAYfU0CaHliYezhlCYDwk source=/home/you/.config/mysh/host_key
```

- The host key is generated on the first start and kept in `~/.config/mysh/host_key`. Note the fingerprint: you will see it again on the client.
- `--authorized-key` is the quickest way to trust one client key. Persistently, put the line in `~/.config/mysh/authorized_keys` on the server; `~/.ssh/authorized_keys` is read too, so an `ssh-ed25519` key that already opens `sshd` on that machine opens mysh as well.
- The server refuses to start with no trusted keys at all, unless you open a pairing window (below).
- `--listen` defaults to `[::]:7722` (all interfaces, IPv4 and IPv6); drop it if that is what you want. Without `-v` the server logs only warnings.

The server runs as the user that started it and serves that user's shell and home. Running it under systemd, launchd or Termux is in [server](server.md).

## First connection

From the client:

```
mysh box true
```

```
The authenticity of host box:7722 can't be established.
Fingerprint SHA256:I1JTosiEZOcK6moI+X7CAIuAYfU0CaHliYezhlCYDwk
Are you sure you want to continue connecting (yes/no)? yes
Warning: permanently added box:7722 (SHA256:I1JTosiEZOcK6moI+X7CAIuAYfU0CaHliYezhlCYDwk) to /home/you/.config/mysh/known_hosts.
```

This is trust-on-first-use: compare the fingerprint with the one the server printed, answer `yes`, and the key is recorded in `~/.config/mysh/known_hosts`. Later connections are silent; a *different* key for the same host is a hard error with no bypass flag (see [keys and trust](keys-and-trust.md#when-the-key-changes)).

Two ways to skip the question:

| flag | effect |
| --- | --- |
| `--accept-new` | answer `yes` silently (scripts, first deploys you are sure about) |
| `--pin SHA256:…` | require exactly this fingerprint (or public key); nothing is asked or written |
| `--strict` | fail with `trust_unknown` instead of asking |

Without a terminal (stdin is a pipe) the client cannot ask and fails the same way `--strict` does:

```
mysh: error: host key verification failed: box:7722 is not in known_hosts (key SHA256:I1JT…); use --accept-new or add it to /home/you/.config/mysh/known_hosts
```

## Three ways to use a connection

```
mysh box                  # land at the meta prompt
mysh -s box               # straight into a shell, like ssh
mysh box uname -a         # run one command, exit with its status
```

`mysh box` prints a banner and a prompt:

```
connected to box:7722 (SHA256:I1JT…, trusted via /home/you/.config/mysh/known_hosts:1); type "shell" for a shell, "help" for commands
mysh box>
```

The prompt is the *meta shell*: `shell` opens an interactive PTY shell, `put`/`get` move files, `forward` opens tunnels, `sessions` lists what is open, `exit` leaves. Inside a shell, `Ctrl-]` returns to the prompt without closing the shell. See [the meta shell](meta-shell.md).

`mysh -s box` runs `shell` immediately and exits when that shell exits, with its status. The prompt is still there behind `Ctrl-]`.

`mysh box CMD...` runs the command without a PTY, pipes stdin/stdout/stderr, and exits with its status. A single argument goes through the remote shell (`mysh box 'ls | wc -l'`); `-t` forces a PTY for full-screen programs; `--timeout 30s` kills it after 30 s and exits 124.

## Authorize more keys

`mysh authorize` is the `ssh-copy-id` equivalent: once *one* identity is trusted, use it to install another.

```
mysh authorize box ~/laptop.pub
```

```
added
```

It appends the line to `~/.config/mysh/authorized_keys` on the server (creating the directory 0700 and the file 0600) and is idempotent: the same key is never added twice. Without a file argument it installs the identity you are currently using, which is useful right after a pairing or a `--authorized-key` bootstrap.

`authorize` works over the file-transfer channel, so it is refused on a server started with `--deny files`.

## Pairing: no copy-paste

When neither side has the other's key yet, a one-time code replaces the key exchange. On the server:

```
mysh serve --pair
```

```
WARN no authorized client keys yet; only pairing will be accepted
pairing code: visual-portion-maid-desert-razor-claim (valid 5m, single use)
```

On the client, type the code (hyphens or spaces, any case):

```
mysh pair box visual portion maid desert razor claim
```

```
paired with box:7722
  server SHA256:31fWNKnvBkj808E26+S5UW7KoKhYIHAPS2kif6f/7Iw
  client SHA256:6gIaFXtDcamPupzTf4VYouZGpo4JGabwg75BzbOFs/8
  installed on the server: mysh-x25519 W9ge… paired 2026-11-03T10:39:47Z
  installed in /home/you/.config/mysh/known_hosts: box:7722 mysh-x25519 Pphf…
```

Both sides now trust each other; `mysh box` connects without a question. The code is single use: a wrong guess closes the window (`server did not know the code (bad code)`), and a later attempt is told `server has no pairing window open`. Send the running server `SIGUSR1` to print a fresh code. Details: [keys and trust](keys-and-trust.md#pairing).

## Next steps

- [Meta shell](meta-shell.md), [sessions](sessions.md), [files](files.md), [forwarding](forwarding.md): the prompt, shells and detached sessions, file transfer, tunnels.
- [Automation](automation.md): `--json`, the `session` command family, master mode, fan-out; [MCP](mcp.md) for agents.
- [Keys and trust](keys-and-trust.md): identities, `authorized_keys` options, `known_hosts`, pins, baked keys.
- [Server](server.md): every `serve` option, the session environment, the audit log, running as a service.
- [Config](config.md): `config.toml` aliases and defaults, environment variables, file layout.
- [Troubleshooting](troubleshooting.md): error codes and what to do about them.
- [CLI reference](cli-reference.md): every flag.
