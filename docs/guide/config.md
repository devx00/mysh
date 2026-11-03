# Configuration

The client reads one optional file, `~/.config/mysh/config.toml`, for defaults and host aliases. The server has no config file: it is flags only ([server](server.md)). Both use the same directory for keys and trust files. This page is the reference for the file, the `HOST` argument, the environment variables mysh reads, and the file layout. Spec: [05-meta-shell.md "Config file"](../05-meta-shell.md#config-file-v1-minimal).

## `config.toml`

```toml
[defaults]
escape = "^]"          # meta key: a character, caret notation, or "none"
shell = false          # true: every `mysh HOST` behaves like `mysh -s HOST`
accept_new = false     # true: --accept-new everywhere (TOFU without asking)
master = "never"       # "auto" (or true) starts a background master for socket-less calls; "always" requires one

[hosts.box]
host = "box.lan"                       # any HOST form; default: the alias name itself
port = 7722
identity = "~/.ssh/id_ed25519"         # private key, or a .pub naming an ssh-agent key
pin = "SHA256:I1JTosiEZOcK6moI+X7CAIuAYfU0CaHliYezhlCYDwk"
forward = ["-L 8080:localhost:80", "-D 1080"]
env = ["LANG", "EDITOR=vim"]
shell = true                           # `mysh box` goes straight to a shell
escape = "^b"
master = "auto"

[hosts.nas]
host = "[fd00::5]:7722"

[groups.lab]
hosts = ["box", "nas", "10.0.0.7:7722"]   # for `mysh run --group lab`, `put/get --group lab`
```

Unknown keys are an error (`usage`, exit 2), so a typo never passes silently. Nothing else is supported: no `Match` blocks, no includes, no per-host `serve` settings.

### `[defaults]`

| key | type | flag equivalent | meaning |
| --- | --- | --- | --- |
| `escape` | string | `-e KEY` | the meta key that returns from a shell to the prompt. A single character, caret notation (`^]`, `^b`), a number (`0x1d`, `29`), or `none` to disable. Built-in `^]` |
| `shell` | bool | `-s` | open a shell on connect and exit when the last session ends |
| `accept_new` | bool | `--accept-new` | trust unknown server keys without asking |
| `master` | `"never"` / `"auto"` / `"always"` (or `true` = `"auto"`) | `--master MODE` | whether a CLI call that finds no control socket starts a background master first; see [automation](automation.md) |

### `[hosts.NAME]`

`NAME` is what you type: `mysh box`, `mysh put box …`, `box` inside a group. The prompt shows `mysh box>`, and `known_hosts` entries are keyed by the real `host:port`.

| key | type | flag equivalent | meaning |
| --- | --- | --- | --- |
| `host` | string | — | the real address, in any `HOST` form (`box.lan`, `box.lan:7722`, `[fd00::5]:7722`, `fd00::5`). Default: the alias name |
| `port` | integer | `-p` | port; `host` with an explicit port wins over this |
| `identity` | path | `-i` | identity for this host only; `~` is expanded |
| `pin` | string | `--pin` | required server key or fingerprint; `known_hosts` is not consulted |
| `forward` | array of strings | `-L`/`-R`/`-D` | forwards opened on every connection, each as `"-L spec"`, `"-R spec"` or `"-D spec"` (`"-Lspec"` also works) |
| `env` | array of strings | `--env` | `NAME` (send the local value) or `NAME=VALUE`; the server must `--accept-env` it |
| `shell` | bool | `-s` | per-host override of `[defaults] shell` |
| `escape` | string | `-e` | per-host meta key |
| `master` | string | `--master` | per-host master policy |

### `[groups.NAME]`

`hosts` is a list of aliases or `HOST` forms in fan-out order, used by `--group NAME` on `run`, `put` and `get`. `--group` repeats and mixes with `--hosts a,b`: the `--hosts` entries come first, then each group's, duplicates dropped. Groups list hosts, not other groups; an unknown group name is a `usage` error.

## Precedence

```
flags  >  [hosts.NAME]  >  [defaults]  >  built-ins
```

A flag on the command line always wins; an alias overrides `[defaults]`; `[defaults]` overrides the built-in values (`^]`, port 7722, prompt mode, TOFU asks, `master = "never"`). Repeatable options are additive: `-L` on the command line adds to the alias's `forward` list rather than replacing it.

The port specifically: `-p` > the port in `HOST` as typed (`mysh box:7723`) > the port inside the alias's `host` > the alias's `port` > 7722.

## `HOST` forms

| form | example |
| --- | --- |
| hostname or IPv4 | `box`, `192.0.2.7` |
| with port | `box:7723`, `192.0.2.7:7723` |
| IPv6 | `fd00::5` (bare), `[fd00::5]:7723` (with port) |
| config alias | `box` when `[hosts.box]` exists (the alias wins over DNS) |

Subcommand names (`serve`, `put`, `session`, …) cannot be used as a bare `HOST`; use `mysh connect NAME` for a host literally named like one.

## Environment variables

| variable | read by | meaning |
| --- | --- | --- |
| `MYSH_CONFIG_DIR` | both | the config directory, default `$XDG_CONFIG_HOME/mysh`, then `~/.config/mysh`. Every file below lives here |
| `MYSH_IDENTITY` | client | identity file; after `-i`, before the baked key and `~/.config/mysh/id` ([resolution order](keys-and-trust.md#resolution-order)) |
| `MYSH_HOST_KEY` | server | host key file; after `--key`, before the baked key and `~/.config/mysh/host_key` |
| `SSH_AUTH_SOCK` | client | the `ssh-agent` whose ed25519 keys are tried after the key files (empty = no agent) |
| `XDG_RUNTIME_DIR` | client | where control sockets go (`$XDG_RUNTIME_DIR/mysh/`), falling back to `$XDG_CACHE_HOME/mysh`, then `~/.cache/mysh` |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME` | both | the usual XDG bases for the config dir, prompt history and sockets |
| `HOME` | both | base for `~`; on the server also the sessions' home |
| `RUST_LOG` | both | a `tracing` filter that overrides `-v` entirely (`RUST_LOG=mysh_net=trace`) |
| `MYSH_BAKED_IDENTITY`, `MYSH_BAKED_PEERS` | `cargo build --features baked` | build-time inputs for [baked keys](keys-and-trust.md#baked-keys); not read at run time |

Empty values count as unset.

## File layout

Under the config directory (`~/.config/mysh` unless `MYSH_CONFIG_DIR`; created 0700):

| file | role | written by |
| --- | --- | --- |
| `id`, `id.pub` | client identity (private 0600, public line) | `mysh keygen` |
| `host_key` | server identity (private, 0600; the public line is not stored separately — `mysh fingerprint host_key` prints its fingerprint) | first `mysh serve` |
| `authorized_keys` | client keys the server trusts, one line each, optional [per-key options](keys-and-trust.md#per-key-options) | you, `mysh authorize`, pairing |
| `known_hosts` | server keys the client trusts: `host:port mysh-x25519 <b64>` lines | TOFU `yes`, `--accept-new`, pairing |
| `config.toml` | this page | you |

Elsewhere:

| path | role |
| --- | --- |
| `$XDG_STATE_HOME/mysh/history` (`~/.local/state/mysh/history`) | prompt line history |
| `$XDG_RUNTIME_DIR/mysh/` (else `~/.cache/mysh/`) | control sockets of interactive clients and masters, one per host |
| `~/.ssh/id_ed25519` | tried as a client identity after `id` |
| `~/.ssh/authorized_keys`, `~/.ssh/known_hosts` | read (ed25519 entries only) unless `--no-ssh-authorized-keys`; never written |

The server reads trust files on every connection, so editing `authorized_keys` needs no restart. The client reads `config.toml` once per invocation.
