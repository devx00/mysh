# mysh

A small, encrypted remote shell. One static binary is both client and
server; it runs on Linux, macOS, Android, FreeBSD and more, and it is built
to be driven by people at a terminal and by programs alike.

```sh
mysh keygen                              # your identity
mysh serve --authorized-key "$(cat ~/.config/mysh/id.pub)"   # on the host
mysh -s box                              # a shell, like ssh
mysh box 'uptime'                        # one command, its exit status
mysh --json box 'df -h /'                # the same, as a JSON document
```

## Why

- **Noise, not SSH.** `Noise_XX_25519_ChaChaPoly_BLAKE2s`, mutual
  authentication, one round trip. No algorithm negotiation, no agent
  forwarding, no X11. Your existing OpenSSH ed25519 keys, `authorized_keys`
  and `known_hosts` are reused as they are; or bake keys into the binary
  for hosts that never get configured by hand.
- **A meta shell between you and the remote.** Every connection lands at a
  prompt that owns the connection: `shell` opens a real PTY shell, `Ctrl-]`
  comes back without dropping it, and `put`, `get`, `forward`, `tail -f`,
  `sessions` and the rest live there — or as plain CLI subcommands that
  reuse a running client's connection.
- **Sessions outlive connections.** Lose the network; `mysh --attach host`
  picks the shell back up with the output you missed.
- **Either side can dial.** A server with no inbound port runs
  `serve --connect-back`; `mysh accept` on the client takes the calls, and
  every command then addresses it as `@name`. Same handshake, same trust.
- **Made for automation.** `--json` and `--json-stream` on every command,
  stable error codes, a session API that reads output by byte offset, file
  primitives that need no shell quoting, `run --hosts` fan-out, an MCP
  server (`mysh mcp`), a Rust library (`mysh-client`), and an agent skill.
- **Portable.** One release script produces static Linux binaries for
  seven architectures, a macOS universal binary, Android, and the BSDs.

## Install

Download the artifact for your platform (`mysh-<version>-<target>`), make
it executable, put it on your `PATH`. Or build it:

```sh
cargo build --release        # target/release/mysh for the host
scripts/release.sh           # every supported target into dist/
cargo xtask install          # client -> ~/.local/bin, dist/ -> ~/.local/share/mysh, agent skill
```

Platform notes, service units and what is validated where: [docs/guide/platforms/](docs/guide/platforms/README.md).

## First connection

```sh
# host: a host key is generated on first start; trust your client key
mysh serve --listen 0.0.0.0:7722 --authorized-key "$(cat ~/.config/mysh/id.pub)"

# client
mysh keygen                  # ~/.config/mysh/id, id.pub
mysh box.lan                 # meta prompt; `shell` for a shell, Ctrl-] to come back
mysh -s box.lan              # straight to a shell
mysh box.lan 'uptime'        # one command
mysh put box.lan ./file '~'  # transfer
mysh forward box.lan -L 8080:localhost:80
```

The first connection asks you to confirm the host key (or use `--accept-new`
/ `--pin`); after that it is pinned in `known_hosts`. To get your key onto a
host without copy-paste, run `mysh serve --pair` there and `mysh pair HOST
CODE` here. Details: [getting started](docs/guide/getting-started.md),
[keys and trust](docs/guide/keys-and-trust.md).

## Documentation

**User guide** — [docs/guide/](docs/guide/README.md)

| page | what it covers |
| --- | --- |
| [getting-started](docs/guide/getting-started.md) | install, keys, first server, first connection |
| [meta-shell](docs/guide/meta-shell.md) | the prompt, the meta key, every prompt command, jobs |
| [sessions](docs/guide/sessions.md) | PTY and exec sessions, persistence, the offset-based session API |
| [files](docs/guide/files.md) | put/get, file primitives, `sync` |
| [forwarding](docs/guide/forwarding.md) | `-L`, `-R`, `-D`, forward policy |
| [automation](docs/guide/automation.md) | `--json`, error codes, masters, fleet fan-out |
| [mcp](docs/guide/mcp.md) | the MCP server for AI agents |
| [library](docs/guide/library.md) | embedding the `mysh-client` crate |
| [connect-back](docs/guide/connect-back.md) | servers with no inbound port: `serve --connect-back`, `mysh accept`, `@NAME` |
| [keys-and-trust](docs/guide/keys-and-trust.md) | identities, ssh key reuse, `authorized_keys` options, pairing, baked keys |
| [server](docs/guide/server.md) | every `serve` option, audit log, running as a service |
| [config](docs/guide/config.md) | `config.toml`, host aliases, groups, environment variables |
| [platforms](docs/guide/platforms/README.md) | per-OS notes, artifacts, validation status, building |
| [troubleshooting](docs/guide/troubleshooting.md) | error codes and what to do about them |
| [cli-reference](docs/guide/cli-reference.md) | every command and flag (generated from the binary) |

**Agent skill** — [skills/mysh/SKILL.md](skills/mysh/SKILL.md): how a
program or AI agent drives a running server from the CLI.

**Design** — `docs/0N-*.md` is the specification the code is written
against: [architecture](docs/01-architecture.md),
[security](docs/02-security.md), [protocol](docs/03-protocol.md),
[sessions and PTY](docs/04-sessions.md), [meta shell and CLI](docs/05-meta-shell.md),
[roadmap and decisions log](docs/06-roadmap.md),
[embedding](docs/07-embedding.md), [platform matrix](docs/08-platform-matrix.md).

## Status

Milestones M1–M12 of the [roadmap](docs/06-roadmap.md) are implemented:
transport, sessions, meta shell, files, forwards, persistence, pairing,
the automation interface, the library and MCP server, the build matrix, and
connect-back. 466 tests run natively on macOS and Linux; every Linux artifact is
exercised under emulation. Not yet: a stable wire protocol (`VERSION 1` is
still allowed to change), signed macOS builds, Windows (out of scope).

## Development

```sh
cargo lint                   # clippy, -D warnings
cargo test --workspace       # unit + integration (loopback servers, real ptys)
cargo check-matrix           # type-check the required targets
scripts/release.sh --stretch # all 25 targets + universal, SHA256SUMS in dist/
scripts/validate-dist.sh     # run every Linux artifact under qemu-user
scripts/lima-test.sh         # the suite on Linux in a lima VM
scripts/fuzz-all.sh 60       # every fuzz target for 60 s
```

[docs/guide/platforms/building.md](docs/guide/platforms/building.md) has
the toolchain requirements. Contributions follow the decisions log: a
change that deviates from a `docs/0N` file updates that file and adds a
row to `docs/06-roadmap.md`.

## License

MIT or Apache-2.0, at your option.
