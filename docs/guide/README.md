# mysh user guide

How to use mysh. The design specification (`docs/0N-*.md`) says *why* and
*exactly how* things work; these pages say *what to type*.

## Start here

1. [Getting started](getting-started.md) — install, make a key, start a
   server, connect.
2. [The meta shell](meta-shell.md) — the prompt you land on, the meta key,
   and every command that lives there.
3. [Keys and trust](keys-and-trust.md) — identities, reusing OpenSSH keys,
   `authorized_keys` options, pairing, baked keys.

## Doing things

| page | use it for |
| --- | --- |
| [Sessions](sessions.md) | shells and commands, reconnecting to them, driving them from a program |
| [Files](files.md) | `put`/`get`, `cat`/`write`/`tail`/`stat`/…, `sync` |
| [Forwarding](forwarding.md) | local, remote and SOCKS forwards |
| [Automation](automation.md) | `--json`, error codes, connection masters, running on many hosts |
| [MCP](mcp.md) | giving an AI agent the same tools over MCP |
| [Library](library.md) | embedding the client in a Rust program |
| [Connect-back](connect-back.md) | servers that dial the client (`serve --connect-back`, `mysh accept`, `@NAME`, bind on request) |

## Running a server

| page | use it for |
| --- | --- |
| [Server](server.md) | every `serve` option, the audit log, running as a service |
| [Config](config.md) | `config.toml`: aliases, groups, defaults, environment variables |
| [Platforms](platforms/README.md) | per-OS notes, which artifact to use, how each was validated, building from source |

## When something is wrong

- [Troubleshooting](troubleshooting.md) — error codes, the handshake rate
  limit, terminal recovery, logging.
- [CLI reference](cli-reference.md) — every command and flag, generated from
  the binary (`scripts/gen-cli-reference.py`).

## For agents

[`skills/mysh/SKILL.md`](../../skills/mysh/SKILL.md) is a self-contained
skill: the rules and command shapes an agent needs to drive a running server
from the command line.
