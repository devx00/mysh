# mysh as an MCP server

`mysh mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio, so any MCP client (Claude Desktop, Claude Code, an IDE agent, your
own program) can run commands, read and write files and drive long-running
processes on the hosts you name. `docs/07-embedding.md` describes the tools,
their schemas and the trust rules; this directory only holds an example client
configuration. Nothing here is installed for you — copy what you need.

## Example: Claude Desktop

`claude_desktop.json` is the shape of a `claude_desktop_config.json` entry:

```json
{
  "mcpServers": {
    "mysh": {
      "command": "mysh",
      "args": ["mcp", "--hosts", "pi,nas", "--group", "lab", "--allow-local-paths"],
      "env": { "MYSH_CONFIG_DIR": "/home/me/.config/mysh" }
    }
  }
}
```

Merge the `mysh` entry into your own config file (the location depends on the
client; Claude Desktop keeps it under its application-support directory and
has a "Developer → Edit Config" menu item that opens it). Use an absolute
`command` path if `mysh` is not on the client's `PATH`, and drop `env` unless
your config lives somewhere other than `~/.config/mysh`.

For Claude Code the equivalent is one command:

```sh
claude mcp add mysh -- mysh mcp --hosts pi,nas --allow-local-paths
```

## Flags

| flag                  | meaning                                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| `--hosts a,b`         | hosts the tools may reach: aliases from `config.toml` or `host[:port]`; repeatable, comma-separated        |
| `--group NAME`        | every host of `[groups.NAME]`; repeatable, mixes with `--hosts`                                             |
| `--accept-new`        | trust an unknown server key on first use and pin it. Without it an unknown host fails with `trust_unknown` |
| `-i PATH`             | identity file (or a `.pub` naming an agent key), as for every other command                                |
| `--allow-local-paths` | let the `put`/`get` tools read and write files on *this* machine; off by default (they fail with `denied`) |

## Trust

The MCP transport is stdin/stdout, so `mysh mcp` never asks a question. Pin
each host's key before pointing an agent at it — `mysh HOST` interactively
once, `mysh pair HOST CODE`, or a `[hosts.NAME] pin = "..."` entry — or pass
`--accept-new` and accept the usual first-use risk. A key that *changes* is
always a hard failure (`trust_mismatch`), flag or no flag.

The server side is unchanged: whatever `authorized_keys` options and `--deny`
flags apply to the client's key apply to every tool call.
