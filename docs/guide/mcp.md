# MCP server

`mysh mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio, so an MCP client — Claude Desktop, Claude Code, an IDE agent,
your own program — can run commands, read and write files and drive
long-running processes on hosts you name, without shelling out to `mysh`
itself.

```
mysh mcp (--hosts a,b | --group NAME)... [--accept-new] [-i PATH] [--allow-local-paths]
```

It reads JSON-RPC 2.0 from stdin and writes one JSON document per line to
stdout (a `Content-Length:`-framed message is accepted and answered with the
same framing). Logs go to stderr. It exits 0 when stdin closes.

## Starting it

| flag | meaning |
| --- | --- |
| `--hosts a,b` | hosts the tools may reach: aliases from `config.toml` or `host[:port]`; comma-separated, repeatable |
| `--group NAME` | every host of `[groups.NAME]`; repeatable, mixes with `--hosts` |
| `--accept-new` | trust an unknown server key on first use and pin it; without it an unknown host fails with `trust_unknown` |
| `-i, --identity PATH` | identity file, or a `.pub` naming an ssh-agent key |
| `--allow-local-paths` | let the `put` and `get` tools read and write files on *this* machine; off by default |

Host selection works exactly as it does for `mysh run`: duplicates dropped,
order kept. Every tool takes a `host` argument naming one of them — except
when you configured a single host, in which case `host` is optional and the
schemas say so. Connections open lazily on first use, stay up between calls,
and are reopened after a loss. A host that cannot be reached fails that call
with `connect_failed` and leaves the others alone.

### Client configuration

`contrib/mcp/` holds a ready example. `contrib/mcp/claude_desktop.json` is
the shape of a `claude_desktop_config.json` entry:

```json
{
  "mcpServers": {
    "mysh": {
      "command": "mysh",
      "args": ["mcp", "--hosts", "box,nas", "--group", "lab", "--allow-local-paths"],
      "env": { "MYSH_CONFIG_DIR": "/home/me/.config/mysh" }
    }
  }
}
```

Merge the `mysh` entry into your own config file; use an absolute `command`
path if `mysh` is not on the client's `PATH`, and drop `env` unless your
config lives somewhere other than `~/.config/mysh`. For Claude Code it is
one command:

```sh
claude mcp add mysh -- mysh mcp --hosts box,nas --allow-local-paths
```

`contrib/mcp/README.md` has the same material from the client's side.

## Tools

| tool | what it does |
| --- | --- |
| `exec` | run a command to completion and return stdout, stderr and the exit status |
| `read_file` | read a remote file from an offset; text, or base64 when it is not UTF-8 |
| `write_file` | write a remote file atomically, or append |
| `list_dir` | list a remote directory, sorted by name |
| `stat` | attributes of one remote path |
| `session_new` | start a long-running command that outlives the call |
| `session_send` | write to a session's stdin, optionally closing it |
| `session_read` | read a session's output from an absolute byte offset |
| `session_kill` | signal a session (default `TERM`) |
| `session_list` | every session of this identity on the host, running or recently exited |
| `put` | copy a local file to the host (needs `--allow-local-paths`) |
| `get` | copy a remote file here (needs `--allow-local-paths`) |
| `info` | what the host is: OS, arch, kernel, shell, home, user, limits, denied features, plus the connection |
| `hosts` | the hosts this server may reach and whether each is connected |

Inputs are JSON objects with `additionalProperties: false`; both
`inputSchema` and `outputSchema` come back from `tools/list`. The result
shapes mirror the CLI's `--json` documents, including the bytes convention
(a string when the data is UTF-8, else `{"base64": "…"}`).

`session_read` is the same absolute-offset, idempotent read as the CLI:
`{offset, next, oldest, chunks, exited}`, pass `next` back. See
[sessions](sessions.md#absolute-offsets).

Requests are served one at a time, in order. A tool that waits — `exec` with
its timeout, `session_read` with `wait_ms` — holds the queue, so keep waits
short and poll instead of blocking for a minute.

## Resources

Files are also readable as resources.

| URI | reads as |
| --- | --- |
| `mysh://HOST/` | the remote home, `inode/directory` |
| `mysh://HOST/etc/hosts` | an absolute path |
| `mysh://HOST/~/notes.txt` | a path under the home |

A directory comes back as `application/json` text — `{"path", "entries":
[...]}`, dot-files included — a UTF-8 file as `text/plain`, and anything
else as an `application/octet-stream` base64 blob. Reads are capped at
1 MiB; use the `read_file` tool with `offset` for more.

`resources/list` advertises one entry per configured host;
`resources/templates/list` advertises `mysh://{host}/{path}`.

## Trust

Stdin carries the protocol, so **`mysh mcp` never asks a question**. Pin each
host's key before pointing an agent at it — connect once interactively with
`mysh HOST`, run `mysh pair HOST CODE`, or put a `pin = "SHA256:…"` in the
alias — or pass `--accept-new` and accept the usual first-use risk.

| server key is | result |
| --- | --- |
| known and matching | fine; `info` says how it was trusted |
| unknown, no `--accept-new` | `trust_unknown` |
| unknown, with `--accept-new` | pinned on first use |
| known and **different** | `trust_mismatch`, no bypass, flag or no flag |

The `instructions` string returned by `initialize` states which of the first
two applies, so an agent can tell you to pin the host instead of retrying.

Identity resolves as it does everywhere else (`-i`, the alias,
`~/.config/mysh/id`, agent keys); a passphrase-protected key file cannot be
unlocked here and fails the same way it does under `mysh --json`.

`put` and `get` touch files on the machine running `mysh mcp`, which is why
they are denied until `--allow-local-paths`:

```json
{"error":{"code":"denied","message":"local paths are disabled; start `mysh mcp --allow-local-paths` to enable put/get"}}
```

Relative local paths resolve against the server process's working directory.
Every other tool only ever touches the remote host, under whatever
`authorized_keys` options and `--deny` flags apply to your key — see
[keys-and-trust](keys-and-trust.md).

## Errors

The distinction matters when you are writing a client.

**Protocol-level problems are JSON-RPC errors**: `-32700` parse error,
`-32600` invalid request, `-32601` unknown method, `-32602` invalid params
(including an unknown tool or an unconfigured `host`), `-32603` internal.

```
→ {"jsonrpc":"2.0","id":8,"method":"nosuch"}
← {"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"method not found: nosuch"}}
```

**A failure on the host is never a JSON-RPC error.** The call succeeds and
the result has `isError: true`, with `{"error":{"code","message"}}` in both
`content[0].text` and `structuredContent`, using the same stable codes as
the CLI ([automation](automation.md#errors-and-codes)):

```
→ {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"stat","arguments":{"path":"/nope"}}}
← {"jsonrpc":"2.0","id":4,"result":{"content":[{"text":"{\"error\":{\"code\":\"not_found\",\"message\":\"/nope: no such file\"}}","type":"text"}],"isError":true,"structuredContent":{"error":{"code":"not_found","message":"/nope: no such file"}}}}
```

**A command that exits non-zero is not an error at all**: `isError: false`
with `exit: 3` in the structured content.

A missing resource path is the one exception on the resource side: JSON-RPC
error `-32002` with `data.code = "not_found"`; other remote failures there
are `-32603` with `data.code` set the same way.

## A session over a pipe

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"resources":{"listChanged":false,"subscribe":false},"tools":{"listChanged":false}},"serverInfo":{"name":"mysh","version":"0.1.0"},"instructions":"mysh gives you a shell-less remote process API on these hosts: box. …"}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"command":"uname -s"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"{\"duration_ms\":7,\"exit\":0,…}","type":"text"}],"isError":false,"structuredContent":{"duration_ms":7,"exit":0,"signal":null,"stderr":"","stdout":"Darwin\n","timed_out":false}}}
→ {"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"mysh://box/~/a.txt"}}
← {"jsonrpc":"2.0","id":7,"result":{"contents":[{"mimeType":"text/plain","text":"one\n","uri":"mysh://box/~/a.txt"}]}}
```

The negotiated `protocolVersion` is the client's if it is `2024-11-05`,
`2025-03-26` or `2025-06-18`, and `2025-06-18` otherwise. `ping` answers
`{}`. Batches (`[…]`) are answered with a batch; notifications get no reply.

## Limitations

- One request at a time, in order — there is no concurrency within a server.
- No prompts, no sampling, no subscriptions: `listChanged` and `subscribe`
  are both false.
- No port forwarding and no interactive PTY attach through MCP; those need
  the CLI.
- Resource reads are capped at 1 MiB.
- `put`/`get` move one file each and are off until `--allow-local-paths`.

If you already have a shell, driving the CLI with `--json` is usually
simpler and strictly more capable — see [automation](automation.md) and the
agent skill at `skills/mysh/SKILL.md`. The tool schemas and their exact
field lists are in [docs/07-embedding.md](../07-embedding.md) under "MCP
server".
