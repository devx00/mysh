//! Hand-written JSON Schemas for every MCP tool (input and output) and the
//! tool descriptions. No schema derivation: the shapes are the `--json`
//! documents of `crate::output` and `client::session_api`, so a change
//! there is a change here (docs/07-embedding.md "Tools").

use serde_json::{Value, json};

/// One entry of `tools/list`.
#[derive(Debug, Clone)]
pub(crate) struct ToolSpec {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) input: Value,
    pub(crate) output: Value,
}

impl ToolSpec {
    /// The `tools/list` object (2025-06-18 shape; older clients ignore
    /// `outputSchema`).
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input,
            "outputSchema": self.output,
        })
    }
}

/// Names of every tool, in `tools/list` order.
pub(crate) const TOOL_NAMES: [&str; 14] = [
    "exec",
    "read_file",
    "write_file",
    "list_dir",
    "stat",
    "session_new",
    "session_send",
    "session_read",
    "session_kill",
    "session_list",
    "put",
    "get",
    "info",
    "hosts",
];

/// Default `max_bytes` of `read_file` (1 MiB).
pub(crate) const READ_FILE_MAX: u64 = 1024 * 1024;
/// Default `timeout_ms` of `exec`.
pub(crate) const EXEC_TIMEOUT_MS: u64 = 60_000;

/// Every tool with its schemas. `single_host` makes `host` optional
/// (it defaults to the only configured host).
#[allow(clippy::too_many_lines)] // one literal per tool; this is the table
pub(crate) fn tools(single_host: bool) -> Vec<ToolSpec> {
    let input = |properties: Value, required: &[&str]| -> Value {
        let mut props = properties;
        if let Value::Object(map) = &mut props {
            map.insert(
                "host".to_owned(),
                json!({
                    "type": "string",
                    "description": if single_host {
                        "Configured host (optional: defaults to the only host)"
                    } else {
                        "Which configured host to use (see the `hosts` tool)"
                    },
                }),
            );
        }
        let mut required: Vec<&str> = required.to_vec();
        if !single_host {
            required.insert(0, "host");
        }
        json!({
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": false,
        })
    };
    let command = json!({
        "oneOf": [
            {"type": "string", "description": "A shell command line (runs through the remote user's shell)"},
            {"type": "array", "items": {"type": "string"}, "minItems": 1,
             "description": "argv: executed directly, no shell"}
        ]
    });
    let env = json!({
        "type": "object",
        "additionalProperties": {"type": "string"},
        "description": "Extra environment variables (subject to the server's accept-env list)"
    });
    let cwd = json!({"type": "string", "description": "Remote working directory (default: home)"});
    let path = json!({"type": "string", "description": "Remote path; `~` and relative paths resolve against the remote home"});
    let session_id =
        json!({"type": "integer", "minimum": 0, "description": "Session id from `session_new`"});
    let encoding = json!({"type": "string", "enum": ["utf-8", "base64"], "default": "utf-8"});
    let ok = json!({
        "type": "object",
        "properties": {"ok": {"type": "boolean", "const": true}},
        "required": ["ok"],
    });

    vec![
        ToolSpec {
            name: "exec",
            description: "Run a command on the host and wait for it to finish. Returns stdout, stderr and \
                          the exit status; a non-zero exit is a normal result, not an error. `timeout_ms` \
                          sends TERM then KILL and reports `timed_out: true`.",
            input: input(
                json!({
                    "command": command,
                    "cwd": cwd,
                    "env": env,
                    "timeout_ms": {"type": "integer", "minimum": 0, "default": EXEC_TIMEOUT_MS,
                                   "description": "Give up after this many milliseconds (0: no limit)"},
                    "stdin": {"type": "string", "description": "Text written to the command's stdin before EOF"},
                }),
                &["command"],
            ),
            output: exec_result(),
        },
        ToolSpec {
            name: "read_file",
            description: "Read a remote file. UTF-8 content comes back as text, anything else as base64; \
                          `truncated` says whether more follows at `offset + content length`.",
            input: input(
                json!({
                    "path": path,
                    "offset": {"type": "integer", "minimum": 0, "default": 0, "description": "Byte offset to start at"},
                    "max_bytes": {"type": "integer", "minimum": 1, "default": READ_FILE_MAX,
                                  "description": "At most this many bytes"},
                }),
                &["path"],
            ),
            output: json!({
                "type": "object",
                "properties": {
                    "content": {"type": "string"},
                    "encoding": encoding,
                    "size": {"type": "integer", "description": "Size of the whole file"},
                    "offset": {"type": "integer"},
                    "truncated": {"type": "boolean"},
                },
                "required": ["content", "encoding", "size", "offset", "truncated"],
            }),
        },
        ToolSpec {
            name: "write_file",
            description: "Write a remote file: replaced atomically, or appended with `append`. Content is \
                          text, or base64 with `encoding: \"base64\"`.",
            input: input(
                json!({
                    "path": path,
                    "content": {"type": "string"},
                    "encoding": encoding,
                    "mode": {"type": "string", "pattern": "^[0-7]{3,4}$",
                             "description": "Octal permission bits of a new file (default 0644)"},
                    "append": {"type": "boolean", "default": false},
                }),
                &["path", "content"],
            ),
            output: json!({
                "type": "object",
                "properties": {"written": {"type": "integer", "description": "Bytes written"}},
                "required": ["written"],
            }),
        },
        ToolSpec {
            name: "list_dir",
            description: "List a remote directory, sorted by name. Dot-files only with `all`.",
            input: input(
                json!({
                    "path": path,
                    "all": {"type": "boolean", "default": false},
                }),
                &["path"],
            ),
            output: json!({
                "type": "object",
                "properties": {"entries": {"type": "array", "items": ls_entry()}},
                "required": ["entries"],
            }),
        },
        ToolSpec {
            name: "stat",
            description: "Attributes of one remote path (kind, size, mode, mtime, owner, symlink target). \
                          A missing path fails with code `not_found`.",
            input: input(json!({"path": path}), &["path"]),
            output: stat_out(),
        },
        ToolSpec {
            name: "session_new",
            description: "Start a long-running command that outlives this call. Read its output with \
                          `session_read`, feed it with `session_send`, end it with `session_kill`. With \
                          `pty` the command gets an 80x24 pseudo-terminal.",
            input: input(
                json!({
                    "command": command,
                    "cwd": cwd,
                    "pty": {"type": "boolean", "default": false},
                    "env": env,
                }),
                &["command"],
            ),
            output: json!({
                "type": "object",
                "properties": {"id": {"type": "integer"}, "pid": {"type": "integer"}},
                "required": ["id", "pid"],
            }),
        },
        ToolSpec {
            name: "session_send",
            description: "Write to a session's stdin. `eof` closes stdin afterwards (non-PTY sessions).",
            input: input(
                json!({
                    "id": session_id,
                    "data": {"type": "string", "description": "Bytes to write (text, or base64 with `encoding`)"},
                    "encoding": encoding,
                    "eof": {"type": "boolean", "default": false},
                }),
                &["id", "data"],
            ),
            output: ok.clone(),
        },
        ToolSpec {
            name: "session_read",
            description: "Read a session's output from an absolute byte offset; pass `next` back to \
                          continue. `wait_ms` blocks for new output. `exited` is set once the process ended.",
            input: input(
                json!({
                    "id": session_id,
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "max_bytes": {"type": "integer", "minimum": 1, "default": 1_048_576},
                    "wait_ms": {"type": "integer", "minimum": 0, "default": 0,
                                "description": "Wait up to this long for output (server caps it)"},
                }),
                &["id"],
            ),
            output: json!({
                "type": "object",
                "properties": {
                    "offset": {"type": "integer"},
                    "next": {"type": "integer"},
                    "oldest": {"type": "integer", "description": "Oldest offset the server still holds"},
                    "chunks": {"type": "array", "items": {
                        "type": "object",
                        "properties": {
                            "stream": {"type": "string", "enum": ["stdout", "stderr"]},
                            "data": bytes(),
                        },
                        "required": ["stream", "data"],
                    }},
                    "exited": {"oneOf": [exit_out(), {"type": "null"}]},
                },
                "required": ["offset", "next", "oldest", "chunks", "exited"],
            }),
        },
        ToolSpec {
            name: "session_kill",
            description: "Send a signal to a session (default TERM).",
            input: input(
                json!({
                    "id": session_id,
                    "signal": {"type": "string", "default": "TERM",
                               "description": "INT, TERM, HUP, KILL, QUIT, USR1, USR2, WINCH (or a number)"},
                }),
                &["id"],
            ),
            output: ok,
        },
        ToolSpec {
            name: "session_list",
            description: "Every session of this identity on the host, running or recently exited.",
            input: input(json!({}), &[]),
            output: json!({
                "type": "object",
                "properties": {"sessions": {"type": "array", "items": session_row()}},
                "required": ["sessions"],
            }),
        },
        ToolSpec {
            name: "put",
            description: "Copy a local file to the host (needs `mysh mcp --allow-local-paths`, else \
                          fails with code `denied`). `checksum` skips the copy when the remote already \
                          matches.",
            input: input(
                json!({
                    "local": {"type": "string", "description": "Local path (relative to the MCP server's cwd)"},
                    "remote": {"type": "string", "description": "Remote file or directory"},
                    "checksum": {"type": "boolean", "default": false},
                }),
                &["local", "remote"],
            ),
            output: transfer_out(),
        },
        ToolSpec {
            name: "get",
            description: "Copy a remote file to the local machine (needs `mysh mcp --allow-local-paths`, \
                          else fails with code `denied`).",
            input: input(
                json!({
                    "remote": {"type": "string", "description": "Remote file"},
                    "local": {"type": "string", "description": "Local file or directory (relative to the MCP server's cwd)"},
                }),
                &["remote", "local"],
            ),
            output: transfer_out(),
        },
        ToolSpec {
            name: "info",
            description: "What the host is: OS, arch, kernel, shell, home, user, limits, denied \
                          features, plus the connection's keys and traffic.",
            input: input(json!({}), &[]),
            output: json!({
                "type": "object",
                "properties": {
                    "server": {"oneOf": [server_info(), {"type": "null"}]},
                    "connection": connection_out(),
                    "sessions": {"type": "array"},
                    "forwards": {"type": "array"},
                },
                "required": ["server", "connection", "sessions", "forwards"],
            }),
        },
        ToolSpec {
            name: "hosts",
            description: "The hosts this server may reach and whether each is connected right now.",
            input: json!({"type": "object", "properties": {}, "additionalProperties": false}),
            output: json!({
                "type": "object",
                "properties": {"hosts": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Name to pass as `host`"},
                        "target": {"type": "string", "description": "Resolved `host:port`"},
                        "connected": {"type": "boolean"},
                        "connection": {"oneOf": [connection_out(), {"type": "null"}]},
                    },
                    "required": ["host", "target", "connected", "connection"],
                }}},
                "required": ["hosts"],
            }),
        },
    ]
}

/// `crate::output::Bytes`: a string when UTF-8, else `{"base64": …}`.
fn bytes() -> Value {
    json!({
        "oneOf": [
            {"type": "string"},
            {"type": "object", "properties": {"base64": {"type": "string"}}, "required": ["base64"]}
        ]
    })
}

fn nullable_int() -> Value {
    json!({"type": ["integer", "null"]})
}

fn exec_result() -> Value {
    json!({
        "type": "object",
        "properties": {
            "stdout": bytes(),
            "stderr": bytes(),
            "exit": nullable_int(),
            "signal": nullable_int(),
            "duration_ms": {"type": "integer"},
            "timed_out": {"type": "boolean"},
        },
        "required": ["stdout", "stderr", "exit", "signal", "duration_ms", "timed_out"],
    })
}

fn exit_out() -> Value {
    json!({
        "type": "object",
        "properties": {"exit": nullable_int(), "signal": nullable_int()},
        "required": ["exit", "signal"],
    })
}

fn ls_entry() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "kind": {"type": "string", "enum": ["file", "dir", "symlink", "other"]},
            "size": {"type": "integer"},
            "mode": {"type": "string", "description": "Octal, e.g. \"0644\""},
            "mtime": {"type": "string", "description": "RFC 3339 UTC"},
            "target": {"type": ["string", "null"], "description": "Symlink target"},
        },
        "required": ["name", "kind", "size", "mode", "mtime", "target"],
    })
}

fn stat_out() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "kind": {"type": "string", "enum": ["file", "dir", "symlink", "other"]},
            "size": {"type": "integer"},
            "mode": {"type": "string"},
            "mtime": {"type": "string"},
            "uid": {"type": "integer"},
            "gid": {"type": "integer"},
            "target": {"type": ["string", "null"]},
        },
        "required": ["path", "kind", "size", "mode", "mtime", "uid", "gid", "target"],
    })
}

fn session_row() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "pid": {"type": "integer"},
            "kind": {"type": "string"},
            "started": {"type": "integer", "description": "Unix seconds"},
            "detached": nullable_int(),
            "pty": {"type": "boolean"},
            "buffered": {"type": "integer"},
            "next": {"type": "integer"},
            "oldest": {"type": "integer"},
            "exited": {"oneOf": [exit_out(), {"type": "null"}]},
        },
        "required": ["id", "pid", "kind", "started", "detached", "pty", "buffered", "next", "oldest", "exited"],
    })
}

fn transfer_out() -> Value {
    json!({
        "type": "object",
        "properties": {
            "files": {"type": "integer"},
            "skipped": {"type": "integer"},
            "bytes": {"type": "integer"},
            "duration_ms": {"type": "integer"},
        },
        "required": ["files", "skipped", "bytes", "duration_ms"],
    })
}

fn connection_out() -> Value {
    json!({
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "peer": {"type": "string"},
            "peer_fingerprint": {"type": "string"},
            "trusted_via": {"type": "string"},
            "our_key": {"type": "string"},
            "protocol": {"type": "integer"},
            "cipher": {"type": "string"},
            "connected_secs": {"type": "integer"},
            "rtt_ms": {"type": ["number", "null"]},
            "bytes_in": {"type": "integer"},
            "bytes_out": {"type": "integer"},
            "rekeys": {"type": "integer"},
        },
        "required": ["host", "port", "peer", "peer_fingerprint", "trusted_via", "our_key",
                     "protocol", "cipher", "connected_secs", "rtt_ms", "bytes_in", "bytes_out", "rekeys"],
    })
}

fn server_info() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "version": {"type": "string"},
            "platform": {
                "type": "object",
                "properties": {
                    "os": {"type": "string"},
                    "arch": {"type": "string"},
                    "kernel": {"type": "string"},
                },
                "required": ["os", "arch", "kernel"],
            },
            "shell": {"type": "string"},
            "home": {"type": "string"},
            "user": {"type": "string"},
            "caps": {"type": "integer"},
            "limits": {
                "type": "object",
                "properties": {
                    "max_sessions": {"type": "integer"},
                    "max_listeners": {"type": "integer"},
                    "max_streams": {"type": "integer"},
                    "detach_grace_secs": {"type": "integer"},
                    "idle_timeout_secs": {"type": "integer"},
                    "handshakes_per_minute": {"type": "integer"},
                    "denied": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["max_sessions", "max_listeners", "max_streams", "detach_grace_secs",
                             "idle_timeout_secs", "handshakes_per_minute", "denied"],
            },
            "uptime_secs": {"type": "integer"},
            "authorized_keys": {"type": "string", "description": "the authorized_keys file the server reads; `authorize` appends to it"},
        },
        "required": ["name", "version", "platform", "shell", "home", "user", "caps", "limits", "uptime_secs", "authorized_keys"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_object_schemas_and_host_rule() {
        for single in [true, false] {
            let specs = tools(single);
            assert_eq!(specs.len(), TOOL_NAMES.len());
            for (spec, name) in specs.iter().zip(TOOL_NAMES) {
                assert_eq!(spec.name, name);
                assert_eq!(spec.input["type"], "object");
                assert_eq!(spec.output["type"], "object");
                if name == "hosts" {
                    continue;
                }
                let required = spec.input["required"].as_array().unwrap();
                assert_eq!(
                    required.iter().any(|r| r == "host"),
                    !single,
                    "{name}: host requirement"
                );
                assert!(spec.input["properties"]["host"].is_object());
            }
        }
    }
}
