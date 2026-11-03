//! `tools/call`: argument parsing (validated against the shapes in
//! [`super::schema`]) and the mapping from a [`Backend`] result to an MCP
//! call result. A remote failure is never a JSON-RPC error: it comes back
//! as `isError: true` with `{"error":{"code","message"}}` both as text and
//! as `structuredContent`, so a client sees the same stable codes as
//! `mysh --json` (docs/05-meta-shell.md "Error codes").

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Result, anyhow};
use base64::Engine as _;
use mysh_proto::{limits::READ_MAX, session::Signal};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Hosts,
    backend::{Backend, ExecRequest},
    rpc::RpcError,
    schema::{EXEC_TIMEOUT_MS, READ_FILE_MAX, TOOL_NAMES},
};
use crate::output::{ErrorOut, coded, codes};

/// `command`: a shell line or an argv.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Command {
    Line(String),
    Argv(Vec<String>),
}

impl Command {
    fn into_argv(self) -> Result<Vec<String>, RpcError> {
        let argv = match self {
            Self::Line(line) => vec![line],
            Self::Argv(argv) => argv,
        };
        if argv.is_empty() || argv.iter().all(String::is_empty) {
            return Err(RpcError::invalid_params("command must not be empty"));
        }
        Ok(argv)
    }
}

/// `encoding` of a string carrying bytes.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
enum Encoding {
    #[default]
    #[serde(rename = "utf-8")]
    Utf8,
    #[serde(rename = "base64")]
    Base64,
}

impl Encoding {
    fn decode(self, data: &str) -> Result<Vec<u8>, RpcError> {
        match self {
            Self::Utf8 => Ok(data.as_bytes().to_vec()),
            Self::Base64 => base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| RpcError::invalid_params(format!("data is not valid base64: {e}"))),
        }
    }
}

fn env_pairs(env: BTreeMap<String, String>) -> Vec<(String, String)> {
    env.into_iter().collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecArgs {
    host: Option<String>,
    command: Command,
    cwd: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    timeout_ms: Option<u64>,
    stdin: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFileArgs {
    host: Option<String>,
    path: String,
    #[serde(default)]
    offset: u64,
    max_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteFileArgs {
    host: Option<String>,
    path: String,
    content: String,
    #[serde(default)]
    encoding: Encoding,
    mode: Option<String>,
    #[serde(default)]
    append: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListDirArgs {
    host: Option<String>,
    path: String,
    #[serde(default)]
    all: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatArgs {
    host: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionNewArgs {
    host: Option<String>,
    command: Command,
    cwd: Option<String>,
    #[serde(default)]
    pty: bool,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSendArgs {
    host: Option<String>,
    id: u32,
    data: String,
    #[serde(default)]
    encoding: Encoding,
    #[serde(default)]
    eof: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReadArgs {
    host: Option<String>,
    id: u32,
    #[serde(default)]
    offset: u64,
    max_bytes: Option<u32>,
    #[serde(default)]
    wait_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionKillArgs {
    host: Option<String>,
    id: u32,
    signal: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostOnlyArgs {
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutArgs {
    host: Option<String>,
    local: String,
    remote: String,
    #[serde(default)]
    checksum: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    host: Option<String>,
    remote: String,
    local: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

/// Parse `arguments` as `T`; a serde message becomes the `-32602` text.
fn parse<T: serde::de::DeserializeOwned>(args: Value) -> Result<T, RpcError> {
    serde_json::from_value(args)
        .map_err(|e| RpcError::invalid_params(format!("invalid arguments: {e}")))
}

/// The `tools/call` result for a value.
fn ok_result(value: &Value) -> Value {
    json!({
        "content": [{"type": "text", "text": value.to_string()}],
        "structuredContent": value,
        "isError": false,
    })
}

/// The `tools/call` result for a failure: `{"error":{"code","message"}}`.
pub(crate) fn error_result(err: &anyhow::Error) -> Value {
    let out = ErrorOut::from_error(err);
    let value = serde_json::to_value(&out).unwrap_or_else(
        |_| json!({"error": {"code": codes::INTERNAL, "message": out.error.message}}),
    );
    json!({
        "content": [{"type": "text", "text": out.to_line()}],
        "structuredContent": value,
        "isError": true,
    })
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| anyhow!("serializing the result: {e}"))
}

fn ok_value() -> Value {
    json!({"ok": true})
}

/// Run one tool. `Err` is a protocol-level problem (`-32602` for bad
/// arguments or an unknown tool); a remote failure is an `Ok` result with
/// `isError: true`.
#[allow(clippy::too_many_lines)] // one arm per tool; splitting them would only scatter the table
pub(crate) async fn call(hosts: &Hosts, name: &str, arguments: Value) -> Result<Value, RpcError> {
    let arguments = if arguments.is_null() {
        json!({})
    } else {
        arguments
    };
    if name == "hosts" {
        let NoArgs {} = parse(arguments)?;
        let value = hosts.list().await;
        return Ok(ok_result(&value));
    }
    let outcome = match name {
        "exec" => {
            let args: ExecArgs = parse(arguments)?;
            let command = args.command.into_argv()?;
            let timeout = match args.timeout_ms.unwrap_or(EXEC_TIMEOUT_MS) {
                0 => None,
                ms => Some(Duration::from_millis(ms)),
            };
            let req = ExecRequest {
                argv: command,
                cwd: args.cwd,
                env: env_pairs(args.env),
                timeout,
                stdin: args.stdin.map(String::into_bytes),
            };
            with_backend(hosts, args.host, |b| async move {
                to_value(&b.exec(req).await?)
            })
            .await
        }
        "read_file" => {
            let args: ReadFileArgs = parse(arguments)?;
            let max = args.max_bytes.unwrap_or(READ_FILE_MAX);
            if max == 0 {
                return Err(RpcError::invalid_params("max_bytes must be at least 1"));
            }
            let offset = args.offset;
            with_backend(hosts, args.host, |b| async move {
                let read = b.read_file(&args.path, offset, max).await?;
                let got = u64::try_from(read.bytes.len()).unwrap_or(u64::MAX);
                let (content, encoding) = encode(read.bytes);
                Ok(json!({
                    "content": content,
                    "encoding": encoding,
                    "size": read.attrs.size,
                    "offset": offset,
                    "truncated": offset.saturating_add(got) < read.attrs.size,
                }))
            })
            .await
        }
        "write_file" => {
            let args: WriteFileArgs = parse(arguments)?;
            let bytes = args.encoding.decode(&args.content)?;
            let mode = args.mode.as_deref().map(parse_mode).transpose()?;
            with_backend(hosts, args.host, |b| async move {
                let written = b.write_file(&args.path, &bytes, mode, args.append).await?;
                Ok(json!({"written": written}))
            })
            .await
        }
        "list_dir" => {
            let args: ListDirArgs = parse(arguments)?;
            with_backend(hosts, args.host, |b| async move {
                let entries = b.list_dir(&args.path, args.all).await?;
                Ok(json!({"entries": to_value(&entries)?}))
            })
            .await
        }
        "stat" => {
            let args: StatArgs = parse(arguments)?;
            with_backend(hosts, args.host, |b| async move {
                to_value(&b.stat(&args.path).await?)
            })
            .await
        }
        "session_new" => {
            let args: SessionNewArgs = parse(arguments)?;
            let command = args.command.into_argv()?;
            with_backend(hosts, args.host, |b| async move {
                to_value(
                    &b.session_new(command, args.cwd, args.pty, env_pairs(args.env))
                        .await?,
                )
            })
            .await
        }
        "session_send" => {
            let args: SessionSendArgs = parse(arguments)?;
            let bytes = args.encoding.decode(&args.data)?;
            if bytes.is_empty() && !args.eof {
                return Err(RpcError::invalid_params(
                    "nothing to send: give data or eof",
                ));
            }
            with_backend(hosts, args.host, |b| async move {
                b.session_send(args.id, &bytes, args.eof).await?;
                Ok(ok_value())
            })
            .await
        }
        "session_read" => {
            let args: SessionReadArgs = parse(arguments)?;
            let max = args.max_bytes.unwrap_or(READ_MAX);
            if max == 0 {
                return Err(RpcError::invalid_params("max_bytes must be at least 1"));
            }
            let wait = Duration::from_millis(args.wait_ms);
            with_backend(hosts, args.host, |b| async move {
                to_value(&b.session_read(args.id, args.offset, max, wait).await?)
            })
            .await
        }
        "session_kill" => {
            let args: SessionKillArgs = parse(arguments)?;
            let signal = match args.signal.as_deref() {
                None => Signal::Term,
                Some(name) => Signal::parse(name)
                    .ok_or_else(|| RpcError::invalid_params(format!("unknown signal {name:?}")))?,
            };
            with_backend(hosts, args.host, |b| async move {
                b.session_kill(args.id, signal).await?;
                Ok(ok_value())
            })
            .await
        }
        "session_list" => {
            let args: HostOnlyArgs = parse(arguments)?;
            with_backend(hosts, args.host, |b| async move {
                Ok(json!({"sessions": to_value(&b.session_list().await?)?}))
            })
            .await
        }
        "put" => {
            let args: PutArgs = parse(arguments)?;
            let local_cwd = hosts.local_cwd().to_path_buf();
            match hosts.local_paths_allowed() {
                Ok(()) => {
                    with_backend(hosts, args.host, |b| async move {
                        to_value(
                            &b.put(&args.local, &args.remote, args.checksum, &local_cwd)
                                .await?,
                        )
                    })
                    .await
                }
                Err(e) => Ok(Err(e)),
            }
        }
        "get" => {
            let args: GetArgs = parse(arguments)?;
            let local_cwd = hosts.local_cwd().to_path_buf();
            match hosts.local_paths_allowed() {
                Ok(()) => {
                    with_backend(hosts, args.host, |b| async move {
                        to_value(&b.get(&args.remote, &args.local, &local_cwd).await?)
                    })
                    .await
                }
                Err(e) => Ok(Err(e)),
            }
        }
        "info" => {
            let args: HostOnlyArgs = parse(arguments)?;
            with_backend(
                hosts,
                args.host,
                |b| async move { to_value(&b.info().await?) },
            )
            .await
        }
        other => {
            return Err(RpcError::invalid_params(format!(
                "unknown tool {other:?}; tools: {}",
                TOOL_NAMES.join(", ")
            )));
        }
    }?;
    Ok(match outcome {
        Ok(value) => ok_result(&value),
        Err(err) => error_result(&err),
    })
}

/// Resolve the host (a protocol error when it is not configured), connect
/// to it lazily, and run `f`. The inner `Result` is the tool outcome.
async fn with_backend<F, Fut>(
    hosts: &Hosts,
    host: Option<String>,
    f: F,
) -> Result<Result<Value>, RpcError>
where
    F: FnOnce(std::sync::Arc<Backend>) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    let name = hosts.resolve_name(host.as_deref())?;
    Ok(match hosts.backend(&name).await {
        Ok(backend) => f(backend).await,
        Err(e) => Err(e),
    })
}

/// Text when UTF-8, else base64.
fn encode(bytes: Vec<u8>) -> (String, &'static str) {
    match String::from_utf8(bytes) {
        Ok(text) => (text, "utf-8"),
        Err(e) => (
            base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
            "base64",
        ),
    }
}

/// Octal permission bits (`"644"`, `"0755"`).
fn parse_mode(text: &str) -> Result<u32, RpcError> {
    u32::from_str_radix(text, 8)
        .ok()
        .filter(|m| *m <= 0o7777)
        .ok_or_else(|| {
            RpcError::invalid_params(format!("mode {text:?} is not octal permission bits"))
        })
}

/// The `denied` failure of `put`/`get` without `--allow-local-paths`.
pub(crate) fn local_paths_denied() -> anyhow::Error {
    coded(
        codes::DENIED,
        anyhow!("local paths are disabled; start `mysh mcp --allow-local-paths` to enable put/get"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_forms() {
        let line: Command = serde_json::from_value(json!("ls -l")).unwrap();
        assert_eq!(line.into_argv().unwrap(), vec!["ls -l".to_owned()]);
        let argv: Command = serde_json::from_value(json!(["ls", "-l"])).unwrap();
        assert_eq!(argv.into_argv().unwrap().len(), 2);
        let empty: Command = serde_json::from_value(json!([])).unwrap();
        assert!(empty.into_argv().is_err());
    }

    #[test]
    fn modes_and_encodings() {
        assert_eq!(parse_mode("644").unwrap(), 0o644);
        assert_eq!(parse_mode("0755").unwrap(), 0o755);
        assert!(parse_mode("999").is_err());
        assert_eq!(Encoding::Base64.decode("aGk=").unwrap(), b"hi");
        assert!(Encoding::Base64.decode("*").is_err());
        assert_eq!(encode(b"hi".to_vec()), ("hi".to_owned(), "utf-8"));
        assert_eq!(encode(vec![0xff, 0x00]), ("/wA=".to_owned(), "base64"));
    }

    #[test]
    fn error_result_carries_the_code() {
        let err = coded(codes::NOT_FOUND, anyhow!("nope"));
        let out = error_result(&err);
        assert_eq!(out["isError"], true);
        assert_eq!(out["structuredContent"]["error"]["code"], "not_found");
        let text: Value =
            serde_json::from_str(out["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, out["structuredContent"]);
    }

    #[test]
    fn unknown_fields_are_invalid_params() {
        let err = parse::<StatArgs>(json!({"path": "x", "bogus": 1})).unwrap_err();
        assert_eq!(err.code, super::super::rpc::code::INVALID_PARAMS);
        assert!(err.message.contains("bogus"));
    }
}
