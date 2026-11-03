//! JSON-RPC 2.0 over stdio for the MCP server: message shapes, error codes
//! and the two input framings (one JSON document per line, or LSP-style
//! `Content-Length` headers when the first bytes of a message look like a
//! header). Replies use the framing of the message they answer.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt as _, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
};

/// Standard JSON-RPC error codes, plus MCP's "resource not found".
pub(crate) mod code {
    pub(crate) const PARSE_ERROR: i64 = -32700;
    pub(crate) const INVALID_REQUEST: i64 = -32600;
    pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
    pub(crate) const INVALID_PARAMS: i64 = -32602;
    pub(crate) const INTERNAL: i64 = -32603;
    pub(crate) const RESOURCE_NOT_FOUND: i64 = -32002;
}

/// Largest message accepted on stdin (a `write_file` body is base64 inside
/// it; 64 MiB leaves room for a large file without unbounded buffering).
const MAX_MESSAGE: u64 = 64 * 1024 * 1024;

/// An incoming request or notification (no `id`).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Request {
    #[serde(default)]
    pub(crate) jsonrpc: Option<String>,
    #[serde(default)]
    pub(crate) id: Option<Value>,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Option<Value>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<Value>,
}

impl RpcError {
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub(crate) fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub(crate) fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_PARAMS, message)
    }
}

/// A response: exactly one of `result` / `error`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Response {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<RpcError>,
}

impl Response {
    pub(crate) fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub(crate) fn err(id: Value, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// How a message arrived, so the answer goes back the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// One JSON document per line.
    Line,
    /// `Content-Length: N\r\n\r\n` + N bytes.
    ContentLength,
}

/// Reads framed messages from stdin.
#[derive(Debug)]
pub(crate) struct Reader<R> {
    input: BufReader<R>,
}

impl<R: tokio::io::AsyncRead + Unpin> Reader<R> {
    pub(crate) fn new(input: R) -> Self {
        Self {
            input: BufReader::new(input),
        }
    }

    /// The next raw message, or `None` at EOF. Blank lines are skipped. A
    /// line starting with `Content-Length:` switches to header framing for
    /// that one message.
    pub(crate) async fn next(&mut self) -> Result<Option<(Framing, Vec<u8>)>> {
        loop {
            let mut line = Vec::new();
            let n = (&mut self.input)
                .take(MAX_MESSAGE)
                .read_until(b'\n', &mut line)
                .await
                .context("reading stdin")?;
            if n == 0 {
                return Ok(None);
            }
            let text = String::from_utf8_lossy(&line);
            let trimmed = text.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(rest) = header_value(trimmed, "content-length") {
                let len: u64 = rest.parse().context("Content-Length is not a number")?;
                if len > MAX_MESSAGE {
                    bail!("message of {len} bytes exceeds the {MAX_MESSAGE} byte limit");
                }
                // Remaining headers up to the blank line.
                loop {
                    let mut header = Vec::new();
                    let n = self
                        .input
                        .read_until(b'\n', &mut header)
                        .await
                        .context("reading headers")?;
                    if n == 0 {
                        bail!("stdin closed inside a Content-Length header block");
                    }
                    if String::from_utf8_lossy(&header).trim().is_empty() {
                        break;
                    }
                }
                let mut body = vec![0u8; usize::try_from(len).context("Content-Length too large")?];
                self.input
                    .read_exact(&mut body)
                    .await
                    .context("reading the message body")?;
                return Ok(Some((Framing::ContentLength, body)));
            }
            return Ok(Some((Framing::Line, line)));
        }
    }
}

/// `NAME: value` (case-insensitive name) → `value`.
fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
}

/// Serialize one message with `framing` and flush it.
pub(crate) async fn write_message<W: AsyncWrite + Unpin>(
    out: &mut W,
    framing: Framing,
    message: &impl Serialize,
) -> Result<()> {
    let mut body = serde_json::to_vec(message).context("serializing a reply")?;
    match framing {
        Framing::Line => body.push(b'\n'),
        Framing::ContentLength => {
            let header = format!("Content-Length: {}\r\n\r\n", body.len());
            body.splice(0..0, header.into_bytes());
        }
    }
    out.write_all(&body).await.context("writing stdout")?;
    out.flush().await.context("flushing stdout")
}

/// Parse one raw message: a single request or a batch (`batch` says
/// which, so the replies can be wrapped the same way). A parse failure is
/// reported through `Err` so the loop can answer with `-32700`.
pub(crate) fn parse(raw: &[u8]) -> Result<Parsed, RpcError> {
    let value: Value = serde_json::from_slice(raw)
        .map_err(|e| RpcError::new(code::PARSE_ERROR, format!("parse error: {e}")))?;
    let (batch, items) = match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Err(RpcError::new(
                    code::INVALID_REQUEST,
                    "invalid request: empty batch",
                ));
            }
            (true, items)
        }
        other => (false, vec![other]),
    };
    let items = items
        .into_iter()
        .map(|item| {
            serde_json::from_value::<Request>(item)
                .map_err(|e| RpcError::new(code::INVALID_REQUEST, format!("invalid request: {e}")))
        })
        .collect();
    Ok(Parsed { batch, items })
}

/// Output of [`parse`].
#[derive(Debug)]
pub(crate) struct Parsed {
    pub(crate) batch: bool,
    pub(crate) items: Vec<Result<Request, RpcError>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_line_and_content_length_framing() {
        let input = b"{\"a\":1}\n\nContent-Length: 7\r\nX-Other: y\r\n\r\n{\"b\":2}{\"c\":3}\n";
        let mut reader = Reader::new(&input[..]);
        let (f, m) = reader.next().await.unwrap().unwrap();
        assert_eq!((f, m.as_slice()), (Framing::Line, &b"{\"a\":1}\n"[..]));
        let (f, m) = reader.next().await.unwrap().unwrap();
        assert_eq!(
            (f, m.as_slice()),
            (Framing::ContentLength, &b"{\"b\":2}"[..])
        );
        let (f, m) = reader.next().await.unwrap().unwrap();
        assert_eq!((f, m.as_slice()), (Framing::Line, &b"{\"c\":3}\n"[..]));
        assert!(reader.next().await.unwrap().is_none());
    }

    #[test]
    fn parses_single_and_batch() {
        let one = parse(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).unwrap();
        assert!(!one.batch);
        assert_eq!(one.items.len(), 1);
        assert_eq!(one.items[0].as_ref().unwrap().method, "ping");
        let batch = parse(br#"[{"jsonrpc":"2.0","method":"a"},{"bad":true}]"#).unwrap();
        assert!(batch.batch);
        assert!(batch.items[0].is_ok());
        assert_eq!(
            batch.items[1].as_ref().unwrap_err().code,
            code::INVALID_REQUEST
        );
        assert_eq!(parse(b"{").unwrap_err().code, code::PARSE_ERROR);
        assert_eq!(parse(b"[]").unwrap_err().code, code::INVALID_REQUEST);
    }

    #[tokio::test]
    async fn writes_with_requested_framing() {
        let mut out = Vec::new();
        write_message(&mut out, Framing::Line, &serde_json::json!({"x": 1}))
            .await
            .unwrap();
        assert_eq!(out, b"{\"x\":1}\n");
        out.clear();
        write_message(
            &mut out,
            Framing::ContentLength,
            &serde_json::json!({"x": 1}),
        )
        .await
        .unwrap();
        assert_eq!(out, b"Content-Length: 7\r\n\r\n{\"x\":1}");
    }
}
