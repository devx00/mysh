//! `mysh mcp`: a Model Context Protocol server over stdio
//! (docs/07-embedding.md "MCP server"). Stdin carries JSON-RPC, so nothing
//! here ever prompts: an unknown server key is accepted only with
//! `--accept-new`, otherwise the tool call fails with `trust_unknown`.
//!
//! One connection per configured host, opened on first use and reopened
//! when lost. Requests are served one at a time in arrival order; a tool
//! that waits (an `exec` with a long timeout, a `session_read` with
//! `wait_ms`) holds the queue, which keeps the server trivially safe
//! without locks across awaits.
//!
//! Layout: `rpc` framing and message shapes, `schema` the tool list,
//! `tools` argument parsing and results, `resources` `mysh://` URIs,
//! `backend` the only file that talks to the client library.

mod backend;
mod resources;
mod rpc;
mod schema;
mod tools;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, anyhow};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use self::{
    backend::Backend,
    rpc::{Request, Response, RpcError, code},
};
use crate::{
    cli::{ConnectOpts, McpArgs},
    client::fleet::expand_hosts,
    config::{Config, Paths, Target, resolve_target},
    identity::Baked,
    output::{coded, codes},
};

/// Protocol versions this server speaks; the client's choice is echoed when
/// it is one of these, else the newest.
const PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

/// The configured hosts and their connections.
pub(crate) struct Hosts {
    /// As given, order kept (the default host is the only one).
    names: Vec<String>,
    targets: HashMap<String, Target>,
    paths: Paths,
    baked: Baked,
    allow_local_paths: bool,
    local_cwd: PathBuf,
    conns: Mutex<HashMap<String, Arc<Backend>>>,
}

impl std::fmt::Debug for Hosts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hosts")
            .field("names", &self.names)
            .field("allow_local_paths", &self.allow_local_paths)
            .finish_non_exhaustive()
    }
}

impl Hosts {
    fn new(args: &McpArgs, config: &Config, paths: Paths, baked: Baked) -> Result<Self> {
        let names = expand_hosts(&args.hosts, &args.group, config)
            .map_err(|e| coded(codes::USAGE, anyhow!(e)))?;
        let opts = ConnectOpts {
            identity: args.identity.clone(),
            accept_new: args.accept_new,
            ..ConnectOpts::default()
        };
        let mut targets = HashMap::with_capacity(names.len());
        for name in &names {
            let target = resolve_target(name, &opts, config)
                .map_err(|e| coded(codes::USAGE, anyhow!(e)))
                .with_context(|| format!("resolving {name}"))?;
            targets.insert(name.clone(), target);
        }
        let local_cwd = std::env::current_dir().context("current directory")?;
        Ok(Self {
            names,
            targets,
            paths,
            baked,
            allow_local_paths: args.allow_local_paths,
            local_cwd,
            conns: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn names(&self) -> &[String] {
        &self.names
    }

    pub(crate) fn local_cwd(&self) -> &Path {
        &self.local_cwd
    }

    /// `Ok` when `put`/`get` may touch local files.
    pub(crate) fn local_paths_allowed(&self) -> Result<()> {
        if self.allow_local_paths {
            Ok(())
        } else {
            Err(tools::local_paths_denied())
        }
    }

    /// The configured name for a tool's `host` argument: as given when it
    /// is configured, the only host when omitted, else a `-32602`.
    pub(crate) fn resolve_name(&self, host: Option<&str>) -> Result<String, RpcError> {
        match host {
            Some(h) if self.targets.contains_key(h) => Ok(h.to_owned()),
            Some(h) => Err(RpcError::invalid_params(format!(
                "unknown host {h:?}; configured: {}",
                self.names.join(", ")
            ))),
            None if self.names.len() == 1 => Ok(self.names[0].clone()),
            None => Err(RpcError::invalid_params(format!(
                "host is required; configured: {}",
                self.names.join(", ")
            ))),
        }
    }

    /// The live connection for `name`, opened now if there is none or the
    /// last one was lost.
    pub(crate) async fn backend(&self, name: &str) -> Result<Arc<Backend>> {
        let mut conns = self.conns.lock().await;
        if let Some(backend) = conns.get(name) {
            if !backend.is_closed() {
                return Ok(Arc::clone(backend));
            }
            debug!(host = name, "connection lost; reconnecting");
            conns.remove(name);
        }
        let target = self
            .targets
            .get(name)
            .ok_or_else(|| anyhow!("unknown host {name:?}"))?;
        let backend = Arc::new(Backend::connect(target, &self.paths, &self.baked).await?);
        conns.insert(name.to_owned(), Arc::clone(&backend));
        Ok(backend)
    }

    /// The `hosts` tool: every configured host with its connection state.
    pub(crate) async fn list(&self) -> Value {
        let conns = self.conns.lock().await;
        let hosts: Vec<Value> = self
            .names
            .iter()
            .map(|name| {
                let target = &self.targets[name];
                let live = conns.get(name).filter(|b| !b.is_closed());
                json!({
                    "host": name,
                    "target": format!("{}:{}", target.host, target.port),
                    "connected": live.is_some(),
                    "connection": live.map(|b| serde_json::to_value(b.connection()).unwrap_or(Value::Null)),
                })
            })
            .collect();
        json!({ "hosts": hosts })
    }

    fn instructions(&self, allow_local_paths: bool, accept_new: bool) -> String {
        let default = if self.names.len() == 1 {
            format!(" `host` may be omitted: it defaults to {}.", self.names[0])
        } else {
            " Every tool takes `host`, one of those names.".to_owned()
        };
        let trust = if accept_new {
            "Unknown server keys are accepted on first use (--accept-new) and pinned in known_hosts."
        } else {
            "A host whose key is not yet in known_hosts fails with code `trust_unknown`: pin it \
             first (`mysh HOST` interactively, `mysh pair`, or restart with `--accept-new`)."
        };
        let local = if allow_local_paths {
            "`put`/`get` move files between this machine and the host."
        } else {
            "`put`/`get` are disabled (no --allow-local-paths) and fail with code `denied`."
        };
        format!(
            "mysh gives you a shell-less remote process API on these hosts: {}.{default} \
             Connections open on first use and stay up. `exec` runs a command to completion \
             (non-zero exit is a normal result); `session_*` runs something longer and reads \
             its output by byte offset; `read_file`/`write_file`/`list_dir`/`stat` are file \
             primitives; `info` says what the host is. {trust} {local} Failures come back as \
             `isError: true` with {{\"error\":{{\"code\",\"message\"}}}} using mysh's stable codes.",
            self.names.join(", ")
        )
    }
}

/// `tools/call` params.
#[derive(Debug, Deserialize)]
struct CallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

/// `resources/read` params.
#[derive(Debug, Deserialize)]
struct ReadParams {
    uri: String,
}

/// `initialize` params (the rest is ignored).
#[derive(Debug, Default, Deserialize)]
struct InitializeParams {
    #[serde(rename = "protocolVersion", default)]
    protocol_version: Option<String>,
}

fn params<T: serde::de::DeserializeOwned + Default>(params: Option<Value>) -> Result<T, RpcError> {
    match params {
        None | Some(Value::Null) => Ok(T::default()),
        Some(value) => serde_json::from_value(value)
            .map_err(|e| RpcError::invalid_params(format!("invalid params: {e}"))),
    }
}

fn required_params<T: serde::de::DeserializeOwned>(params: Option<Value>) -> Result<T, RpcError> {
    match params {
        None | Some(Value::Null) => Err(RpcError::invalid_params("invalid params: missing")),
        Some(value) => serde_json::from_value(value)
            .map_err(|e| RpcError::invalid_params(format!("invalid params: {e}"))),
    }
}

/// The server: hosts plus the flags `initialize` reports.
#[derive(Debug)]
struct Server {
    hosts: Hosts,
    accept_new: bool,
    allow_local_paths: bool,
}

impl Server {
    /// Answer one request; `None` for a notification.
    async fn handle(&self, req: Request) -> Option<Response> {
        let id = req.id.clone()?;
        let result = self.dispatch(&req.method, req.params).await;
        Some(match result {
            Ok(value) => Response::ok(id, value),
            Err(err) => Response::err(id, err),
        })
    }

    async fn dispatch(&self, method: &str, p: Option<Value>) -> Result<Value, RpcError> {
        match method {
            "initialize" => {
                let init: InitializeParams = params(p)?;
                let version = pick_version(init.protocol_version.as_deref());
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {
                        "tools": {"listChanged": false},
                        "resources": {"subscribe": false, "listChanged": false},
                    },
                    "serverInfo": {"name": "mysh", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": self.hosts.instructions(self.allow_local_paths, self.accept_new),
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => {
                let single = self.hosts.names().len() == 1;
                let tools: Vec<Value> = schema::tools(single)
                    .iter()
                    .map(schema::ToolSpec::to_json)
                    .collect();
                Ok(json!({ "tools": tools }))
            }
            "tools/call" => {
                let call: CallParams = required_params(p)?;
                tools::call(&self.hosts, &call.name, call.arguments).await
            }
            "resources/list" => Ok(resources::list(&self.hosts)),
            "resources/templates/list" => Ok(resources::templates()),
            "resources/read" => {
                let read: ReadParams = required_params(p)?;
                resources::read(&self.hosts, &read.uri).await
            }
            other => Err(RpcError::new(
                code::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        }
    }
}

/// `mysh mcp`: serve until stdin closes. Returns `Err` only for a startup
/// problem (no hosts, an unresolvable host); protocol errors are answered
/// on the wire.
pub async fn serve(args: McpArgs, config: &Config, paths: Paths, baked: Baked) -> Result<()> {
    let hosts = Hosts::new(&args, config, paths, baked)?;
    let server = Server {
        hosts,
        accept_new: args.accept_new,
        allow_local_paths: args.allow_local_paths,
    };
    let mut reader = rpc::Reader::new(tokio::io::stdin());
    let mut out = tokio::io::stdout();
    while let Some((framing, raw)) = reader.next().await? {
        let parsed = match rpc::parse(&raw) {
            Ok(parsed) => parsed,
            Err(err) => {
                rpc::write_message(&mut out, framing, &Response::err(Value::Null, err)).await?;
                continue;
            }
        };
        let mut replies = Vec::with_capacity(parsed.items.len());
        for item in parsed.items {
            match item {
                Ok(req) => {
                    if req.jsonrpc.as_deref() != Some("2.0") {
                        warn!(method = %req.method, "request without jsonrpc: \"2.0\"");
                    }
                    if let Some(reply) = server.handle(req).await {
                        replies.push(reply);
                    }
                }
                Err(err) => replies.push(Response::err(Value::Null, err)),
            }
        }
        if parsed.batch {
            if !replies.is_empty() {
                rpc::write_message(&mut out, framing, &replies).await?;
            }
        } else if let Some(reply) = replies.pop() {
            rpc::write_message(&mut out, framing, &reply).await?;
        }
    }
    debug!("stdin closed; exiting");
    Ok(())
}

/// The client's version when this server speaks it, else the newest.
fn pick_version(requested: Option<&str>) -> &'static str {
    PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|v| Some(*v) == requested)
        .unwrap_or(PROTOCOL_VERSIONS[PROTOCOL_VERSIONS.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_pick() {
        assert_eq!(pick_version(Some("2024-11-05")), "2024-11-05");
        assert_eq!(pick_version(Some("2025-03-26")), "2025-03-26");
        assert_eq!(pick_version(Some("1999-01-01")), "2025-06-18");
        assert_eq!(pick_version(None), "2025-06-18");
    }

    #[test]
    fn params_helpers() {
        let p: InitializeParams = params(None).unwrap();
        assert!(p.protocol_version.is_none());
        let p: InitializeParams =
            params(Some(json!({"protocolVersion": "x", "extra": 1}))).unwrap();
        assert_eq!(p.protocol_version.as_deref(), Some("x"));
        assert_eq!(
            required_params::<ReadParams>(None).unwrap_err().code,
            code::INVALID_PARAMS
        );
        assert_eq!(
            required_params::<ReadParams>(Some(json!({"uri": 1})))
                .unwrap_err()
                .code,
            code::INVALID_PARAMS
        );
        assert_eq!(
            required_params::<ReadParams>(Some(json!({"uri": "mysh://a/"})))
                .unwrap()
                .uri,
            "mysh://a/"
        );
    }
}
