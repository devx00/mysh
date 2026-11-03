//! `resources/*`: one `mysh://HOST/` root per configured host, the
//! `mysh://{host}/{path}` template, and reads that go through the same
//! `read_file`/`list_dir` paths as the tools. A directory reads as a JSON
//! listing; a non-UTF-8 file as a base64 `blob`.

use base64::Engine as _;
use serde_json::{Value, json};

use super::{
    Hosts,
    rpc::{RpcError, code},
    schema::READ_FILE_MAX,
};
use crate::output::{code_for, codes};

/// URI scheme of every resource.
const SCHEME: &str = "mysh://";

/// `resources/list`.
pub(crate) fn list(hosts: &Hosts) -> Value {
    let resources: Vec<Value> = hosts
        .names()
        .iter()
        .map(|host| {
            json!({
                "uri": format!("{SCHEME}{host}/"),
                "name": host,
                "description": format!("Home directory of {host} (append a path: mysh://{host}/etc/hosts, mysh://{host}/~/notes)"),
                "mimeType": "inode/directory",
            })
        })
        .collect();
    json!({ "resources": resources })
}

/// `resources/templates/list`.
pub(crate) fn templates() -> Value {
    json!({
        "resourceTemplates": [{
            "uriTemplate": "mysh://{host}/{path}",
            "name": "mysh file",
            "description": "A file or directory on a configured host: an absolute path (mysh://HOST/etc/hosts) \
                            or one under the remote home (mysh://HOST/~/notes.txt). Directories read as a JSON \
                            listing; text files as text, other files as a base64 blob.",
        }]
    })
}

/// `mysh://HOST/path` → `(host, remote path)`. An empty path is the remote
/// home; `~/...` stays home-relative; anything else is absolute.
pub(crate) fn parse_uri(uri: &str) -> Result<(String, String), RpcError> {
    let rest = uri.strip_prefix(SCHEME).ok_or_else(|| {
        RpcError::invalid_params(format!(
            "unsupported uri {uri:?}: expected mysh://HOST/path"
        ))
    })?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() {
        return Err(RpcError::invalid_params(format!("uri {uri:?} has no host")));
    }
    let path = if path.is_empty() {
        "~".to_owned()
    } else if path.starts_with('~') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    Ok((host.to_owned(), path))
}

/// `resources/read`.
pub(crate) async fn read(hosts: &Hosts, uri: &str) -> Result<Value, RpcError> {
    let (host, path) = parse_uri(uri)?;
    let name = hosts.resolve_name(Some(&host))?;
    let backend = hosts.backend(&name).await.map_err(|e| rpc_error(&e))?;
    let stat = backend.stat(&path).await.map_err(|e| rpc_error(&e))?;
    let contents = if stat.kind == "dir" {
        let entries = backend
            .list_dir(&path, true)
            .await
            .map_err(|e| rpc_error(&e))?;
        let listing = serde_json::to_value(&entries)
            .map_err(|e| RpcError::new(code::INTERNAL, format!("serializing the listing: {e}")))?;
        json!({
            "uri": uri,
            "mimeType": "application/json",
            "text": json!({"path": path, "entries": listing}).to_string(),
        })
    } else {
        let read = backend
            .read_file(&path, 0, READ_FILE_MAX)
            .await
            .map_err(|e| rpc_error(&e))?;
        match String::from_utf8(read.bytes) {
            Ok(text) => json!({"uri": uri, "mimeType": "text/plain", "text": text}),
            Err(e) => json!({
                "uri": uri,
                "mimeType": "application/octet-stream",
                "blob": base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
            }),
        }
    };
    Ok(json!({ "contents": [contents] }))
}

/// A remote failure while reading a resource: `-32002` for a missing path,
/// else `-32603`; `data.code` carries the mysh code either way.
fn rpc_error(err: &anyhow::Error) -> RpcError {
    let mysh_code = code_for(err);
    let rpc_code = if mysh_code == codes::NOT_FOUND {
        code::RESOURCE_NOT_FOUND
    } else {
        code::INTERNAL
    };
    RpcError::new(rpc_code, format!("{err:#}")).with_data(json!({"code": mysh_code}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris() {
        assert_eq!(parse_uri("mysh://pi/").unwrap(), ("pi".into(), "~".into()));
        assert_eq!(parse_uri("mysh://pi").unwrap(), ("pi".into(), "~".into()));
        assert_eq!(
            parse_uri("mysh://pi/etc/hosts").unwrap(),
            ("pi".into(), "/etc/hosts".into())
        );
        assert_eq!(
            parse_uri("mysh://pi/~/n.txt").unwrap(),
            ("pi".into(), "~/n.txt".into())
        );
        assert_eq!(
            parse_uri("mysh://127.0.0.1:7722/tmp").unwrap(),
            ("127.0.0.1:7722".into(), "/tmp".into())
        );
        assert!(parse_uri("file:///x").is_err());
        assert!(parse_uri("mysh:///x").is_err());
    }
}
