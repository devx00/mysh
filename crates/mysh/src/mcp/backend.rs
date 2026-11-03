//! The one file that binds the MCP tools to [`mysh_client::Client`]. Every
//! tool in [`super::tools`] goes through [`Backend`]; nothing else in
//! `mcp/` names a connection or a protocol message, so a library change
//! touches this file only.
//!
//! All calls return the typed `--json` documents of `mysh_client::types`;
//! a failure keeps its stable code (re-tagged with `coded`, so
//! `code_for` finds it) and the tool layer reports
//! `{"error":{"code","message"}}`.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow};
use mysh_client::{
    Client, ExecRequest as ClientExecRequest, NullReporter, RefuseUnknown,
    session_api::{ApiSessionRow, NewArgs, NewSessionOut, ReadOut},
};
use mysh_proto::{file::Attrs, session::Signal};

use crate::{
    config::{Paths, Target},
    identity::Baked,
    output::{ConnectionOut, ExecResult, InfoOut, LsEntry, StatOut, TransferOut, coded, codes},
};

/// What the `exec` tool asks for.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExecRequest {
    /// Command and arguments; one element runs through the remote shell.
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: Option<String>,
    /// Extra environment on top of the connection's.
    pub(crate) env: Vec<(String, String)>,
    /// `--timeout` escalation (TERM, KILL, give up).
    pub(crate) timeout: Option<Duration>,
    /// Bytes for the command's stdin; it gets EOF either way.
    pub(crate) stdin: Option<Vec<u8>>,
}

/// A bounded read of a remote file.
#[derive(Debug)]
pub(crate) struct FileRead {
    pub(crate) attrs: Attrs,
    pub(crate) bytes: Vec<u8>,
}

/// One connected host.
#[derive(Debug)]
pub(crate) struct Backend {
    client: Client,
}

/// Re-tag a library error so `code_for` sees its code at the head of the
/// chain.
fn lift(err: mysh_client::Error) -> anyhow::Error {
    coded(err.code, err.into_inner())
}

impl Backend {
    /// Connect to `target` silently: no reporter output, and an unknown
    /// server key is accepted only through `target.accept_new`
    /// ([`RefuseUnknown`] answers every prompt with "no", which surfaces as
    /// `trust_unknown`).
    pub(crate) async fn connect(target: &Target, paths: &Paths, baked: &Baked) -> Result<Self> {
        let client = Client::connect(
            target,
            paths,
            baked,
            Arc::new(NullReporter),
            Arc::new(RefuseUnknown),
        )
        .await
        .map_err(lift)?;
        Ok(Self { client })
    }

    /// The connection is gone; the caller drops this backend and connects
    /// again on the next use.
    pub(crate) fn is_closed(&self) -> bool {
        !self.client.is_connected()
    }

    /// `host:port` and fingerprint facts for the `hosts` tool.
    pub(crate) fn connection(&self) -> ConnectionOut {
        self.client.connection().connection_out()
    }

    /// Run one non-PTY command to completion and collect its output.
    /// A non-zero exit is a result, not an error; a timeout reports
    /// `timed_out: true`.
    pub(crate) async fn exec(&self, req: ExecRequest) -> Result<ExecResult> {
        let req = ClientExecRequest {
            argv: req.argv,
            cwd: req.cwd,
            env: req.env,
            pty: None,
            timeout: req.timeout,
            stdin: req.stdin,
        };
        self.client.exec(req).await.map_err(lift)
    }

    /// At most `max` bytes of `path` from `offset`, with the attributes
    /// (`attrs.size` is the whole file).
    pub(crate) async fn read_file(&self, path: &str, offset: u64, max: u64) -> Result<FileRead> {
        let (attrs, bytes) = self
            .client
            .files()
            .read(path, offset, Some(max))
            .await
            .map_err(lift)?;
        Ok(FileRead { attrs, bytes })
    }

    /// Replace a file atomically (or append to it) with `bytes`; returns
    /// the bytes written.
    pub(crate) async fn write_file(
        &self,
        path: &str,
        bytes: &[u8],
        mode: Option<u32>,
        append: bool,
    ) -> Result<u64> {
        self.client
            .files()
            .write(path, bytes, mode, append)
            .await
            .map_err(lift)
    }

    /// Sorted directory listing; dot-files only with `all`.
    pub(crate) async fn list_dir(&self, path: &str, all: bool) -> Result<Vec<LsEntry>> {
        self.client.files().list(path, all).await.map_err(lift)
    }

    /// Attributes of one path; a missing path is `not_found`.
    pub(crate) async fn stat(&self, path: &str) -> Result<StatOut> {
        match self.client.files().stat(path).await.map_err(lift)? {
            Some(out) => Ok(out),
            None => Err(coded(codes::NOT_FOUND, anyhow!("{path}: no such file"))),
        }
    }

    /// Start a persistent session (`session new`); a PTY gets the API's
    /// default size.
    pub(crate) async fn session_new(
        &self,
        command: Vec<String>,
        cwd: Option<String>,
        pty: bool,
        env: Vec<(String, String)>,
    ) -> Result<NewSessionOut> {
        let args = NewArgs {
            command,
            cwd,
            pty,
            env: env.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
            size: None,
        };
        self.client.sessions().new(&args).await.map_err(lift)
    }

    /// `session send`: bytes to the session's stdin; `eof` closes it.
    pub(crate) async fn session_send(&self, id: u32, bytes: &[u8], eof: bool) -> Result<()> {
        self.client
            .sessions()
            .send(id, bytes, eof)
            .await
            .map_err(lift)
    }

    /// `session read` from an absolute offset.
    pub(crate) async fn session_read(
        &self,
        id: u32,
        offset: u64,
        max: u32,
        wait: Duration,
    ) -> Result<ReadOut> {
        self.client
            .sessions()
            .read(id, offset, max, wait)
            .await
            .map_err(lift)
    }

    /// `session kill`.
    pub(crate) async fn session_kill(&self, id: u32, signal: Signal) -> Result<()> {
        self.client.sessions().kill(id, signal).await.map_err(lift)
    }

    /// `session list`.
    pub(crate) async fn session_list(&self) -> Result<Vec<ApiSessionRow>> {
        self.client.sessions().list().await.map_err(lift)
    }

    /// Upload one local file. A `remote` that is a directory takes the
    /// local file's name, as `mysh put` does.
    pub(crate) async fn put(
        &self,
        local: &str,
        remote: &str,
        checksum: bool,
        local_cwd: &Path,
    ) -> Result<TransferOut> {
        let local = local_cwd.join(local);
        let files = self.client.files();
        let remote = match files.stat(remote).await.map_err(lift)? {
            Some(StatOut { kind, .. }) if kind == "dir" => {
                let name = local
                    .file_name()
                    .ok_or_else(|| anyhow!("{}: no file name to copy as", local.display()))?;
                join_remote(remote, &name.to_string_lossy())
            }
            _ => remote.to_owned(),
        };
        files.put(&local, &remote, checksum).await.map_err(lift)
    }

    /// Download one remote file. A `local` that is a directory takes the
    /// remote file's name.
    pub(crate) async fn get(
        &self,
        remote: &str,
        local: &str,
        local_cwd: &Path,
    ) -> Result<TransferOut> {
        let mut local: PathBuf = local_cwd.join(local);
        if local.is_dir() {
            let name = remote
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|n| !n.is_empty() && *n != "." && *n != ".." && *n != "~")
                .ok_or_else(|| anyhow!("{remote}: no file name to copy as"))?;
            local.push(name);
        }
        self.client
            .files()
            .get(remote, &local, false)
            .await
            .map_err(lift)
    }

    /// `info`: the server's facts plus this connection's.
    pub(crate) async fn info(&self) -> Result<InfoOut> {
        self.client.info().await.map_err(lift)
    }
}

/// `base/name` without doubling the separator.
fn join_remote(base: &str, name: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}
