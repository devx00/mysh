//! File transfer over `Open::File` streams (docs/03-protocol.md §9,
//! docs/04-sessions.md "File transfer"): `put`, `get`, `ls`, `authorize`.
//!
//! One stream per operation, issued sequentially. Remote paths are strings
//! resolved by the server (`~` expansion, `cwd` for relative paths); local
//! paths are expanded here (`~` → home, relative → `local_cwd`).

use std::{
    io::SeekFrom,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use mysh_net::{
    framing::read_msg,
    mux::{OpenError, Stream},
};
use mysh_proto::{
    file::{Attrs, DirEntry, FileKind, FileOp, ListPage, PutDone},
    open::{ErrorCode, Open},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    sync::Semaphore,
    task::JoinSet,
};

use super::{
    conn::Connection,
    console::{Console, human},
};
use crate::{
    cli::{GetArgs, LsArgs, PutArgs},
    config::expand_tilde,
};

/// Progress callback: `(bytes so far, total)`.
type ProgressFn<'a> = &'a mut (dyn FnMut(u64, u64) + Send);

/// Bytes per read/write on the raw body of `Get`/`Put` streams.
const CHUNK: usize = 64 * 1024;

/// Suffix of the local temporary file a `get` writes before renaming.
const TMP_SUFFIX: &str = ".mysh-tmp";

/// Mode for directories created without `-P`.
const DEFAULT_DIR_MODE: u32 = 0o755;

// ---------------------------------------------------------------------------
// Low-level file client
// ---------------------------------------------------------------------------

async fn open_file(conn: &Connection, op: FileOp, cwd: Option<&str>) -> Result<Stream, OpenError> {
    conn.open(&Open::File {
        op,
        cwd: cwd.map(str::to_owned),
    })
    .await
}

/// `Stat`; `NotFound` → `None`.
async fn stat(conn: &Connection, path: &str, cwd: Option<&str>) -> Result<Option<Attrs>> {
    let op = FileOp::Stat {
        path: path.to_owned(),
    };
    match open_file(conn, op, cwd).await {
        Ok(mut stream) => {
            let attrs: Attrs = read_msg(&mut stream)
                .await
                .with_context(|| format!("stat {path}: reading attributes"))?;
            Ok(Some(attrs))
        }
        Err(OpenError::Rejected {
            code: ErrorCode::NotFound,
            ..
        }) => Ok(None),
        Err(e) => Err(anyhow!(e).context(format!("stat {path}"))),
    }
}

/// `List`, all pages concatenated.
async fn list_all(conn: &Connection, path: &str, cwd: Option<&str>) -> Result<Vec<DirEntry>> {
    let op = FileOp::List {
        path: path.to_owned(),
    };
    let mut stream = open_file(conn, op, cwd)
        .await
        .map_err(|e| anyhow!(e).context(format!("list {path}")))?;
    let mut entries = Vec::new();
    loop {
        let page: ListPage = read_msg(&mut stream)
            .await
            .with_context(|| format!("list {path}: reading page"))?;
        entries.extend(page.entries);
        if !page.more {
            break;
        }
    }
    Ok(entries)
}

/// `Realpath`.
async fn realpath(conn: &Connection, path: &str, cwd: Option<&str>) -> Result<String> {
    let op = FileOp::Realpath {
        path: path.to_owned(),
    };
    let mut stream = open_file(conn, op, cwd)
        .await
        .map_err(|e| anyhow!(e).context(format!("realpath {path}")))?;
    read_msg(&mut stream)
        .await
        .with_context(|| format!("realpath {path}: reading reply"))
}

/// `Mkdir`, ignoring an existing directory (a `Stat` runs first so the
/// server never has to report "exists").
async fn mkdir(conn: &Connection, path: &str, mode: u32, cwd: Option<&str>) -> Result<()> {
    match stat(conn, path, cwd).await? {
        Some(Attrs {
            kind: FileKind::Dir,
            ..
        }) => return Ok(()),
        Some(_) => bail!("{path}: exists and is not a directory"),
        None => {}
    }
    let op = FileOp::Mkdir {
        path: path.to_owned(),
        mode,
    };
    open_file(conn, op, cwd)
        .await
        .map(drop)
        .map_err(|e| anyhow!(e).context(format!("mkdir {path}")))
}

/// `SetAttr`.
async fn set_attr(
    conn: &Connection,
    path: &str,
    mode: Option<u32>,
    mtime: Option<i64>,
    cwd: Option<&str>,
) -> Result<()> {
    let op = FileOp::SetAttr {
        path: path.to_owned(),
        mode,
        mtime,
    };
    open_file(conn, op, cwd)
        .await
        .map(drop)
        .map_err(|e| anyhow!(e).context(format!("setattr {path}")))
}

/// `Get { offset }`: copies the raw body into `local`; returns the remote
/// attributes and the number of bytes received. `progress` is called with
/// `(bytes so far including offset, remote size)`.
async fn get_to<W: AsyncWrite + Unpin>(
    conn: &Connection,
    remote: &str,
    offset: u64,
    cwd: Option<&str>,
    local: &mut W,
    progress: ProgressFn<'_>,
) -> Result<(Attrs, u64)> {
    let op = FileOp::Get {
        path: remote.to_owned(),
        offset,
    };
    let mut stream = open_file(conn, op, cwd)
        .await
        .map_err(|e| anyhow!(e).context(format!("get {remote}")))?;
    let attrs: Attrs = read_msg(&mut stream)
        .await
        .with_context(|| format!("get {remote}: reading attributes"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut received = 0u64;
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .with_context(|| format!("get {remote}: reading body"))?;
        if n == 0 {
            break;
        }
        local
            .write_all(&buf[..n])
            .await
            .context("writing local file")?;
        received += n as u64;
        progress(offset + received, attrs.size);
    }
    local.flush().await.context("writing local file")?;
    Ok((attrs, received))
}

/// `Put`: streams `local` as the raw body, half-closes, and returns the
/// server's `PutDone.written`. `progress` is called with `(bytes so far
/// including the op's offset, total)`.
async fn put_from<R: AsyncRead + Unpin>(
    conn: &Connection,
    op: FileOp,
    cwd: Option<&str>,
    total: u64,
    local: &mut R,
    progress: ProgressFn<'_>,
) -> Result<u64> {
    let FileOp::Put { path, offset, .. } = &op else {
        bail!("put_from needs FileOp::Put");
    };
    let remote = path.clone();
    let mut sent = *offset;
    let mut stream = open_file(conn, op, cwd)
        .await
        .map_err(|e| anyhow!(e).context(format!("put {remote}")))?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = local.read(&mut buf).await.context("reading local file")?;
        if n == 0 {
            break;
        }
        stream
            .write_all(&buf[..n])
            .await
            .with_context(|| format!("put {remote}: sending body"))?;
        sent += n as u64;
        progress(sent, total);
    }
    stream
        .shutdown()
        .await
        .with_context(|| format!("put {remote}: closing body"))?;
    let done: PutDone = read_msg(&mut stream)
        .await
        .with_context(|| format!("put {remote}: waiting for completion"))?;
    Ok(done.written)
}

// ---------------------------------------------------------------------------
// Path rules
// ---------------------------------------------------------------------------

/// Last non-empty component of a slash-separated path; `None` when there is
/// no usable name (`""`, `"/"`, `"."`, `".."`, `"~"`).
fn basename(path: &str) -> Option<&str> {
    let name = path.trim_end_matches('/').rsplit('/').next()?;
    match name {
        "" | "." | ".." | "~" => None,
        n => Some(n),
    }
}

/// `base/name` without doubling the separator.
fn join_path(base: &str, name: &str) -> String {
    if base.is_empty() || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Pair every source with its destination path (docs/04-sessions.md):
/// one source and no DEST → `default_dest/<basename>`; one source and DEST a
/// directory → `DEST/<basename>`; one source and DEST not a directory →
/// `DEST`; several sources → DEST must be a directory.
fn plan_copy(
    sources: &[String],
    dest_arg: Option<&str>,
    default_dest: &str,
    dest_is_dir: bool,
) -> Result<Vec<(String, String)>, String> {
    let base = dest_arg.unwrap_or(default_dest);
    let into_dir = dest_arg.is_none() || dest_is_dir;
    if sources.len() > 1 && !into_dir {
        return Err(format!(
            "{base}: not a directory (several sources need a directory destination)"
        ));
    }
    sources
        .iter()
        .map(|src| -> Result<(String, String), String> {
            if into_dir {
                let name =
                    basename(src).ok_or_else(|| format!("{src}: cannot determine a file name"))?;
                Ok((src.clone(), join_path(base, name)))
            } else {
                Ok((src.clone(), base.to_owned()))
            }
        })
        .collect()
}

/// `put` path rules; `default_remote` is the probed session cwd, else `~`.
fn plan_put(
    locals: &[String],
    remote_arg: Option<&str>,
    default_remote: Option<&str>,
    remote_is_dir: bool,
) -> Result<Vec<(String, String)>, String> {
    plan_copy(
        locals,
        remote_arg,
        default_remote.unwrap_or("~"),
        remote_is_dir,
    )
}

/// `get` path rules; `local_cwd` is the client's working directory.
fn plan_get(
    remotes: &[String],
    local_arg: Option<&str>,
    local_cwd: &str,
    local_is_dir: bool,
) -> Result<Vec<(String, String)>, String> {
    plan_copy(remotes, local_arg, local_cwd, local_is_dir)
}

/// `~` expansion and `local_cwd` for relative paths.
fn expand_local(path: &str, local_cwd: &Path) -> PathBuf {
    let p = expand_tilde(path, &mysh_pty::process::home_dir());
    if p.is_absolute() {
        p
    } else {
        local_cwd.join(p)
    }
}

fn split_last(paths: &[String]) -> (&[String], Option<&str>) {
    match paths {
        [] => (paths, None),
        [only] => (std::slice::from_ref(only), None),
        [init @ .., last] => (init, Some(last.as_str())),
    }
}

fn local_tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(TMP_SUFFIX);
    PathBuf::from(s)
}

fn mtime_to_system_time(mtime: i64) -> Option<SystemTime> {
    let secs = u64::try_from(mtime).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

// ---------------------------------------------------------------------------
// Transfer bookkeeping
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Totals {
    files: u64,
    bytes: u64,
    started: Option<Instant>,
}

impl Totals {
    fn new() -> Self {
        Self {
            started: Some(Instant::now()),
            ..Self::default()
        }
    }

    fn add(&mut self, bytes: u64) {
        self.files += 1;
        self.bytes += bytes;
    }

    fn add_many(&mut self, files: u64, bytes: u64) {
        self.files += files;
        self.bytes += bytes;
    }

    fn summary(&self) -> String {
        let secs = self.started.map_or(0.0, |t| t.elapsed().as_secs_f64());
        let files = if self.files == 1 { "file" } else { "files" };
        format!("{} {files}, {}, {secs:.1} s", self.files, human(self.bytes))
    }
}

fn label_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// One progress line for a whole tree: `NAME: N/M files  X/Y  P%`.
struct Aggregate {
    console: Console,
    label: String,
    files_total: usize,
    bytes_total: u64,
    files_done: AtomicUsize,
    bytes_done: AtomicU64,
}

impl Aggregate {
    fn new(console: &Console, label: String, files_total: usize, bytes_total: u64) -> Arc<Self> {
        Arc::new(Self {
            console: console.clone(),
            label,
            files_total,
            bytes_total,
            files_done: AtomicUsize::new(0),
            bytes_done: AtomicU64::new(0),
        })
    }

    fn report(&self) {
        let label = format!(
            "{}: {}/{} files",
            self.label,
            self.files_done.load(Ordering::Relaxed),
            self.files_total
        );
        self.console.progress(
            &label,
            self.bytes_done.load(Ordering::Relaxed),
            Some(self.bytes_total),
        );
    }

    /// A file reports `done` bytes so far; `last` is its previous report.
    fn advance(&self, last: &mut u64, done: u64) {
        let delta = done.saturating_sub(*last);
        *last = done;
        self.bytes_done.fetch_add(delta, Ordering::Relaxed);
        self.report();
    }

    /// A file is complete (also when skipped): count its full size.
    fn file_done(&self, last: u64, size: u64) {
        self.bytes_done
            .fetch_add(size.saturating_sub(last), Ordering::Relaxed);
        self.files_done.fetch_add(1, Ordering::Relaxed);
        self.report();
    }
}

/// Run `tasks` with at most `jobs` in flight (`JoinSet` behind a
/// semaphore). Returns the sum of their results; the first error aborts the
/// rest and is returned.
async fn run_parallel<F>(jobs: usize, tasks: Vec<F>) -> Result<u64>
where
    F: Future<Output = Result<u64>> + Send + 'static,
{
    let sem = Arc::new(Semaphore::new(jobs.max(1)));
    let mut set: JoinSet<Result<u64>> = JoinSet::new();
    let mut pending = tasks.into_iter().peekable();
    let mut total = 0u64;
    loop {
        tokio::select! {
            permit = Arc::clone(&sem).acquire_owned(), if pending.peek().is_some() => {
                let permit = permit.context("transfer semaphore closed")?;
                let Some(task) = pending.next() else { break };
                set.spawn(async move {
                    let _permit = permit;
                    task.await
                });
            }
            joined = set.join_next(), if !set.is_empty() => {
                match joined {
                    Some(Ok(Ok(n))) => total += n,
                    Some(Ok(Err(e))) => {
                        set.abort_all();
                        return Err(e);
                    }
                    Some(Err(e)) => {
                        set.abort_all();
                        bail!("transfer task failed: {e}");
                    }
                    None => {}
                }
            }
            else => break,
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------

/// Everything a `put` task needs; shared by the files of one tree.
struct PutCtx {
    conn: Connection,
    console: Console,
    args: PutArgs,
    cwd: Option<String>,
}

/// `put [-r] [-c] [-P] [-F] [-j N] LOCAL... [REMOTE]`.
pub async fn put(
    conn: &Connection,
    console: &Console,
    args: &PutArgs,
    default_remote: Option<&str>,
    local_cwd: &Path,
) -> Result<()> {
    let (locals, remote_arg) = split_last(&args.paths);
    if locals.is_empty() {
        bail!("put: no local path given");
    }

    // Resolve locals up front so that `.`/`..`/trailing-slash arguments get a
    // real basename and errors surface before any stream is opened.
    let mut resolved = Vec::with_capacity(locals.len());
    for l in locals {
        let mut p = expand_local(l, local_cwd);
        if p.file_name().is_none() {
            p = tokio::fs::canonicalize(&p)
                .await
                .with_context(|| format!("{}: cannot resolve", p.display()))?;
        }
        tokio::fs::symlink_metadata(&p)
            .await
            .with_context(|| format!("{}: cannot stat", p.display()))?;
        resolved.push(p.to_string_lossy().into_owned());
    }

    let base = remote_arg.or(default_remote).unwrap_or("~");
    let base_attrs = stat(conn, base, default_remote).await?;
    let remote_is_dir = matches!(
        base_attrs,
        Some(Attrs {
            kind: FileKind::Dir,
            ..
        })
    );
    if remote_arg.is_none() && !remote_is_dir {
        bail!("{base}: remote destination is not a directory");
    }
    let plan = plan_put(&resolved, remote_arg, default_remote, remote_is_dir)
        .map_err(|e| anyhow!("put: {e}"))?;

    let ctx = Arc::new(PutCtx {
        conn: conn.clone(),
        console: console.clone(),
        args: args.clone(),
        cwd: default_remote.map(str::to_owned),
    });
    let mut totals = Totals::new();
    // A single file onto an existing non-directory: honour "no atomic rename
    // onto devices/FIFOs" (docs/03-protocol.md §9).
    let dest_other = !remote_is_dir
        && matches!(
            base_attrs,
            Some(Attrs {
                kind: FileKind::Other,
                ..
            })
        );

    for (local, remote) in plan {
        let local = PathBuf::from(local);
        let meta = tokio::fs::symlink_metadata(&local)
            .await
            .with_context(|| format!("{}: cannot stat", local.display()))?;
        let meta = if meta.file_type().is_symlink() {
            if !args.follow_symlinks {
                console.notice(&format!(
                    "skipping symlink {} (use -F to follow)",
                    local.display()
                ));
                continue;
            }
            tokio::fs::metadata(&local)
                .await
                .with_context(|| format!("{}: cannot follow symlink", local.display()))?
        } else {
            meta
        };
        if meta.is_dir() {
            if !args.recursive {
                bail!("{}: is a directory (use -r)", local.display());
            }
            put_tree(&ctx, &local, &remote, &mut totals).await?;
        } else if meta.is_file() {
            let label = label_of(&local);
            let c = console.clone();
            let mut progress = move |done: u64, total: u64| c.progress(&label, done, Some(total));
            let result = put_file(&ctx, &local, &meta, &remote, !dest_other, &mut progress).await;
            console.progress_done();
            totals.add(result?);
        } else {
            console.notice(&format!("skipping {}: not a regular file", local.display()));
        }
    }
    console.println(&totals.summary());
    Ok(())
}

/// Upload one regular file; returns the bytes written (0 when skipped as
/// already complete). `allow_atomic` is false when the destination is known
/// to be a device or FIFO.
async fn put_file(
    ctx: &PutCtx,
    local: &Path,
    meta: &std::fs::Metadata,
    remote: &str,
    allow_atomic: bool,
    progress: ProgressFn<'_>,
) -> Result<u64> {
    let size = meta.len();
    let mode = meta.mode() & 0o7777;
    let mtime = ctx.args.preserve.then(|| meta.mtime());
    let cwd = ctx.cwd.as_deref();

    let mut offset = 0u64;
    let mut truncate = true;
    let mut atomic = allow_atomic;
    if ctx.args.continue_ {
        match stat(&ctx.conn, remote, cwd).await? {
            Some(Attrs {
                kind: FileKind::File,
                size: have,
                ..
            }) if have < size => {
                offset = have;
                truncate = false;
                atomic = false;
            }
            Some(Attrs {
                kind: FileKind::File,
                size: have,
                ..
            }) if have == size => {
                ctx.console
                    .notice(&format!("{remote}: already complete, skipped"));
                return Ok(0);
            }
            Some(Attrs {
                kind: FileKind::Dir,
                ..
            }) => bail!("{remote}: is a directory"),
            Some(Attrs {
                kind: FileKind::Other,
                ..
            }) => atomic = false,
            _ => {}
        }
    }

    let mut file = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("{}: cannot open", local.display()))?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset))
            .await
            .with_context(|| format!("{}: cannot seek", local.display()))?;
    }

    let op = FileOp::Put {
        path: remote.to_owned(),
        mode,
        mtime,
        offset,
        truncate,
        atomic,
    };
    progress(offset, size);
    put_from(&ctx.conn, op, cwd, size, &mut file, progress).await
}

/// A regular file found by the walk of a `put -r` tree.
struct PutEntry {
    local: PathBuf,
    meta: std::fs::Metadata,
    remote: String,
}

/// Walk a local tree for `put -r`: create each remote directory pre-order
/// (name order) and collect the regular files. Returns the files and the
/// directories created as `(remote, mode, mtime)` for `-P`.
async fn put_walk(
    ctx: &PutCtx,
    root: &Path,
    remote_root: &str,
) -> Result<(Vec<PutEntry>, Vec<(String, u32, i64)>)> {
    let cwd = ctx.cwd.as_deref();
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), remote_root.to_owned())];
    let mut created: Vec<(String, u32, i64)> = Vec::new();
    let mut files: Vec<PutEntry> = Vec::new();
    while let Some((dir, remote_dir)) = stack.pop() {
        let meta = tokio::fs::metadata(&dir)
            .await
            .with_context(|| format!("{}: cannot stat", dir.display()))?;
        let dir_mode = if ctx.args.preserve {
            (meta.mode() & 0o7777) | 0o700
        } else {
            DEFAULT_DIR_MODE
        };
        mkdir(&ctx.conn, &remote_dir, dir_mode, cwd).await?;
        created.push((remote_dir.clone(), meta.mode() & 0o7777, meta.mtime()));

        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("{}: cannot read directory", dir.display()))?;
        let mut names = Vec::new();
        while let Some(entry) = rd
            .next_entry()
            .await
            .with_context(|| format!("{}: reading directory", dir.display()))?
        {
            names.push(entry.file_name());
        }
        names.sort();
        let mut subdirs = Vec::new();
        for name in names {
            let local = dir.join(&name);
            let remote = join_path(&remote_dir, &name.to_string_lossy());
            let meta = tokio::fs::symlink_metadata(&local)
                .await
                .with_context(|| format!("{}: cannot stat", local.display()))?;
            let meta = if meta.file_type().is_symlink() {
                if !ctx.args.follow_symlinks {
                    ctx.console.notice(&format!(
                        "skipping symlink {} (use -F to follow)",
                        local.display()
                    ));
                    continue;
                }
                match tokio::fs::metadata(&local).await {
                    Ok(m) => m,
                    Err(e) => {
                        ctx.console
                            .notice(&format!("skipping {}: {e}", local.display()));
                        continue;
                    }
                }
            } else {
                meta
            };
            if meta.is_dir() {
                subdirs.push((local, remote));
            } else if meta.is_file() {
                files.push(PutEntry {
                    local,
                    meta,
                    remote,
                });
            } else {
                ctx.console
                    .notice(&format!("skipping {}: not a regular file", local.display()));
            }
        }
        // Push in reverse so the stack pops them in name order.
        stack.extend(subdirs.into_iter().rev());
    }
    Ok((files, created))
}

/// Upload a directory tree (`-r`): walk it first (directories created
/// pre-order, in name order), then upload the files `-j` at a time, then
/// apply directory attributes post-order (with `-P`) so that a read-only
/// mode never blocks the children.
async fn put_tree(
    ctx: &Arc<PutCtx>,
    root: &Path,
    remote_root: &str,
    totals: &mut Totals,
) -> Result<()> {
    let (files, created) = put_walk(ctx, root, remote_root).await?;
    let bytes_total: u64 = files.iter().map(|f| f.meta.len()).sum();
    let agg = Aggregate::new(&ctx.console, label_of(root), files.len(), bytes_total);
    agg.report();
    let tasks: Vec<_> = files
        .into_iter()
        .map(|entry| {
            let ctx = Arc::clone(ctx);
            let agg = Arc::clone(&agg);
            async move {
                let size = entry.meta.len();
                let mut last = 0u64;
                let mut progress = |done: u64, _total: u64| agg.advance(&mut last, done);
                let written = put_file(
                    &ctx,
                    &entry.local,
                    &entry.meta,
                    &entry.remote,
                    true,
                    &mut progress,
                )
                .await?;
                agg.file_done(last, size);
                Ok(written)
            }
        })
        .collect();
    let files_count = tasks.len() as u64;
    let result = run_parallel(ctx.args.concurrency(), tasks).await;
    ctx.console.progress_done();
    totals.add_many(files_count, result?);

    if ctx.args.preserve {
        for (remote_dir, mode, mtime) in created.into_iter().rev() {
            set_attr(
                &ctx.conn,
                &remote_dir,
                Some(mode),
                Some(mtime),
                ctx.cwd.as_deref(),
            )
            .await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// Everything a `get` task needs; shared by the files of one tree.
struct GetCtx {
    conn: Connection,
    console: Console,
    args: GetArgs,
    cwd: Option<String>,
}

/// `get [-r] [-c] [-P] [-j N] REMOTE... [LOCAL]`.
pub async fn get(
    conn: &Connection,
    console: &Console,
    args: &GetArgs,
    default_remote: Option<&str>,
    local_cwd: &Path,
) -> Result<()> {
    let (remotes, local_arg) = split_last(&args.paths);
    if remotes.is_empty() {
        bail!("get: no remote path given");
    }

    // Remotes without a usable basename (`~`, `.`) are resolved server-side.
    let mut resolved = Vec::with_capacity(remotes.len());
    for r in remotes {
        if basename(r).is_none() {
            resolved.push(realpath(conn, r, default_remote).await?);
        } else {
            resolved.push(r.clone());
        }
    }

    let local_base = local_arg.map(|l| expand_local(l, local_cwd));
    let local_is_dir = match &local_base {
        Some(p) => tokio::fs::metadata(p).await.is_ok_and(|m| m.is_dir()),
        None => true,
    };
    let local_base_str = local_base
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let plan = plan_get(
        &resolved,
        local_base_str.as_deref(),
        &local_cwd.to_string_lossy(),
        local_is_dir,
    )
    .map_err(|e| anyhow!("get: {e}"))?;

    let ctx = Arc::new(GetCtx {
        conn: conn.clone(),
        console: console.clone(),
        args: args.clone(),
        cwd: default_remote.map(str::to_owned),
    });
    let mut totals = Totals::new();
    for (remote, local) in plan {
        let local = PathBuf::from(local);
        let attrs = stat(conn, &remote, default_remote)
            .await?
            .ok_or_else(|| anyhow!("{remote}: not found"))?;
        match attrs.kind {
            FileKind::File => {
                let label = label_of(&local);
                let c = console.clone();
                let mut progress =
                    move |done: u64, total: u64| c.progress(&label, done, Some(total));
                let result = get_file(&ctx, &remote, &local, &mut progress).await;
                console.progress_done();
                totals.add(result?);
            }
            FileKind::Dir => {
                if !args.recursive {
                    bail!("{remote}: is a directory (use -r)");
                }
                get_tree(&ctx, &remote, &local, &mut totals).await?;
            }
            FileKind::Symlink { target } => {
                console.notice(&format!("skipping symlink {remote} -> {target}"));
            }
            FileKind::Other => console.notice(&format!("skipping {remote}: not a regular file")),
        }
    }
    console.println(&totals.summary());
    Ok(())
}

/// Download one regular file to `local` (temp file + rename, or append when
/// resuming with `-c`); returns the bytes received.
async fn get_file(
    ctx: &GetCtx,
    remote: &str,
    local: &Path,
    progress: ProgressFn<'_>,
) -> Result<u64> {
    let existing = if ctx.args.continue_ {
        tokio::fs::metadata(local)
            .await
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map(|m| m.len())
    } else {
        None
    };
    let resume = existing.is_some_and(|len| len > 0);
    let offset = existing.unwrap_or(0);

    let path = if resume {
        local.to_path_buf()
    } else {
        local_tmp_path(local)
    };
    let mut file = if resume {
        tokio::fs::OpenOptions::new().append(true).open(&path).await
    } else {
        tokio::fs::File::create(&path).await
    }
    .with_context(|| format!("{}: cannot open for writing", path.display()))?;

    let result = get_to(
        &ctx.conn,
        remote,
        offset,
        ctx.cwd.as_deref(),
        &mut file,
        progress,
    )
    .await;
    let (attrs, received) = match result {
        Ok(v) => v,
        Err(e) => {
            if !resume {
                let _ = tokio::fs::remove_file(&path).await;
            }
            return Err(e);
        }
    };
    if attrs.kind != FileKind::File {
        if !resume {
            let _ = tokio::fs::remove_file(&path).await;
        }
        bail!("{remote}: not a regular file");
    }
    if offset > attrs.size {
        bail!(
            "{remote}: local file ({offset} bytes) is larger than the remote ({} bytes); remove it to re-download",
            attrs.size
        );
    }

    if ctx.args.preserve {
        let std_file = file.into_std().await;
        std_file
            .set_permissions(std::fs::Permissions::from_mode(attrs.mode & 0o7777))
            .with_context(|| format!("{}: cannot set mode", path.display()))?;
        if let Some(t) = mtime_to_system_time(attrs.mtime) {
            std_file
                .set_modified(t)
                .with_context(|| format!("{}: cannot set mtime", path.display()))?;
        }
    } else {
        drop(file);
    }
    if !resume {
        tokio::fs::rename(&path, local)
            .await
            .with_context(|| format!("{}: cannot rename into place", path.display()))?;
    }
    Ok(received)
}

/// A regular file found by the walk of a `get -r` tree.
struct GetEntry {
    remote: String,
    local: PathBuf,
    size: u64,
}

/// Download a directory tree (`-r`): list it first (local directories
/// created pre-order, in name order), then download the files `-j` at a
/// time, then apply directory attributes post-order (with `-P`).
async fn get_tree(
    ctx: &Arc<GetCtx>,
    remote_root: &str,
    local_root: &Path,
    totals: &mut Totals,
) -> Result<()> {
    let cwd = ctx.cwd.as_deref();
    let mut stack: Vec<(String, PathBuf)> =
        vec![(remote_root.to_owned(), local_root.to_path_buf())];
    let mut created: Vec<(PathBuf, u32, i64)> = Vec::new();
    let mut files: Vec<GetEntry> = Vec::new();
    while let Some((remote_dir, local_dir)) = stack.pop() {
        tokio::fs::create_dir_all(&local_dir)
            .await
            .with_context(|| format!("{}: cannot create directory", local_dir.display()))?;
        if ctx.args.preserve {
            let attrs = stat(&ctx.conn, &remote_dir, cwd)
                .await?
                .ok_or_else(|| anyhow!("{remote_dir}: vanished during transfer"))?;
            created.push((local_dir.clone(), attrs.mode & 0o7777, attrs.mtime));
        }
        let mut entries = list_all(&ctx.conn, &remote_dir, cwd).await?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut subdirs = Vec::new();
        for entry in entries {
            let remote = join_path(&remote_dir, &entry.name);
            let local = local_dir.join(&entry.name);
            match entry.attrs.kind {
                FileKind::File => files.push(GetEntry {
                    remote,
                    local,
                    size: entry.attrs.size,
                }),
                FileKind::Dir => subdirs.push((remote, local)),
                FileKind::Symlink { target } => {
                    ctx.console
                        .notice(&format!("skipping symlink {remote} -> {target}"));
                }
                FileKind::Other => ctx
                    .console
                    .notice(&format!("skipping {remote}: not a regular file")),
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }

    let bytes_total: u64 = files.iter().map(|f| f.size).sum();
    let agg = Aggregate::new(
        &ctx.console,
        basename(remote_root).unwrap_or(remote_root).to_owned(),
        files.len(),
        bytes_total,
    );
    agg.report();
    let tasks: Vec<_> = files
        .into_iter()
        .map(|entry| {
            let ctx = Arc::clone(ctx);
            let agg = Arc::clone(&agg);
            async move {
                let mut last = 0u64;
                let mut progress = |done: u64, _total: u64| agg.advance(&mut last, done);
                let received = get_file(&ctx, &entry.remote, &entry.local, &mut progress).await?;
                agg.file_done(last, entry.size);
                Ok(received)
            }
        })
        .collect();
    let files_count = tasks.len() as u64;
    let result = run_parallel(ctx.args.concurrency(), tasks).await;
    ctx.console.progress_done();
    totals.add_many(files_count, result?);

    for (dir, mode, mtime) in created.into_iter().rev() {
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
            .await
            .with_context(|| format!("{}: cannot set mode", dir.display()))?;
        if let Some(t) = mtime_to_system_time(mtime) {
            let f = std::fs::File::open(&dir)
                .with_context(|| format!("{}: cannot open", dir.display()))?;
            f.set_modified(t)
                .with_context(|| format!("{}: cannot set mtime", dir.display()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

/// `st_mode`-style type bits for an [`Attrs`] (the wire carries only the
/// permission bits plus a kind).
fn mode_bits(kind: &FileKind, mode: u32) -> u32 {
    let ty = match kind {
        FileKind::File => 0o100_000,
        FileKind::Dir => 0o040_000,
        FileKind::Symlink { .. } => 0o120_000,
        FileKind::Other => 0,
    };
    ty | (mode & 0o7777)
}

/// `ls -l` mode string from a full `st_mode` (`0o100644` → `-rw-r--r--`).
fn format_mode(mode: u32) -> String {
    let ty = match mode & 0o170_000 {
        0o100_000 => '-',
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(ty);
    s.extend(perm_triple(mode, 6, 0o4000, 's', 'S'));
    s.extend(perm_triple(mode, 3, 0o2000, 's', 'S'));
    s.extend(perm_triple(mode, 0, 0o1000, 't', 'T'));
    s
}

/// `rwx` triple for the permission bits at `shift` (6 = owner, 3 = group,
/// 0 = other); `special` is the setuid/setgid/sticky bit shown in the `x`
/// slot as `set`/`unset`.
fn perm_triple(mode: u32, shift: u32, special: u32, set: char, unset: char) -> [char; 3] {
    let bit = |mask: u32| mode & (mask << shift) != 0;
    [
        if bit(0o4) { 'r' } else { '-' },
        if bit(0o2) { 'w' } else { '-' },
        match (bit(0o1), mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        },
    ]
}

/// Proleptic Gregorian civil date from days since 1970-01-01 (UTC).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// `YYYY-MM-DD HH:MM` in UTC.
fn format_mtime(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn format_long(entries: &[DirEntry]) -> Vec<String> {
    let width = entries
        .iter()
        .map(|e| e.attrs.size.to_string().len())
        .max()
        .unwrap_or(1);
    entries
        .iter()
        .map(|e| {
            let a = &e.attrs;
            let mut line = format!(
                "{} {:>width$} {} {}",
                format_mode(mode_bits(&a.kind, a.mode)),
                a.size,
                format_mtime(a.mtime),
                e.name,
            );
            if let FileKind::Symlink { target } = &a.kind {
                line.push_str(" -> ");
                line.push_str(target);
            }
            line
        })
        .collect()
}

/// `ls [-l] [-a] [REMOTE]`.
pub async fn ls(
    conn: &Connection,
    console: &Console,
    args: &LsArgs,
    default_remote: Option<&str>,
) -> Result<()> {
    let path = args.path.as_deref().or(default_remote).unwrap_or("~");
    let mut entries = list_all(conn, path, default_remote).await?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    if !args.all {
        entries.retain(|e| !e.name.starts_with('.'));
    }
    let lines = if args.long {
        format_long(&entries)
    } else {
        entries
            .into_iter()
            .map(|e| {
                if matches!(e.attrs.kind, FileKind::Dir) {
                    format!("{}/", e.name)
                } else {
                    e.name
                }
            })
            .collect()
    };
    for line in lines {
        console.println(&line);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------

const REMOTE_CONFIG_DIR: &str = "~/.config";
const REMOTE_MYSH_DIR: &str = "~/.config/mysh";
const REMOTE_AUTHORIZED_KEYS: &str = "~/.config/mysh/authorized_keys";

/// Second whitespace-separated token of a public key line (the key itself).
fn key_token(line: &str) -> Option<&str> {
    line.split_whitespace().nth(1)
}

/// Whether `authorized_keys` text already lists `key` (second token of any
/// non-comment line).
fn contains_key(text: &str, key: &str) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| key_token(l) == Some(key))
}

/// `existing` with `line` appended on its own line.
fn append_line(existing: &[u8], line: &str) -> Vec<u8> {
    let mut out = existing.to_vec();
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    out
}

/// Append `pubkey_line` to the server's `~/.config/mysh/authorized_keys`
/// unless the key is already present (the `ssh-copy-id` equivalent).
pub async fn authorize(conn: &Connection, console: &Console, pubkey_line: &str) -> Result<()> {
    let line = pubkey_line.trim();
    let key = key_token(line)
        .ok_or_else(|| anyhow!("malformed public key line: expected `TYPE KEY [COMMENT]`"))?;

    mkdir(conn, REMOTE_CONFIG_DIR, DEFAULT_DIR_MODE, None).await?;
    mkdir(conn, REMOTE_MYSH_DIR, 0o700, None).await?;

    let mut existing: Vec<u8> = Vec::new();
    let mut no_progress = |_: u64, _: u64| {};
    match stat(conn, REMOTE_AUTHORIZED_KEYS, None).await? {
        None => {}
        Some(Attrs {
            kind: FileKind::Dir,
            ..
        }) => bail!("{REMOTE_AUTHORIZED_KEYS}: is a directory"),
        Some(_) => {
            get_to(
                conn,
                REMOTE_AUTHORIZED_KEYS,
                0,
                None,
                &mut existing,
                &mut no_progress,
            )
            .await?;
        }
    }

    if contains_key(&String::from_utf8_lossy(&existing), key) {
        console.println("already present");
        return Ok(());
    }

    let content = append_line(&existing, line);
    let op = FileOp::Put {
        path: REMOTE_AUTHORIZED_KEYS.to_owned(),
        mode: 0o600,
        mtime: None,
        offset: 0,
        truncate: true,
        atomic: true,
    };
    let mut body: &[u8] = &content;
    put_from(
        conn,
        op,
        None,
        content.len() as u64,
        &mut body,
        &mut no_progress,
    )
    .await?;
    console.println("added");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn basename_rules() {
        assert_eq!(basename("a/b/c.txt"), Some("c.txt"));
        assert_eq!(basename("dir/"), Some("dir"));
        assert_eq!(basename("plain"), Some("plain"));
        assert_eq!(basename("/"), None);
        assert_eq!(basename("."), None);
        assert_eq!(basename("~"), None);
        assert_eq!(basename("~/x"), Some("x"));
        assert_eq!(basename(""), None);
    }

    #[test]
    fn join_path_rules() {
        assert_eq!(join_path("~", "f"), "~/f");
        assert_eq!(join_path("/tmp/", "f"), "/tmp/f");
        assert_eq!(join_path("", "f"), "f");
    }

    #[test]
    fn plan_put_single_no_remote_uses_default_or_home() {
        let plan = plan_put(&s(&["/l/a.txt"]), None, Some("/srv/cwd"), true).unwrap();
        assert_eq!(
            plan,
            vec![("/l/a.txt".to_owned(), "/srv/cwd/a.txt".to_owned())]
        );
        let plan = plan_put(&s(&["/l/a.txt"]), None, None, true).unwrap();
        assert_eq!(plan, vec![("/l/a.txt".to_owned(), "~/a.txt".to_owned())]);
    }

    #[test]
    fn plan_put_single_into_dir_or_onto_file() {
        let plan = plan_put(&s(&["a.txt"]), Some("/dst"), None, true).unwrap();
        assert_eq!(plan[0].1, "/dst/a.txt");
        let plan = plan_put(&s(&["a.txt"]), Some("/dst/renamed.txt"), None, false).unwrap();
        assert_eq!(plan[0].1, "/dst/renamed.txt");
    }

    #[test]
    fn plan_put_several_needs_dir() {
        let plan = plan_put(&s(&["a", "b/c"]), Some("/dst"), None, true).unwrap();
        assert_eq!(
            plan,
            vec![
                ("a".to_owned(), "/dst/a".to_owned()),
                ("b/c".to_owned(), "/dst/c".to_owned())
            ]
        );
        assert!(plan_put(&s(&["a", "b"]), Some("/dst/file"), None, false).is_err());
    }

    #[test]
    fn plan_put_rejects_nameless_source_into_dir() {
        assert!(plan_put(&s(&["."]), Some("/dst"), None, true).is_err());
        // Onto a non-directory the source name is irrelevant.
        assert!(plan_put(&s(&["."]), Some("/dst/x"), None, false).is_ok());
    }

    #[test]
    fn plan_get_mirrors_put() {
        let plan = plan_get(&s(&["~/r.txt"]), None, "/home/me", true).unwrap();
        assert_eq!(plan[0].1, "/home/me/r.txt");
        let plan = plan_get(&s(&["/a", "/b"]), Some("/local/dir"), "/home/me", true).unwrap();
        assert_eq!(plan[1].1, "/local/dir/b");
        assert!(plan_get(&s(&["/a", "/b"]), Some("/local/file"), "/home/me", false).is_err());
    }

    #[test]
    fn split_last_rules() {
        let p = s(&["a"]);
        assert_eq!(split_last(&p), (&p[..], None));
        let p = s(&["a", "b", "c"]);
        assert_eq!(split_last(&p), (&p[..2], Some("c")));
    }

    #[test]
    fn mode_strings() {
        assert_eq!(format_mode(0o100_644), "-rw-r--r--");
        assert_eq!(format_mode(0o040_755), "drwxr-xr-x");
        assert_eq!(format_mode(0o120_777), "lrwxrwxrwx");
        assert_eq!(format_mode(0o104_755), "-rwsr-xr-x");
        assert_eq!(format_mode(0o104_655), "-rwSr-xr-x");
        assert_eq!(format_mode(0o041_777), "drwxrwxrwt");
        assert_eq!(format_mode(0o020_600), "crw-------");
        assert_eq!(format_mode(0o600), "?rw-------");
        assert_eq!(format_mode(mode_bits(&FileKind::Dir, 0o700)), "drwx------");
        assert_eq!(
            format_mode(mode_bits(&FileKind::Other, 0o644)),
            "?rw-r--r--"
        );
    }

    #[test]
    fn mtime_formatting() {
        assert_eq!(format_mtime(0), "1970-01-01 00:00");
        assert_eq!(format_mtime(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(format_mtime(951_782_400), "2000-02-29 00:00");
        assert_eq!(format_mtime(-86_400), "1969-12-31 00:00");
    }

    #[test]
    fn long_listing_format() {
        let entries = vec![
            DirEntry {
                name: "a".to_owned(),
                attrs: Attrs {
                    kind: FileKind::File,
                    size: 5,
                    mode: 0o644,
                    mtime: 0,
                    uid: 0,
                    gid: 0,
                },
            },
            DirEntry {
                name: "link".to_owned(),
                attrs: Attrs {
                    kind: FileKind::Symlink {
                        target: "a".to_owned(),
                    },
                    size: 12_345,
                    mode: 0o777,
                    mtime: 0,
                    uid: 0,
                    gid: 0,
                },
            },
        ];
        let lines = format_long(&entries);
        assert_eq!(lines[0], "-rw-r--r--     5 1970-01-01 00:00 a");
        assert_eq!(lines[1], "lrwxrwxrwx 12345 1970-01-01 00:00 link -> a");
    }

    #[test]
    fn authorized_keys_helpers() {
        let text = "# comment\nmysh-x25519 AAAA me@host\n\nssh-ed25519 BBBB other\n";
        assert!(contains_key(text, "AAAA"));
        assert!(contains_key(text, "BBBB"));
        assert!(!contains_key(text, "CCCC"));
        assert_eq!(key_token("mysh-x25519 AAAA"), Some("AAAA"));
        assert_eq!(key_token("single"), None);
        assert_eq!(append_line(b"", "t k"), b"t k\n");
        assert_eq!(append_line(b"a b\n", "t k"), b"a b\nt k\n");
        assert_eq!(append_line(b"a b", "t k"), b"a b\nt k\n");
    }

    #[test]
    fn tmp_path_and_mtime_conversion() {
        assert_eq!(
            local_tmp_path(Path::new("/x/y.bin")),
            PathBuf::from("/x/y.bin.mysh-tmp")
        );
        assert_eq!(mtime_to_system_time(0), Some(SystemTime::UNIX_EPOCH));
        assert_eq!(mtime_to_system_time(-1), None);
    }

    #[test]
    fn expand_local_rules() {
        assert_eq!(
            expand_local("/abs", Path::new("/cwd")),
            PathBuf::from("/abs")
        );
        assert_eq!(
            expand_local("rel/x", Path::new("/cwd")),
            PathBuf::from("/cwd/rel/x")
        );
        assert!(expand_local("~/x", Path::new("/cwd")).is_absolute());
    }
}
