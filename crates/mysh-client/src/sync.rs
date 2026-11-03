//! `sync [--pull] [--delete] [--dry-run] [--checksum] [-j N] SRC DST`
//! (docs/04-sessions.md "sync"): mirror one directory tree into another
//! where exactly one side is remote. The direction comes from the command
//! form (`sync LOCAL REMOTE` pushes, `sync --pull REMOTE LOCAL` pulls),
//! never from a `HOST:` prefix.
//!
//! Plan first (walk both trees, compare by size and mtime ±1 s or by
//! BLAKE2s digest), then execute with the parallel transfer machinery of
//! `files` (`-j`), then — with `--delete` — remove the destination's extras,
//! files first, directories deepest first. Symlinks are skipped with a
//! notice on the source side and count as extras on the destination.

use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use mysh_proto::file::{Attrs, FileKind};

use crate::{
    args::{GetArgs, PutArgs, SyncArgs},
    conn::Connection,
    files::{
        self, Aggregate, DEFAULT_DIR_MODE, GetCtx, PutCtx, Tally, expand_local, get_file,
        join_path, list_all, put_file, remove, run_parallel, same_content, stat,
    },
    report::Reporter,
    types::{SyncEntry, SyncPlan, SyncSummary, human},
};

/// Tolerance when comparing modification times, in seconds.
const MTIME_SLACK: i64 = 1;

/// A regular file of a tree, keyed by its path relative to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    size: u64,
    mtime: i64,
}

/// One side of a sync, relative paths only (`/`-separated, no root).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Tree {
    files: BTreeMap<String, Entry>,
    /// Directories below the root, pre-order when iterated (sorted).
    dirs: BTreeSet<String>,
    /// Symlinks and special files: never copied, deleted as extras.
    others: BTreeSet<String>,
}

/// What a run would do; `new_dirs` are created before the copies.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Plan {
    new_dirs: Vec<String>,
    copies: Vec<SyncEntry>,
    /// Extra files (and others) on the destination.
    delete_files: Vec<String>,
    /// Extra directories on the destination, deepest first.
    delete_dirs: Vec<String>,
    unchanged: u64,
    bytes: u64,
}

impl Plan {
    fn out(&self) -> SyncPlan {
        SyncPlan {
            copies: self.copies.clone(),
            deletes: self
                .delete_files
                .iter()
                .chain(&self.delete_dirs)
                .cloned()
                .collect(),
            unchanged: self.unchanged,
            bytes: self.bytes,
        }
    }
}

/// `rel` under `base` as a remote path.
fn remote_join(base: &str, rel: &str) -> String {
    join_path(base, rel)
}

/// `rel` under `dir` as a child relative path.
fn rel_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// Walk a local tree (sorted, symlinks skipped with a notice).
async fn walk_local(root: &Path, console: &dyn Reporter) -> Result<Tree> {
    let mut tree = Tree::default();
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel_dir)) = stack.pop() {
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
            let path = dir.join(&name);
            let rel = rel_join(&rel_dir, &name.to_string_lossy());
            let md = tokio::fs::symlink_metadata(&path)
                .await
                .with_context(|| format!("{}: cannot stat", path.display()))?;
            let ft = md.file_type();
            if ft.is_symlink() {
                console.notice(&format!("skipping symlink {}", path.display()));
                tree.others.insert(rel);
            } else if ft.is_dir() {
                tree.dirs.insert(rel.clone());
                subdirs.push((path, rel));
            } else if ft.is_file() {
                tree.files.insert(
                    rel,
                    Entry {
                        size: md.len(),
                        mtime: md.mtime(),
                    },
                );
            } else {
                console.notice(&format!("skipping {}: not a regular file", path.display()));
                tree.others.insert(rel);
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(tree)
}

/// Walk a remote tree with `List` pages; a missing root is an empty tree.
async fn walk_remote(
    conn: &Connection,
    root: &str,
    cwd: Option<&str>,
    console: &dyn Reporter,
) -> Result<Tree> {
    let mut tree = Tree::default();
    match stat(conn, root, cwd).await? {
        None => return Ok(tree),
        Some(Attrs {
            kind: FileKind::Dir,
            ..
        }) => {}
        Some(_) => bail!("{root}: not a directory"),
    }
    let mut stack: Vec<(String, String)> = vec![(root.to_owned(), String::new())];
    while let Some((dir, rel_dir)) = stack.pop() {
        let mut entries = list_all(conn, &dir, cwd).await?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut subdirs = Vec::new();
        for e in entries {
            let rel = rel_join(&rel_dir, &e.name);
            match e.attrs.kind {
                FileKind::File => {
                    tree.files.insert(
                        rel,
                        Entry {
                            size: e.attrs.size,
                            mtime: e.attrs.mtime,
                        },
                    );
                }
                FileKind::Dir => {
                    tree.dirs.insert(rel.clone());
                    subdirs.push((remote_join(&dir, &e.name), rel));
                }
                FileKind::Symlink { target } => {
                    console.notice(&format!(
                        "skipping symlink {} -> {target}",
                        remote_join(&dir, &e.name)
                    ));
                    tree.others.insert(rel);
                }
                FileKind::Other => {
                    console.notice(&format!(
                        "skipping {}: not a regular file",
                        remote_join(&dir, &e.name)
                    ));
                    tree.others.insert(rel);
                }
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(tree)
}

/// Why a same-size pair still differs (`--checksum`): the hashes compare
/// the local copy under `local_root` with the remote one under
/// `remote_root`, whichever side is the source.
struct Hasher<'a> {
    conn: &'a Connection,
    local_root: &'a Path,
    remote_root: &'a str,
    cwd: Option<&'a str>,
}

impl Hasher<'_> {
    async fn same(&self, rel: &str, size: u64) -> Result<bool> {
        same_content(
            self.conn,
            &self.local_root.join(rel),
            size,
            &remote_join(self.remote_root, rel),
            size,
            self.cwd,
        )
        .await
    }
}

/// Compare `src` against `dst`.
async fn plan(src: &Tree, dst: &Tree, delete: bool, hasher: Option<&Hasher<'_>>) -> Result<Plan> {
    let mut plan = Plan::default();
    for (rel, a) in &src.files {
        let reason = match dst.files.get(rel) {
            None => Some("missing"),
            Some(b) if b.size != a.size => Some("size"),
            Some(b) => match hasher {
                Some(h) => (!h.same(rel, a.size).await?).then_some("content"),
                None => ((a.mtime - b.mtime).abs() > MTIME_SLACK).then_some("mtime"),
            },
        };
        match reason {
            Some(reason) => {
                plan.bytes += a.size;
                plan.copies.push(SyncEntry {
                    path: rel.clone(),
                    size: a.size,
                    reason: reason.to_owned(),
                });
            }
            None => plan.unchanged += 1,
        }
    }
    plan.new_dirs = src.dirs.difference(&dst.dirs).cloned().collect();
    if delete {
        plan.delete_files = dst
            .files
            .keys()
            .chain(&dst.others)
            .filter(|rel| !src.files.contains_key(*rel) && !src.dirs.contains(*rel))
            .cloned()
            .collect();
        plan.delete_files.sort();
        let mut dirs: Vec<String> = dst.dirs.difference(&src.dirs).cloned().collect();
        // Deepest first: more separators sort first, ties in reverse name order.
        dirs.sort_by(|a, b| {
            let depth = |s: &String| s.matches('/').count();
            depth(b).cmp(&depth(a)).then_with(|| b.cmp(a))
        });
        plan.delete_dirs = dirs;
    }
    Ok(plan)
}

/// The dry-run listing (`--json`: a [`SyncPlan`]).
fn print_plan(console: &dyn Reporter, plan: &SyncPlan) {
    console.report(plan, || {
        use std::fmt::Write as _;
        let mut text = String::new();
        for c in &plan.copies {
            let _ = writeln!(
                text,
                "copy    {}  ({}, {})",
                c.path,
                c.reason,
                human(c.size)
            );
        }
        for d in &plan.deletes {
            let _ = writeln!(text, "delete  {d}");
        }
        let _ = writeln!(
            text,
            "{} to copy ({}), {} to delete, {} unchanged",
            plan.copies.len(),
            human(plan.bytes),
            plan.deletes.len(),
            plan.unchanged
        );
        text
    });
}

/// What [`sync`] did: the plan of a `--dry-run`, else the summary of the
/// executed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// `--dry-run`: what a run would copy and delete.
    Plan(SyncPlan),
    /// The executed run.
    Summary(SyncSummary),
}

/// `sync` entry point: [`sync`] plus its report (the dry-run listing or
/// the summary line; `--json`: the [`SyncPlan`] / [`SyncSummary`]).
/// `cwd` is the remote base for relative paths.
pub async fn run(
    conn: &Connection,
    reporter: Arc<dyn Reporter>,
    args: &SyncArgs,
    cwd: Option<&str>,
    local_cwd: &Path,
) -> Result<()> {
    let console = Arc::clone(&reporter);
    match sync(conn, reporter, args, cwd, local_cwd).await? {
        SyncOutcome::Plan(plan) => print_plan(&*console, &plan),
        SyncOutcome::Summary(out) => console.report(&out, || {
            format!(
                "{} copied, {} unchanged, {} deleted, {}, {:.1} s\n",
                out.copied,
                out.unchanged,
                out.deleted,
                human(out.bytes),
                Duration::from_millis(out.duration_ms).as_secs_f64()
            )
        }),
    }
    Ok(())
}

/// Plan and (unless `--dry-run`) execute one `sync`; notices and progress
/// go to `reporter`, the outcome comes back typed. `cwd` is the remote
/// base for relative paths.
pub async fn sync(
    conn: &Connection,
    reporter: Arc<dyn Reporter>,
    args: &SyncArgs,
    cwd: Option<&str>,
    local_cwd: &Path,
) -> Result<SyncOutcome> {
    let console: &dyn Reporter = &*reporter;
    let started = Instant::now();
    let (local_root, remote_root) = if args.pull {
        (expand_local(&args.dst, local_cwd), args.src.as_str())
    } else {
        (expand_local(&args.src, local_cwd), args.dst.as_str())
    };
    if remote_root.is_empty() {
        bail!("sync: empty remote path");
    }

    let hasher = args.checksum.then_some(Hasher {
        conn,
        local_root: &local_root,
        remote_root,
        cwd,
    });
    let plan = if args.pull {
        let src = walk_remote(conn, remote_root, cwd, console).await?;
        let dst = match tokio::fs::metadata(&local_root).await {
            Ok(md) if md.is_dir() => walk_local(&local_root, console).await?,
            Ok(_) => bail!("{}: not a directory", local_root.display()),
            Err(_) => Tree::default(),
        };
        plan(&src, &dst, args.delete, hasher.as_ref()).await?
    } else {
        let md = tokio::fs::metadata(&local_root)
            .await
            .with_context(|| format!("{}: cannot stat", local_root.display()))?;
        if !md.is_dir() {
            bail!("{}: not a directory", local_root.display());
        }
        let src = walk_local(&local_root, console).await?;
        let dst = walk_remote(conn, remote_root, cwd, console).await?;
        plan(&src, &dst, args.delete, hasher.as_ref()).await?
    };

    if args.dry_run {
        return Ok(SyncOutcome::Plan(plan.out()));
    }

    let copied = plan.copies.len() as u64;
    let tally = if args.pull {
        pull(conn, reporter, args, &plan, remote_root, &local_root, cwd).await?
    } else {
        push(conn, reporter, args, &plan, &local_root, remote_root, cwd).await?
    };
    let deleted = (plan.delete_files.len() + plan.delete_dirs.len()) as u64;
    Ok(SyncOutcome::Summary(SyncSummary {
        copied,
        deleted,
        unchanged: plan.unchanged,
        bytes: tally.bytes,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }))
}

/// Local → remote: directories, then files `-j` at a time, then extras.
async fn push(
    conn: &Connection,
    reporter: Arc<dyn Reporter>,
    args: &SyncArgs,
    plan: &Plan,
    local_root: &Path,
    remote_root: &str,
    cwd: Option<&str>,
) -> Result<Tally> {
    files::mkdir(conn, remote_root, DEFAULT_DIR_MODE, cwd).await?;
    for rel in &plan.new_dirs {
        files::mkdir(conn, &remote_join(remote_root, rel), DEFAULT_DIR_MODE, cwd).await?;
    }
    let ctx = Arc::new(PutCtx {
        conn: conn.clone(),
        console: reporter,
        args: PutArgs {
            preserve: true,
            jobs: args.concurrency(),
            ..PutArgs::default()
        },
        cwd: cwd.map(str::to_owned),
    });
    let agg = Aggregate::new(
        &ctx.console,
        files::label_of(local_root),
        plan.copies.len(),
        plan.bytes,
    );
    let mut tasks = Vec::with_capacity(plan.copies.len());
    for c in &plan.copies {
        let ctx = Arc::clone(&ctx);
        let agg = Arc::clone(&agg);
        let local = local_root.join(&c.path);
        let remote = remote_join(remote_root, &c.path);
        let size = c.size;
        tasks.push(async move {
            let meta = tokio::fs::metadata(&local)
                .await
                .with_context(|| format!("{}: cannot stat", local.display()))?;
            let mut last = 0u64;
            let mut progress = |done: u64, _total: u64| agg.advance(&mut last, done);
            let tally = put_file(&ctx, &local, &meta, &remote, true, &mut progress).await?;
            agg.file_done(last, size);
            Ok(tally)
        });
    }
    if !tasks.is_empty() {
        agg.report();
    }
    let result = run_parallel(args.concurrency(), tasks).await;
    ctx.console.progress_done();
    let tally = result?;

    for rel in &plan.delete_files {
        remove(conn, &remote_join(remote_root, rel), false, cwd).await?;
    }
    for rel in &plan.delete_dirs {
        remove(conn, &remote_join(remote_root, rel), true, cwd).await?;
    }
    Ok(tally)
}

/// Remote → local.
async fn pull(
    conn: &Connection,
    reporter: Arc<dyn Reporter>,
    args: &SyncArgs,
    plan: &Plan,
    remote_root: &str,
    local_root: &Path,
    cwd: Option<&str>,
) -> Result<Tally> {
    tokio::fs::create_dir_all(local_root)
        .await
        .with_context(|| format!("{}: cannot create directory", local_root.display()))?;
    for rel in &plan.new_dirs {
        let dir = local_root.join(rel);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("{}: cannot create directory", dir.display()))?;
    }
    let ctx = Arc::new(GetCtx {
        conn: conn.clone(),
        console: reporter,
        args: GetArgs {
            preserve: true,
            jobs: args.concurrency(),
            ..GetArgs::default()
        },
        cwd: cwd.map(str::to_owned),
    });
    let agg = Aggregate::new(
        &ctx.console,
        files::basename(remote_root)
            .unwrap_or(remote_root)
            .to_owned(),
        plan.copies.len(),
        plan.bytes,
    );
    let mut tasks = Vec::with_capacity(plan.copies.len());
    for c in &plan.copies {
        let ctx = Arc::clone(&ctx);
        let agg = Arc::clone(&agg);
        let remote = remote_join(remote_root, &c.path);
        let local = local_root.join(&c.path);
        let size = c.size;
        tasks.push(async move {
            let mut last = 0u64;
            let mut progress = |done: u64, _total: u64| agg.advance(&mut last, done);
            let tally = get_file(&ctx, &remote, &local, &mut progress).await?;
            agg.file_done(last, size);
            Ok(tally)
        });
    }
    if !tasks.is_empty() {
        agg.report();
    }
    let result = run_parallel(args.concurrency(), tasks).await;
    ctx.console.progress_done();
    let tally = result?;

    for rel in &plan.delete_files {
        let path = local_root.join(rel);
        tokio::fs::remove_file(&path)
            .await
            .with_context(|| format!("{}: cannot remove", path.display()))?;
    }
    for rel in &plan.delete_dirs {
        let path = local_root.join(rel);
        tokio::fs::remove_dir_all(&path)
            .await
            .with_context(|| format!("{}: cannot remove", path.display()))?;
    }
    Ok(tally)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, u64, i64)], dirs: &[&str]) -> Tree {
        Tree {
            files: files
                .iter()
                .map(|(p, size, mtime)| {
                    (
                        (*p).to_owned(),
                        Entry {
                            size: *size,
                            mtime: *mtime,
                        },
                    )
                })
                .collect(),
            dirs: dirs.iter().map(|d| (*d).to_owned()).collect(),
            others: BTreeSet::new(),
        }
    }

    #[tokio::test]
    async fn plan_compares_size_and_mtime() {
        let src = tree(
            &[("a", 1, 100), ("b", 2, 100), ("c", 3, 100), ("d/e", 4, 100)],
            &["d", "new"],
        );
        let dst = tree(
            &[("a", 1, 101), ("b", 9, 100), ("c", 3, 50), ("x", 1, 1)],
            &["d", "old/deep", "old"],
        );
        let p = plan(&src, &dst, true, None).await.expect("plan");
        let reasons: Vec<(&str, &str)> = p
            .copies
            .iter()
            .map(|c| (c.path.as_str(), c.reason.as_str()))
            .collect();
        assert_eq!(reasons, [("b", "size"), ("c", "mtime"), ("d/e", "missing")]);
        assert_eq!(p.unchanged, 1);
        assert_eq!(p.bytes, 2 + 3 + 4);
        assert_eq!(p.new_dirs, ["new"]);
        assert_eq!(p.delete_files, ["x"]);
        assert_eq!(p.delete_dirs, ["old/deep", "old"]);
    }

    #[tokio::test]
    async fn plan_without_delete_keeps_extras() {
        let src = tree(&[], &[]);
        let dst = tree(&[("x", 1, 1)], &["d"]);
        let p = plan(&src, &dst, false, None).await.expect("plan");
        assert!(p.delete_files.is_empty() && p.delete_dirs.is_empty());
        assert_eq!(p.out().deletes, Vec::<String>::new());
    }

    #[test]
    fn rel_join_skips_empty_dir() {
        assert_eq!(rel_join("", "a"), "a");
        assert_eq!(rel_join("a/b", "c"), "a/b/c");
    }
}
