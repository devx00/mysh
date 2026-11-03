//! File primitives beyond `put`/`get` (docs/04-sessions.md "File
//! primitives", docs/06-roadmap.md M8): `cat`, `write`, `tail [-f]`, `stat`,
//! `mkdir`, `rm`, `mv`, `realpath`, `hash` and the entry point of `sync`.
//! One [`FileCmd`] runs the same way as a CLI subcommand, at the prompt and
//! over the control socket; only the source of standard input differs.

use std::{path::Path, time::Duration};

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_net::framing::read_msg;
use mysh_proto::file::{Attrs, FileKind, FileOp, HashAlgo};
use tokio::io::AsyncReadExt as _;

use super::{
    conn::Connection,
    console::Console,
    files::{
        self, DEFAULT_DIR_MODE, DEFAULT_FILE_MODE, get_to, hash, open_file, put_from, realpath,
        stat,
    },
    sync,
};
use crate::{
    cli::{FileCmd, HashArgs, MkdirArgs, RmArgs, TailArgs, WriteArgs},
    output::{self, Bytes, DataOut, HashOut, OkOut, RealpathOut, codes},
};

/// Where `put -` and `write` take their bytes from.
#[derive(Debug, Clone, Copy)]
pub enum Input<'a> {
    /// This process's standard input, read to EOF.
    Process,
    /// The bytes that travelled with a control-socket request.
    Bytes(&'a [u8]),
}

/// First window `tail` fetches from the end of the file; quadrupled until
/// it holds `-n` lines.
const TAIL_WINDOW: u64 = 64 * 1024;

/// Run one file primitive. `cwd` is the remote base for relative paths
/// (the prompt's MRU session cwd); `input` is `None` where standard input
/// belongs to someone else (the prompt), which refuses `write`.
pub async fn run(
    conn: &Connection,
    console: &Console,
    cmd: &FileCmd,
    cwd: Option<&str>,
    local_cwd: &Path,
    input: Option<Input<'_>>,
) -> Result<()> {
    match cmd {
        FileCmd::Cat(args) => files::cat(conn, console, &args.paths, cwd).await,
        FileCmd::Write(args) => {
            let Some(input) = input else {
                bail!("write: standard input is not available here (use `mysh write HOST REMOTE`)");
            };
            write(conn, console, args, cwd, input).await
        }
        FileCmd::Tail(args) => tail(conn, console, args, cwd).await,
        FileCmd::Stat(args) => files::stat_cmd(conn, console, &args.paths, cwd).await,
        FileCmd::Mkdir(args) => mkdir(conn, console, args, cwd).await,
        FileCmd::Rm(args) => rm(conn, console, args, cwd).await,
        FileCmd::Mv(args) => {
            let op = FileOp::Rename {
                from: args.from.clone(),
                to: args.to.clone(),
            };
            open_file(conn, op, cwd)
                .await
                .map(drop)
                .map_err(|e| anyhow!(e).context(format!("mv {} {}", args.from, args.to)))?;
            console.report(&OkOut::default(), String::new);
            Ok(())
        }
        FileCmd::Realpath(args) => {
            let real = realpath(conn, &args.path, cwd).await?;
            let out = RealpathOut {
                path: args.path.clone(),
                realpath: real,
            };
            console.report(&out, || format!("{}\n", out.realpath));
            Ok(())
        }
        FileCmd::Hash(args) => hash_cmd(conn, console, args, cwd).await,
        FileCmd::Sync(args) => sync::run(conn, console, args, cwd, local_cwd).await,
    }
}

/// After streaming a body through `Console::write_bytes`: in `--json` mode
/// the collected bytes become one [`DataOut`]; otherwise they are already
/// on stdout.
pub(crate) fn finish_data(console: &Console, bytes: u64) {
    if console.mode() == output::Mode::Json {
        let (data, _) = console.take_exec_capture();
        console.report(
            &DataOut {
                data: Bytes::from(data),
                bytes,
            },
            String::new,
        );
    }
}

/// `write [--mode M] [--append] REMOTE`: standard input into one file,
/// replaced atomically, or appended (`Put { offset: size, truncate: false,
/// atomic: false }` after a `Stat`).
async fn write(
    conn: &Connection,
    console: &Console,
    args: &WriteArgs,
    cwd: Option<&str>,
    input: Input<'_>,
) -> Result<()> {
    let existing = stat(conn, &args.path, cwd).await?;
    let (offset, truncate, atomic, mode) = match (&existing, args.append) {
        (
            Some(Attrs {
                kind: FileKind::Dir,
                ..
            }),
            _,
        ) => bail!("{}: is a directory", args.path),
        (
            Some(Attrs {
                kind: FileKind::File,
                size,
                mode,
                ..
            }),
            true,
        ) => (*size, false, false, args.mode.unwrap_or(*mode)),
        (
            Some(Attrs {
                kind: FileKind::Other,
                mode,
                ..
            }),
            append,
        ) => (0, !append, false, args.mode.unwrap_or(*mode)),
        _ => (
            0,
            true,
            !args.append,
            args.mode.unwrap_or(DEFAULT_FILE_MODE),
        ),
    };
    let op = FileOp::Put {
        path: args.path.clone(),
        mode,
        mtime: None,
        offset,
        truncate,
        atomic,
    };
    let c = console.clone();
    let mut progress = move |done: u64, _total: u64| c.progress("stdin", done, None);
    let written = match input {
        Input::Process => {
            let mut stdin = tokio::io::stdin();
            put_from(conn, op, cwd, 0, &mut stdin, &mut progress).await
        }
        Input::Bytes(mut bytes) => put_from(conn, op, cwd, 0, &mut bytes, &mut progress).await,
    };
    console.progress_done();
    let written = written?;
    console.report(&OkOut::default(), || {
        format!("{}: {written} bytes written\n", args.path)
    });
    Ok(())
}

/// The last `n` lines of `data` (a final line without a newline counts),
/// and whether `data` held at least `n` whole lines.
fn last_lines(data: &[u8], n: usize) -> (&[u8], bool) {
    if n == 0 {
        return (&[], true);
    }
    let body_end = data.len() - usize::from(data.last() == Some(&b'\n'));
    let mut lines = 0;
    for i in (0..body_end).rev() {
        if data[i] == b'\n' {
            lines += 1;
            if lines == n {
                return (&data[i + 1..], true);
            }
        }
    }
    (data, false)
}

/// `tail [-n N] [-f] REMOTE`: `Stat`, fetch a window from the end, trim to
/// the last `N` lines; with `-f`, keep a `Get { follow: true }` stream open
/// from the stat'ed size and print bytes as they arrive until the caller
/// cancels this future (Ctrl-C) or `--timeout` passes.
pub async fn tail(
    conn: &Connection,
    console: &Console,
    args: &TailArgs,
    cwd: Option<&str>,
) -> Result<()> {
    let path = args.path.as_str();
    let attrs = stat(conn, path, cwd)
        .await?
        .ok_or_else(|| output::coded(codes::NOT_FOUND, anyhow!("tail {path}: not found")))?;
    if attrs.kind == FileKind::Dir {
        bail!("tail {path}: is a directory");
    }
    let size = attrs.size;
    let mut window = TAIL_WINDOW;
    let mut total = 0u64;
    loop {
        let start = size.saturating_sub(window);
        let mut data: Vec<u8> = Vec::new();
        get_to(conn, path, start, cwd, &mut data, &mut |_, _| {}).await?;
        // Bytes past the stat'ed size belong to the follow stream.
        data.truncate(usize::try_from(size - start).unwrap_or(usize::MAX));
        let (lines, enough) = last_lines(&data, args.lines);
        if enough || start == 0 {
            console.write_bytes(lines);
            total += lines.len() as u64;
            break;
        }
        window = window.saturating_mul(4);
    }
    if args.follow {
        total += follow(conn, console, path, size, cwd, args.timeout).await?;
    }
    finish_data(console, total);
    Ok(())
}

/// The streaming half of `tail -f`; returns the bytes printed.
async fn follow(
    conn: &Connection,
    console: &Console,
    path: &str,
    offset: u64,
    cwd: Option<&str>,
    timeout: Option<Duration>,
) -> Result<u64> {
    let op = FileOp::Get {
        path: path.to_owned(),
        offset,
        follow: true,
    };
    let mut stream = open_file(conn, op, cwd)
        .await
        .map_err(|e| anyhow!(e).context(format!("tail -f {path}")))?;
    let _attrs: Attrs = read_msg(&mut stream)
        .await
        .with_context(|| format!("tail -f {path}: reading attributes"))?;
    let deadline = async move {
        match timeout {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    let mut buf = vec![0u8; 64 * 1024];
    let mut printed = 0u64;
    loop {
        let n = tokio::select! {
            n = stream.read(&mut buf) => n.with_context(|| format!("tail -f {path}: reading"))?,
            () = &mut deadline => break,
        };
        if n == 0 {
            break;
        }
        console.write_bytes(&buf[..n]);
        printed += n as u64;
    }
    // Dropping the stream is what ends the server's follow loop.
    drop(stream);
    Ok(printed)
}

/// `mkdir [-p] [-m MODE] REMOTE…`; `-p` walks the components with
/// `Stat`/`Mkdir` so a missing middle is created and an existing end is
/// not an error.
async fn mkdir(
    conn: &Connection,
    console: &Console,
    args: &MkdirArgs,
    cwd: Option<&str>,
) -> Result<()> {
    let mode = args.mode.unwrap_or(DEFAULT_DIR_MODE);
    for path in &args.paths {
        if args.parents {
            for prefix in prefixes(path) {
                files::mkdir(conn, &prefix, mode, cwd).await?;
            }
        } else {
            let op = FileOp::Mkdir {
                path: path.clone(),
                mode,
            };
            open_file(conn, op, cwd)
                .await
                .map(drop)
                .map_err(|e| anyhow!(e).context(format!("mkdir {path}")))?;
        }
    }
    console.report(&OkOut::default(), String::new);
    Ok(())
}

/// Every leading directory of `path` ending with `path` itself:
/// `a/b/c` → `a`, `a/b`, `a/b/c`; `/x/y` → `/x`, `/x/y`; `~/d` → `~/d`.
fn prefixes(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut end = 0;
    for (i, c) in path.char_indices() {
        if c == '/' && i > 0 {
            let prefix = &path[..i];
            if !matches!(prefix, "~" | "." | "..") {
                out.push(prefix.to_owned());
            }
        }
        end = i + c.len_utf8();
    }
    let whole = path[..end].trim_end_matches('/');
    if !whole.is_empty() && out.last().is_none_or(|p| p != whole) {
        out.push(whole.to_owned());
    }
    out
}

/// `rm [-r] REMOTE…`.
async fn rm(conn: &Connection, console: &Console, args: &RmArgs, cwd: Option<&str>) -> Result<()> {
    for path in &args.paths {
        let op = FileOp::Remove {
            path: path.clone(),
            recursive: args.recursive,
        };
        open_file(conn, op, cwd)
            .await
            .map(drop)
            .map_err(|e| anyhow!(e).context(format!("rm {path}")))?;
    }
    console.report(&OkOut::default(), String::new);
    Ok(())
}

/// `hash REMOTE…`: `blake2s256  <hex>  <size>  <path>` per file.
async fn hash_cmd(
    conn: &Connection,
    console: &Console,
    args: &HashArgs,
    cwd: Option<&str>,
) -> Result<()> {
    let mut outs = Vec::with_capacity(args.paths.len());
    for path in &args.paths {
        let h = hash(conn, path, cwd).await?;
        let HashAlgo::Blake2s256 = h.algo;
        outs.push(HashOut {
            path: path.clone(),
            algo: "blake2s256".to_owned(),
            size: h.size,
            digest: hex(&h.digest),
        });
    }
    let human = || {
        use std::fmt::Write as _;
        outs.iter().fold(String::new(), |mut s, o| {
            let _ = writeln!(s, "{}  {}  {}  {}", o.algo, o.digest, o.size, o.path);
            s
        })
    };
    match outs.as_slice() {
        [one] => console.report(one, human),
        _ => console.report(&outs, human),
    }
    Ok(())
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_lines_counts_from_the_end() {
        let (t, enough) = last_lines(b"a\nb\nc\n", 2);
        assert_eq!((t, enough), (&b"b\nc\n"[..], true));
        let (t, enough) = last_lines(b"a\nb\nc", 2);
        assert_eq!((t, enough), (&b"b\nc"[..], true));
        let (t, enough) = last_lines(b"a\nb\n", 5);
        assert_eq!((t, enough), (&b"a\nb\n"[..], false));
        let (t, enough) = last_lines(b"", 3);
        assert_eq!((t, enough), (&b""[..], false));
        assert_eq!(last_lines(b"x\ny\n", 0), (&b""[..], true));
    }

    #[test]
    fn prefixes_walk_components() {
        assert_eq!(prefixes("a/b/c"), ["a", "a/b", "a/b/c"]);
        assert_eq!(prefixes("/x/y/"), ["/x", "/x/y"]);
        assert_eq!(prefixes("~/d/e"), ["~/d", "~/d/e"]);
        assert_eq!(prefixes("single"), ["single"]);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
    }
}
