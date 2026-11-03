//! File primitives through the real binary (docs/04-sessions.md "File
//! primitives", docs/06-roadmap.md M8): `put -`/`get -` pipes, `cat`,
//! `write [--append]`, `tail [-n] [-f]`, `stat --json`, `mkdir -p`, `rm -r`,
//! `mv`, `realpath`, `--checksum` skips, and `sync` (push, `--pull`,
//! `--delete`, `--dry-run`).

mod common;

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime},
};

use mysh::output::{InfoOut, OkOut, RealpathOut, StatOut, SyncPlan, SyncSummary, TransferOut};

/// `mysh SUB --accept-new HOST …` with the harness environment and piped
/// stdio.
fn sub(server: &common::TestServer, name: &str) -> Command {
    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .envs(common::client_env(server))
        .arg(name)
        .arg("--accept-new")
        .arg(server.host_arg())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run_with_stdin(cmd: &mut Command, stdin: &[u8]) -> Output {
    let mut child = cmd.spawn().expect("spawn mysh");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin).expect("write stdin");
    drop(pipe);
    child.wait_with_output().expect("wait")
}

fn run(cmd: &mut Command) -> Output {
    run_with_stdin(cmd, b"")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn ok(out: &Output) {
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

/// Parse stdout as exactly one JSON document of type `T`.
fn one<T: serde::de::DeserializeOwned>(out: &Output) -> T {
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("no JSON on stdout; stderr: {}", text(&out.stderr)));
    assert!(
        lines.next().is_none(),
        "more than one document on stdout: {stdout}"
    );
    serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"))
}

/// Deterministic pseudo-random bytes (xorshift64*).
fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let word = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let bytes = word.to_le_bytes();
        let take = bytes.len().min(len - out.len());
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

/// Every regular file under `root` as `relative path → content`.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let ft = entry.file_type().expect("file type");
            if ft.is_dir() {
                walk(&entry.path(), &child_rel, out);
            } else if ft.is_file() {
                out.insert(child_rel, std::fs::read(entry.path()).expect("read"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

fn local_dir(server: &common::TestServer, name: &str) -> PathBuf {
    let dir = server.dir.join(name);
    std::fs::create_dir_all(&dir).expect("local dir");
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn put_and_get_stream_through_pipes() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let blob = random_bytes(3 * 1024 * 1024, 42);

    let out = run_with_stdin(sub(&server, "put").arg("-").arg("~/blob.bin"), &blob);
    ok(&out);
    let on_server = std::fs::read(server.home.join("blob.bin")).expect("remote file");
    assert!(on_server == blob, "put - must land every byte");

    let out = run(sub(&server, "get").arg("~/blob.bin").arg("-"));
    ok(&out);
    assert!(
        out.stdout == blob,
        "get - must print every byte and nothing else"
    );

    // `--mode` and `--mtime` apply to the stdin file.
    let out = run_with_stdin(
        sub(&server, "put")
            .arg("--mode")
            .arg("600")
            .arg("--mtime")
            .arg("1700000000")
            .arg("-")
            .arg("~/secret.txt"),
        b"shh\n",
    );
    ok(&out);
    let md = std::fs::metadata(server.home.join("secret.txt")).expect("stat");
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o777,
        0o600
    );
    assert_eq!(std::os::unix::fs::MetadataExt::mtime(&md), 1_700_000_000);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cat_concatenates() {
    let server = common::start_server(common::ServerOpts::default()).await;
    std::fs::write(server.home.join("a.txt"), b"first\n").expect("write");
    std::fs::write(server.home.join("b.txt"), b"second\n").expect("write");
    let out = run(sub(&server, "cat").arg("~/a.txt").arg("~/b.txt"));
    ok(&out);
    assert_eq!(out.stdout, b"first\nsecond\n");

    let out = run(sub(&server, "cat").arg("~/missing.txt"));
    assert_eq!(out.status.code(), Some(1));
    let both = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(both.contains("missing.txt"), "{both}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn write_replaces_atomically_and_appends() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let path = server.home.join("notes.txt");
    std::fs::write(&path, b"old content that is longer\n").expect("write");

    let out = run_with_stdin(sub(&server, "write").arg("~/notes.txt"), b"new\n");
    ok(&out);
    assert_eq!(std::fs::read(&path).expect("read"), b"new\n");

    let out = run_with_stdin(
        sub(&server, "write").arg("--append").arg("~/notes.txt"),
        b"more\n",
    );
    ok(&out);
    assert_eq!(std::fs::read(&path).expect("read"), b"new\nmore\n");

    // `--append` on a missing file creates it; `--mode` applies.
    let out = run_with_stdin(
        sub(&server, "write")
            .arg("--append")
            .arg("--mode")
            .arg("640")
            .arg("~/fresh.txt"),
        b"x",
    );
    ok(&out);
    let md = std::fs::metadata(server.home.join("fresh.txt")).expect("stat");
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o777,
        0o640
    );

    // No temp file is left behind by the atomic replace.
    let leftovers: Vec<String> = std::fs::read_dir(&server.home)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("mysh-tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tail_prints_last_lines() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let lines: String = (1..=20).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "line {i}");
        s
    });
    std::fs::write(server.home.join("log.txt"), &lines).expect("write");

    let out = run(sub(&server, "tail").arg("-n").arg("3").arg("~/log.txt"));
    ok(&out);
    assert_eq!(text(&out.stdout), "line 18\nline 19\nline 20\n");

    // Default is 10 lines; a final line without newline counts.
    std::fs::write(server.home.join("short.txt"), b"a\nb\nc").expect("write");
    let out = run(sub(&server, "tail").arg("~/short.txt"));
    ok(&out);
    assert_eq!(text(&out.stdout), "a\nb\nc");

    // A file bigger than the first window still yields exactly N lines.
    let big: String = (0..20_000).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "row {i:05}");
        s
    });
    std::fs::write(server.home.join("big.txt"), &big).expect("write");
    let out = run(sub(&server, "tail").arg("-n").arg("2").arg("~/big.txt"));
    ok(&out);
    assert_eq!(text(&out.stdout), "row 19998\nrow 19999\n");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tail_follow_streams_appended_lines() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let path = server.home.join("follow.txt");
    std::fs::write(&path, b"one\ntwo\n").expect("write");

    let mut child = sub(&server, "tail")
        .arg("-f")
        .arg("~/follow.txt")
        .spawn()
        .expect("spawn tail -f");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let next = |rx: &mpsc::Receiver<String>, what: &str| -> String {
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("waiting for {what}: {e}"))
    };
    assert_eq!(next(&rx, "initial line 1"), "one");
    assert_eq!(next(&rx, "initial line 2"), "two");

    for word in ["three", "four"] {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        writeln!(f, "{word}").expect("append");
        drop(f);
        let started = Instant::now();
        let got = rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_else(|e| panic!("appended line {word} not streamed within 1 s: {e}"));
        assert_eq!(got, word);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    child.kill().expect("kill tail -f");
    let _ = child.wait();

    // `--timeout` ends a follow cleanly (exit 0, not 124).
    let started = Instant::now();
    let out = run(sub(&server, "tail")
        .arg("-f")
        .arg("--timeout")
        .arg("300ms")
        .arg("~/follow.txt"));
    ok(&out);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        text(&out.stdout).ends_with("three\nfour\n"),
        "{:?}",
        text(&out.stdout)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stat_json_parses() {
    let server = common::start_server(common::ServerOpts::default()).await;
    std::fs::write(server.home.join("s.txt"), b"12345").expect("write");
    let out = run(sub(&server, "stat").arg("--json").arg("~/s.txt"));
    ok(&out);
    let st: StatOut = one(&out);
    assert_eq!((st.kind.as_str(), st.size), ("file", 5));
    assert_eq!(st.path, "~/s.txt");

    // Several paths: an array.
    std::fs::create_dir_all(server.home.join("d")).expect("mkdir");
    let out = run(sub(&server, "stat").arg("--json").arg("~/s.txt").arg("~/d"));
    ok(&out);
    let rows: Vec<StatOut> = one(&out);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].kind, "dir");

    // A missing path is `not_found`.
    let out = run(sub(&server, "stat").arg("--json").arg("~/nope"));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("\"not_found\""),
        "{}",
        text(&out.stderr)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mkdir_rm_mv_realpath() {
    let server = common::start_server(common::ServerOpts::default()).await;

    let out = run(sub(&server, "mkdir").arg("-P").arg("~/a/b/c"));
    ok(&out);
    assert!(server.home.join("a/b/c").is_dir());
    // Existing with `-P` is fine; without it a missing parent fails
    // (`-p` is the shared port option, hence the capital).
    ok(&run(sub(&server, "mkdir").arg("-P").arg("~/a/b/c")));
    let out = run(sub(&server, "mkdir").arg("~/x/y"));
    assert_eq!(out.status.code(), Some(1));
    // A parent that is a symlink to a directory is a directory for `-P`
    // (`/tmp` -> `/private/tmp` on macOS); a link to a file is not.
    std::os::unix::fs::symlink(server.home.join("a"), server.home.join("link")).expect("symlink");
    ok(&run(sub(&server, "mkdir")
        .arg("-P")
        .arg("~/link/via-link/deeper")));
    assert!(server.home.join("a/via-link/deeper").is_dir());
    std::fs::write(server.home.join("file"), b"").expect("write");
    std::os::unix::fs::symlink(server.home.join("file"), server.home.join("filelink"))
        .expect("symlink");
    let out = run(sub(&server, "mkdir").arg("-P").arg("~/filelink/sub"));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("not a directory"),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    // `-m` sets the mode.
    ok(&run(sub(&server, "mkdir")
        .arg("-m")
        .arg("700")
        .arg("~/private")));
    let md = std::fs::metadata(server.home.join("private")).expect("stat");
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o777,
        0o700
    );

    std::fs::write(server.home.join("a/b/c/f.txt"), b"f").expect("write");
    let out = run(sub(&server, "mv").arg("~/a/b/c/f.txt").arg("~/a/g.txt"));
    ok(&out);
    assert!(server.home.join("a/g.txt").is_file());
    assert!(!server.home.join("a/b/c/f.txt").exists());

    let out = run(sub(&server, "realpath").arg("--json").arg("~/a/../a/g.txt"));
    ok(&out);
    let rp: RealpathOut = one(&out);
    let canonical = std::fs::canonicalize(server.home.join("a/g.txt")).expect("canonicalize");
    assert_eq!(rp.realpath, canonical.display().to_string());
    let out = run(sub(&server, "realpath").arg("~/a"));
    ok(&out);
    assert_eq!(
        text(&out.stdout).trim(),
        std::fs::canonicalize(server.home.join("a"))
            .expect("canonicalize")
            .display()
            .to_string()
    );

    // `rm` without `-r` refuses a non-empty directory; `-r` removes it.
    let out = run(sub(&server, "rm").arg("~/a"));
    assert_eq!(out.status.code(), Some(1));
    let out = run(sub(&server, "rm").arg("--json").arg("-r").arg("~/a"));
    ok(&out);
    let ack: OkOut = one(&out);
    assert!(ack.ok);
    assert!(!server.home.join("a").exists());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn checksum_skips_identical_files() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let local = local_dir(&server, "local");
    let size = 400_000usize;
    let data = random_bytes(size, 7);
    std::fs::write(local.join("same.bin"), &data).expect("write");
    std::fs::write(server.home.join("same.bin"), &data).expect("write");

    // One scripted connection: the transfer, then the connection's counters.
    let script = format!(
        "put --checksum {} ~/same.bin\ninfo\n",
        local.join("same.bin").display()
    );
    let out = run_with_stdin(
        Command::new(common::mysh_bin())
            .env_clear()
            .envs(common::client_env(&server))
            .arg("--accept-new")
            .arg("--json")
            .arg(server.host_arg())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        script.as_bytes(),
    );
    ok(&out);
    let stdout = text(&out.stdout);
    let mut docs = stdout.lines().filter(|l| !l.trim().is_empty());
    let transfer: TransferOut =
        serde_json::from_str(docs.next().expect("transfer document")).expect("TransferOut");
    assert_eq!(
        (transfer.files, transfer.skipped, transfer.bytes),
        (0, 1, 0)
    );
    let info: InfoOut = serde_json::from_str(docs.next().expect("info document")).expect("InfoOut");
    assert!(
        info.connection.bytes_out < size as u64 / 2,
        "the body must not have been sent: bytes_out = {}",
        info.connection.bytes_out
    );

    // A different file of the same size is transferred.
    std::fs::write(local.join("same.bin"), random_bytes(size, 8)).expect("write");
    let out = run(sub(&server, "put")
        .arg("--json")
        .arg("--checksum")
        .arg(local.join("same.bin"))
        .arg("~/same.bin"));
    ok(&out);
    let transfer: TransferOut = one(&out);
    assert_eq!((transfer.files, transfer.skipped), (1, 0));
    assert_eq!(
        std::fs::read(server.home.join("same.bin")).expect("read"),
        random_bytes(size, 8)
    );

    // `get --checksum` likewise.
    let out = run(sub(&server, "get")
        .arg("--json")
        .arg("--checksum")
        .arg("~/same.bin")
        .arg(local.join("same.bin")));
    ok(&out);
    let transfer: TransferOut = one(&out);
    assert_eq!((transfer.files, transfer.skipped), (0, 1));
    server.stop().await;
}

/// 100 files over a few subdirectories.
fn make_tree(root: &Path) {
    for i in 0..100 {
        let dir = root
            .join(format!("d{}", i % 4))
            .join(if i % 8 == 0 { "deep" } else { "" });
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(format!("f{i:03}.txt")), format!("file {i}\n")).expect("write");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_transfers_only_changes() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let local = local_dir(&server, "tree");
    make_tree(&local);

    let out = run(sub(&server, "sync")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let summary: SyncSummary = one(&out);
    assert_eq!(
        (summary.copied, summary.unchanged, summary.deleted),
        (100, 0, 0)
    );
    assert_eq!(snapshot(&local), snapshot(&server.home.join("mirror")));

    // Nothing to do the second time.
    let out = run(sub(&server, "sync")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let summary: SyncSummary = one(&out);
    assert_eq!((summary.copied, summary.unchanged), (0, 100));

    // Change three files: one grows, two keep their size but get a new
    // mtime (well outside the ±1 s slack) and new content.
    std::fs::write(local.join("d1/f001.txt"), b"file 1 but longer\n").expect("write");
    for name in ["d2/f002.txt", "d3/f003.txt"] {
        let path = local.join(name);
        let mut content = std::fs::read(&path).expect("read");
        content[0] = b'F';
        std::fs::write(&path, content).expect("write");
        let f = std::fs::File::open(&path).expect("open");
        f.set_modified(SystemTime::now() + Duration::from_secs(30))
            .expect("set mtime");
    }

    let out = run(sub(&server, "sync")
        .arg("--dry-run")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let plan: SyncPlan = one(&out);
    let mut changed: Vec<&str> = plan.copies.iter().map(|c| c.path.as_str()).collect();
    changed.sort_unstable();
    assert_eq!(changed, ["d1/f001.txt", "d2/f002.txt", "d3/f003.txt"]);
    assert_eq!(plan.unchanged, 97);
    assert_eq!(plan.deletes, Vec::<String>::new());
    assert_eq!(plan.bytes, 18 + 7 + 7);
    // Dry run changed nothing.
    assert_eq!(
        std::fs::read(server.home.join("mirror/d1/f001.txt")).expect("read"),
        b"file 1\n"
    );

    let out = run(sub(&server, "sync")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let summary: SyncSummary = one(&out);
    assert_eq!(
        (summary.copied, summary.unchanged, summary.bytes),
        (3, 97, 32)
    );
    assert_eq!(snapshot(&local), snapshot(&server.home.join("mirror")));

    // `--checksum` sees the same content as unchanged even when the mtime
    // differs, and a changed byte with an untouched mtime as `content`.
    let path = local.join("d0/f004.txt");
    let f = std::fs::File::open(&path).expect("open");
    f.set_modified(SystemTime::now() + Duration::from_secs(60))
        .expect("set mtime");
    let out = run(sub(&server, "sync")
        .arg("--dry-run")
        .arg("--checksum")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let plan: SyncPlan = one(&out);
    assert!(plan.copies.is_empty(), "{plan:?}");
    let mtime = std::fs::metadata(&path)
        .expect("stat")
        .modified()
        .expect("mtime");
    std::fs::write(&path, b"FILE 4\n").expect("write");
    std::fs::File::open(&path)
        .expect("open")
        .set_modified(mtime)
        .expect("set mtime");
    let out = run(sub(&server, "sync")
        .arg("--dry-run")
        .arg("--checksum")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let plan: SyncPlan = one(&out);
    assert_eq!(plan.copies.len(), 1);
    assert_eq!(plan.copies[0].reason, "content");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_delete_removes_extras() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let local = local_dir(&server, "tree");
    make_tree(&local);
    ok(&run(sub(&server, "sync").arg(&local).arg("~/mirror")));

    let mirror = server.home.join("mirror");
    std::fs::write(mirror.join("extra.txt"), b"x").expect("write");
    std::fs::create_dir_all(mirror.join("old/deeper")).expect("mkdir");
    std::fs::write(mirror.join("old/deeper/gone.txt"), b"y").expect("write");

    // Without `--delete` the extras stay.
    let out = run(sub(&server, "sync")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    assert!(mirror.join("extra.txt").exists());

    let out = run(sub(&server, "sync")
        .arg("--dry-run")
        .arg("--delete")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let plan: SyncPlan = one(&out);
    assert_eq!(
        plan.deletes,
        ["extra.txt", "old/deeper/gone.txt", "old/deeper", "old"]
    );

    let out = run(sub(&server, "sync")
        .arg("--delete")
        .arg("--json")
        .arg(&local)
        .arg("~/mirror"));
    ok(&out);
    let summary: SyncSummary = one(&out);
    assert_eq!(
        (summary.copied, summary.deleted, summary.unchanged),
        (0, 4, 100)
    );
    assert!(!mirror.join("extra.txt").exists());
    assert!(!mirror.join("old").exists());
    assert_eq!(snapshot(&local), snapshot(&mirror));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_pull_direction() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let remote = server.home.join("src");
    make_tree(&remote);
    let local = server.dir.join("pulled");

    let out = run(sub(&server, "sync")
        .arg("--pull")
        .arg("--json")
        .arg("~/src")
        .arg(&local));
    ok(&out);
    let summary: SyncSummary = one(&out);
    assert_eq!((summary.copied, summary.unchanged), (100, 0));
    assert_eq!(snapshot(&remote), snapshot(&local));

    // Change one remote file, add a local extra: pull copies 1 and, with
    // `--delete`, drops the extra.
    std::fs::write(remote.join("d1/f001.txt"), b"changed on the server\n").expect("write");
    std::fs::write(local.join("local-only.txt"), b"z").expect("write");
    let out = run(sub(&server, "sync")
        .arg("--pull")
        .arg("--delete")
        .arg("--json")
        .arg("~/src")
        .arg(&local));
    ok(&out);
    let summary: SyncSummary = one(&out);
    assert_eq!(
        (summary.copied, summary.deleted, summary.unchanged),
        (1, 1, 99)
    );
    assert_eq!(snapshot(&remote), snapshot(&local));

    // The human dry run lists one line per entry.
    std::fs::write(remote.join("d0/f000.txt"), b"again\n").expect("write");
    let out = run(sub(&server, "sync")
        .arg("--pull")
        .arg("--dry-run")
        .arg("~/src")
        .arg(&local));
    ok(&out);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("copy    d0/f000.txt"), "{stdout}");
    assert!(stdout.contains("1 to copy"), "{stdout}");
    server.stop().await;
}
