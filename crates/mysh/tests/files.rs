//! File transfer (docs/04-sessions.md "File transfer", docs/06-roadmap.md
//! M3): `put`/`get`/`authorize` through the library API against an
//! in-process server, plus the raw `List`/`Stat` protocol.

mod common;

use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use common::{ServerOpts, TestServer};
use mysh::{
    cli::{ConnectOpts, Feature, GetArgs, PutArgs},
    client::{
        conn::Connection,
        console::Console,
        files::{authorize, get, put},
    },
};
use mysh_net::{framing::read_msg, keys::SecretKey};
use mysh_proto::{
    file::{Attrs, FileKind, FileOp, ListPage},
    open::Open,
};

/// Deterministic pseudo-random bytes (xorshift64*), seeded per call so that
/// different sizes produce different content.
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

struct Ctx {
    server: TestServer,
    conn: Connection,
    console: Console,
    /// Scratch directory on the client side.
    local: PathBuf,
}

async fn setup(opts: ServerOpts) -> Ctx {
    let server = common::start_server(opts).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let local = server.dir.join("local");
    std::fs::create_dir_all(&local).expect("local scratch dir");
    Ctx {
        server,
        conn,
        console: Console::new(),
        local,
    }
}

impl Ctx {
    async fn put(&self, args: PutArgs) -> anyhow::Result<()> {
        put(
            &self.conn,
            Arc::new(self.console.clone()),
            &args,
            None,
            &self.local,
        )
        .await
    }

    async fn get(&self, args: GetArgs) -> anyhow::Result<()> {
        get(
            &self.conn,
            Arc::new(self.console.clone()),
            &args,
            None,
            &self.local,
        )
        .await
    }

    async fn finish(self) {
        self.conn.close().await;
        self.server.stop().await;
    }
}

fn args(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|&p| p.to_owned()).collect()
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[tokio::test]
async fn round_trip_sizes() {
    let ctx = setup(ServerOpts::default()).await;
    for (i, size) in [0usize, 1, 65_535, 65_536, 300_000, 3_000_000]
        .into_iter()
        .enumerate()
    {
        let data = random_bytes(size, i as u64 + 1);
        let local_in = ctx.local.join(format!("in{size}"));
        let local_out = ctx.local.join(format!("out{size}"));
        std::fs::write(&local_in, &data).expect("write local");
        let remote = format!("~/f{size}");
        ctx.put(PutArgs {
            paths: vec![path_str(&local_in), remote.clone()],
            ..Default::default()
        })
        .await
        .unwrap_or_else(|e| panic!("put {size}: {e:#}"));
        let on_server =
            std::fs::read(ctx.server.home.join(format!("f{size}"))).expect("remote file exists");
        assert_eq!(on_server.len(), size, "remote size for {size}");
        assert!(on_server == data, "remote content for {size}");

        ctx.get(GetArgs {
            paths: vec![remote, path_str(&local_out)],
            ..Default::default()
        })
        .await
        .unwrap_or_else(|e| panic!("get {size}: {e:#}"));
        let back = std::fs::read(&local_out).expect("read local out");
        assert_eq!(back.len(), size, "fetched size for {size}");
        assert!(back == data, "fetched content for {size}");
    }
    ctx.finish().await;
}

#[tokio::test]
async fn put_resume_at_offset() {
    let ctx = setup(ServerOpts::default()).await;
    let data = random_bytes(200_000, 7);
    let local = ctx.local.join("whole");
    std::fs::write(&local, &data).expect("write local");
    let remote = ctx.server.home.join("part");
    std::fs::write(&remote, &data[..120_000]).expect("write partial remote");
    let before = std::fs::metadata(&remote).expect("stat remote");
    assert_eq!(before.len(), 120_000);

    ctx.put(PutArgs {
        continue_: true,
        paths: vec![path_str(&local), path_str(&remote)],
        ..Default::default()
    })
    .await
    .expect("resume put");
    let after = std::fs::metadata(&remote).expect("stat remote");
    assert_eq!(after.len(), 200_000);
    // The tail was appended in place: no atomic temp+rename replaced the
    // inode that held the first 120_000 bytes.
    assert_eq!(after.ino(), before.ino(), "resume must append in place");
    let got = std::fs::read(&remote).expect("read remote");
    assert!(got == data, "remote content after resume");

    // A second resume of a complete file is a no-op (notice only).
    ctx.put(PutArgs {
        continue_: true,
        paths: vec![path_str(&local), path_str(&remote)],
        ..Default::default()
    })
    .await
    .expect("resume of complete file");
    let again = std::fs::metadata(&remote).expect("stat remote");
    assert_eq!(again.len(), 200_000);
    assert_eq!(again.ino(), before.ino());
    ctx.finish().await;
}

#[tokio::test]
async fn get_resume_at_offset() {
    let ctx = setup(ServerOpts::default()).await;
    let data = random_bytes(200_000, 11);
    let remote = ctx.server.home.join("big");
    std::fs::write(&remote, &data).expect("write remote");
    let local = ctx.local.join("partial");
    std::fs::write(&local, &data[..50_000]).expect("write partial local");

    ctx.get(GetArgs {
        continue_: true,
        paths: vec![path_str(&remote), path_str(&local)],
        ..Default::default()
    })
    .await
    .expect("resume get");
    let got = std::fs::read(&local).expect("read local");
    assert_eq!(got.len(), 200_000);
    assert!(got == data, "local content after resume");
    assert!(
        !ctx.local.join("partial.mysh-tmp").exists(),
        "resume must not leave a temp file"
    );
    ctx.finish().await;
}

#[tokio::test]
async fn preserve_mode_and_mtime() {
    let ctx = setup(ServerOpts::default()).await;
    let local = ctx.local.join("modes");
    std::fs::write(&local, b"hello").expect("write local");
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    std::fs::File::options()
        .write(true)
        .open(&local)
        .expect("open local")
        .set_times(std::fs::FileTimes::new().set_modified(past))
        .expect("set mtime");

    ctx.put(PutArgs {
        preserve: true,
        paths: vec![path_str(&local), "~/modes".to_owned()],
        ..Default::default()
    })
    .await
    .expect("put -P");
    let md = std::fs::metadata(ctx.server.home.join("modes")).expect("stat remote");
    assert_eq!(md.mode() & 0o7777, 0o640, "remote mode preserved");
    assert_eq!(md.mtime(), 1_000_000_000, "remote mtime preserved");

    // Without -P the mode is still sent (as the local mode) but the mtime is
    // "now".
    ctx.put(PutArgs {
        paths: vec![path_str(&local), "~/modes2".to_owned()],
        ..Default::default()
    })
    .await
    .expect("put");
    let md2 = std::fs::metadata(ctx.server.home.join("modes2")).expect("stat remote");
    assert!(
        md2.mtime() > 1_000_000_000,
        "mtime not preserved without -P"
    );

    let remote = ctx.server.home.join("secret");
    std::fs::write(&remote, b"shh").expect("write remote");
    std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    std::fs::File::options()
        .write(true)
        .open(&remote)
        .expect("open remote")
        .set_times(std::fs::FileTimes::new().set_modified(past))
        .expect("set mtime");
    let fetched = ctx.local.join("secret");
    ctx.get(GetArgs {
        preserve: true,
        paths: vec!["~/secret".to_owned(), path_str(&fetched)],
        ..Default::default()
    })
    .await
    .expect("get -P");
    let md = std::fs::metadata(&fetched).expect("stat local");
    assert_eq!(md.mode() & 0o7777, 0o600, "local mode preserved");
    assert_eq!(md.mtime(), 1_000_000_000, "local mtime preserved");
    ctx.finish().await;
}

#[tokio::test]
async fn recursive_put_and_get_with_symlinks() {
    let ctx = setup(ServerOpts::default()).await;
    let tree = ctx.local.join("tree");
    std::fs::create_dir_all(tree.join("sub")).expect("mkdir");
    std::fs::write(tree.join("a.txt"), b"alpha").expect("a");
    std::fs::write(tree.join("sub/b.txt"), b"beta").expect("b");
    std::os::unix::fs::symlink("a.txt", tree.join("link")).expect("link");
    std::os::unix::fs::symlink("nope", tree.join("dangle")).expect("dangle");

    ctx.put(PutArgs {
        recursive: true,
        paths: vec![path_str(&tree), "~/t1".to_owned()],
        ..Default::default()
    })
    .await
    .expect("put -r");
    let t1 = ctx.server.home.join("t1");
    assert_eq!(std::fs::read(t1.join("a.txt")).expect("a"), b"alpha");
    assert_eq!(std::fs::read(t1.join("sub/b.txt")).expect("b"), b"beta");
    assert!(!t1.join("link").exists() && t1.join("link").symlink_metadata().is_err());
    assert!(t1.join("dangle").symlink_metadata().is_err());

    ctx.put(PutArgs {
        recursive: true,
        follow_symlinks: true,
        paths: vec![path_str(&tree), "~/t2".to_owned()],
        ..Default::default()
    })
    .await
    .expect("put -rF");
    let t2 = ctx.server.home.join("t2");
    let link = std::fs::symlink_metadata(t2.join("link")).expect("link copied");
    assert!(link.is_file(), "followed symlink becomes a regular file");
    assert_eq!(std::fs::read(t2.join("link")).expect("link"), b"alpha");
    assert!(t2.join("dangle").symlink_metadata().is_err());

    let back = ctx.local.join("back");
    ctx.get(GetArgs {
        recursive: true,
        paths: vec!["~/t2".to_owned(), path_str(&back)],
        ..Default::default()
    })
    .await
    .expect("get -r");
    assert_eq!(std::fs::read(back.join("a.txt")).expect("a"), b"alpha");
    assert_eq!(std::fs::read(back.join("sub/b.txt")).expect("b"), b"beta");
    assert_eq!(std::fs::read(back.join("link")).expect("link"), b"alpha");
    let mut names: Vec<String> = std::fs::read_dir(&back)
        .expect("read back")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["a.txt", "link", "sub"]);
    ctx.finish().await;
}

#[tokio::test]
async fn put_into_directory_uses_basename_and_multiple_sources_need_dir() {
    let ctx = setup(ServerOpts::default()).await;
    let l1 = ctx.local.join("one.txt");
    let l2 = ctx.local.join("two.txt");
    std::fs::write(&l1, b"1").expect("l1");
    std::fs::write(&l2, b"2").expect("l2");
    std::fs::create_dir(ctx.server.home.join("dir")).expect("remote dir");

    ctx.put(PutArgs {
        paths: vec![path_str(&l1), "~/dir".to_owned()],
        ..Default::default()
    })
    .await
    .expect("put into dir");
    assert_eq!(
        std::fs::read(ctx.server.home.join("dir/one.txt")).expect("dir/one.txt"),
        b"1"
    );

    // No REMOTE and no session cwd → `~/<basename>`.
    ctx.put(PutArgs {
        paths: vec![path_str(&l2)],
        ..Default::default()
    })
    .await
    .expect("put default dest");
    assert_eq!(
        std::fs::read(ctx.server.home.join("two.txt")).expect("~/two.txt"),
        b"2"
    );

    std::fs::write(ctx.server.home.join("notadir"), b"x").expect("remote file");
    let err = ctx
        .put(PutArgs {
            paths: args(&[&path_str(&l1), &path_str(&l2), "~/notadir"]),
            ..Default::default()
        })
        .await
        .expect_err("several sources onto a file must fail");
    assert!(
        format!("{err:#}").contains("directory"),
        "error should mention directory: {err:#}"
    );
    assert_eq!(
        std::fs::read(ctx.server.home.join("notadir")).expect("remote file"),
        b"x",
        "destination untouched"
    );
    ctx.finish().await;
}

async fn file_op(conn: &Connection, op: FileOp) -> mysh_net::mux::Stream {
    conn.open(&Open::File { op, cwd: None })
        .await
        .unwrap_or_else(|e| panic!("open File: {e:?}"))
}

#[tokio::test]
async fn ls_lists_names_and_hides_dotfiles() {
    let ctx = setup(ServerOpts::default()).await;
    let dir = ctx.server.home.join("listing");
    std::fs::create_dir_all(dir.join("subdir")).expect("mkdir");
    std::fs::write(dir.join("plain"), b"p").expect("plain");
    std::fs::write(dir.join(".hidden"), b"h").expect("hidden");
    std::os::unix::fs::symlink("plain", dir.join("ln")).expect("ln");

    let mut stream = file_op(
        &ctx.conn,
        FileOp::List {
            path: "~/listing".to_owned(),
        },
    )
    .await;
    let mut entries = Vec::new();
    loop {
        let page: ListPage = read_msg(&mut stream).await.expect("list page");
        entries.extend(page.entries);
        if !page.more {
            break;
        }
    }
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [".hidden", "ln", "plain", "subdir"],
        "raw listing includes dot files (hiding is client-side)"
    );
    let by_name = |n: &str| {
        &entries
            .iter()
            .find(|e| e.name == n)
            .unwrap_or_else(|| panic!("entry {n}"))
            .attrs
    };
    assert_eq!(by_name("plain").kind, FileKind::File);
    assert_eq!(by_name("plain").size, 1);
    assert_eq!(by_name("subdir").kind, FileKind::Dir);
    assert_eq!(
        by_name("ln").kind,
        FileKind::Symlink {
            target: "plain".to_owned()
        }
    );

    let mut stream = file_op(
        &ctx.conn,
        FileOp::Stat {
            path: "~/listing/ln".to_owned(),
        },
    )
    .await;
    let attrs: Attrs = read_msg(&mut stream).await.expect("stat reply");
    assert_eq!(
        attrs.kind,
        FileKind::Symlink {
            target: "plain".to_owned()
        }
    );
    ctx.finish().await;
}

#[tokio::test]
async fn authorize_installs_key_once() {
    let ctx = setup(ServerOpts::default()).await;
    let key = SecretKey::generate().public();
    let line = key.to_line(Some("newbox"));
    assert!(line.starts_with("mysh-x25519 "), "line: {line}");

    authorize(&ctx.conn, &ctx.console, &line)
        .await
        .expect("authorize");
    let mysh_dir = ctx.server.home.join(".config/mysh");
    let ak = mysh_dir.join("authorized_keys");
    assert_eq!(
        std::fs::metadata(&mysh_dir).expect("mysh dir").mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&ak).expect("authorized_keys").mode() & 0o777,
        0o600
    );
    let text = std::fs::read_to_string(&ak).expect("read authorized_keys");
    assert_eq!(text.trim(), line.trim());

    authorize(&ctx.conn, &ctx.console, &line)
        .await
        .expect("authorize again");
    let text = std::fs::read_to_string(&ak).expect("read authorized_keys");
    let token = line.split_whitespace().nth(1).expect("key token");
    assert_eq!(
        text.matches(token).count(),
        1,
        "key installed exactly once: {text:?}"
    );

    // A different key appends a second line, keeping the first.
    let other = SecretKey::generate().public().to_line(Some("other"));
    authorize(&ctx.conn, &ctx.console, &other)
        .await
        .expect("authorize other");
    let text = std::fs::read_to_string(&ak).expect("read authorized_keys");
    assert_eq!(text.lines().count(), 2, "{text:?}");
    assert!(text.contains(line.trim()) && text.contains(other.trim()));

    // Connecting with the new key is not checked here: the harness server's
    // `TrustSource.files` is empty, so it never reads this file.
    ctx.finish().await;
}

#[tokio::test]
async fn files_denied_by_policy() {
    let ctx = setup(ServerOpts {
        deny: vec![Feature::Files],
        ..Default::default()
    })
    .await;
    let local = ctx.local.join("x");
    std::fs::write(&local, b"x").expect("write local");
    let err = ctx
        .put(PutArgs {
            paths: vec![path_str(&local), "~/x".to_owned()],
            ..Default::default()
        })
        .await
        .expect_err("put must be refused");
    let msg = format!("{err:#}").to_lowercase();
    assert!(msg.contains("denied"), "error should mention denied: {msg}");
    assert!(!ctx.server.home.join("x").exists());
    ctx.finish().await;
}
