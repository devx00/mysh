//! Server side of `Open::File` streams (docs/03-protocol.md §9).
//!
//! Every op is split in two phases: `prepare` does everything that can fail
//! *before* the `OpenReply` (path resolution, stat, open, bind the error to
//! an `ErrorCode`), then `Ok` is sent and the op body streams. Failures after
//! the reply are logged and the stream is dropped, which resets it.

use std::fs::{FileTimes, Permissions};
use std::io::{self, SeekFrom};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mysh_net::framing::{write_msg, write_reply};
use mysh_net::mux::Stream;
use mysh_proto::file::{Attrs, DirEntry, FileKind, FileOp, ListPage, PutDone};
use mysh_proto::limits;
use mysh_proto::open::{ErrorCode, OpenReply};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};
use tracing::debug;

use crate::cli::Feature;
use crate::server::{ConnCtx, resolve_remote_path};

/// Serve one file op; sends the `OpenReply` itself.
#[allow(clippy::needless_pass_by_value)] // signature fixed by the dispatch contract
pub async fn handle_file(mut stream: Stream, op: FileOp, cwd: Option<String>, ctx: ConnCtx) {
    if ctx.policy.deny.contains(&Feature::Files) {
        send_error(
            &mut stream,
            ErrorCode::Denied,
            "file transfer is disabled by server policy",
        )
        .await;
        return;
    }
    let resolve = |path: &str| resolve_remote_path(path, cwd.as_deref(), &ctx.policy.home);
    let body = match prepare(&op, resolve).await {
        Ok(body) => body,
        Err(err) => {
            debug!(?op, %err, "file op failed");
            send_error(&mut stream, error_code(&err), &err.to_string()).await;
            return;
        }
    };
    if let Err(err) = write_reply(&mut stream, &OpenReply::Ok).await {
        debug!(%err, "file op: reply failed");
        return;
    }
    if let Err(err) = send_body(&mut stream, body).await {
        debug!(?op, %err, "file op body failed");
        // Dropping without shutdown resets the stream.
        return;
    }
    if let Err(err) = stream.shutdown().await {
        debug!(%err, "file op: shutdown failed");
    }
}

/// What follows `OpenReply::Ok` on the stream.
enum Body {
    /// `→ close`
    Close,
    Attrs(Attrs),
    Pages(Vec<DirEntry>),
    Path(String),
    Get {
        file: File,
        attrs: Attrs,
        offset: u64,
    },
    Put(PutTarget),
}

/// Destination of a `Put`, opened before the reply so open errors reach the
/// client with a meaningful code.
struct PutTarget {
    file: File,
    /// Final location.
    path: PathBuf,
    /// Temp file to rename over `path` when atomic.
    temp: Option<PathBuf>,
    mode: u32,
    mtime: Option<i64>,
}

async fn prepare(op: &FileOp, resolve: impl Fn(&str) -> PathBuf + Sync) -> io::Result<Body> {
    match op {
        FileOp::Stat { path } => {
            let path = resolve(path);
            let md = fs::symlink_metadata(&path).await?;
            Ok(Body::Attrs(attrs(&path, &md).await))
        }
        FileOp::List { path } => Ok(Body::Pages(list(&resolve(path)).await?)),
        FileOp::Mkdir { path, mode } => {
            mkdir(&resolve(path), *mode).await?;
            Ok(Body::Close)
        }
        FileOp::Remove { path, recursive } => {
            remove(&resolve(path), *recursive).await?;
            Ok(Body::Close)
        }
        FileOp::Rename { from, to } => {
            fs::rename(resolve(from), resolve(to)).await?;
            Ok(Body::Close)
        }
        FileOp::SetAttr { path, mode, mtime } => {
            let path = resolve(path);
            if let Some(mode) = mode {
                fs::set_permissions(&path, Permissions::from_mode(*mode)).await?;
            }
            if let Some(mtime) = mtime {
                set_mtime(path, *mtime).await?;
            }
            Ok(Body::Close)
        }
        FileOp::Realpath { path } => {
            let real = fs::canonicalize(resolve(path)).await?;
            Ok(Body::Path(real.to_string_lossy().into_owned()))
        }
        FileOp::Get { path, offset, .. } => {
            let path = resolve(path);
            let file = File::open(&path).await?;
            let md = file.metadata().await?;
            let attrs = attrs(&path, &md).await;
            Ok(Body::Get {
                file,
                attrs,
                offset: *offset,
            })
        }
        FileOp::Put {
            path,
            mode,
            mtime,
            offset,
            truncate,
            atomic,
        } => {
            let target =
                open_put(resolve(path), *mode, *mtime, *offset, *truncate, *atomic).await?;
            Ok(Body::Put(target))
        }
        FileOp::Hash { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hash is not implemented on this server",
        )),
    }
}

async fn send_body(stream: &mut Stream, body: Body) -> io::Result<()> {
    match body {
        Body::Close => Ok(()),
        Body::Attrs(attrs) => write_msg(stream, &attrs).await,
        Body::Path(path) => write_msg(stream, &path).await,
        Body::Pages(entries) => {
            let mut chunks = entries.chunks(limits::LIST_PAGE).peekable();
            if chunks.peek().is_none() {
                return write_msg(
                    stream,
                    &ListPage {
                        entries: Vec::new(),
                        more: false,
                    },
                )
                .await;
            }
            while let Some(chunk) = chunks.next() {
                let page = ListPage {
                    entries: chunk.to_vec(),
                    more: chunks.peek().is_some(),
                };
                write_msg(stream, &page).await?;
            }
            Ok(())
        }
        Body::Get {
            mut file,
            attrs,
            offset,
        } => {
            write_msg(stream, &attrs).await?;
            if offset > 0 {
                file.seek(SeekFrom::Start(offset)).await?;
            }
            tokio::io::copy(&mut file, stream).await?;
            stream.flush().await
        }
        Body::Put(mut target) => {
            let written = match receive_put(stream, &mut target).await {
                Ok(written) => written,
                Err(err) => {
                    if let Some(temp) = &target.temp {
                        let _ = fs::remove_file(temp).await;
                    }
                    return Err(err);
                }
            };
            write_msg(stream, &PutDone { written }).await
        }
    }
}

/// Stream the body into the opened target and finalise it; returns bytes
/// written. The caller removes the temp file on error.
async fn receive_put(stream: &mut Stream, target: &mut PutTarget) -> io::Result<u64> {
    let written = tokio::io::copy(stream, &mut target.file).await?;
    target.file.sync_data().await?;
    target
        .file
        .set_permissions(Permissions::from_mode(target.mode))
        .await?;
    if let Some(mtime) = target.mtime {
        let file = target.file.try_clone().await?.into_std().await;
        set_file_mtime(file, mtime).await?;
    }
    if let Some(temp) = &target.temp {
        fs::rename(temp, &target.path).await?;
    }
    Ok(written)
}

static PUT_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn open_put(
    path: PathBuf,
    mode: u32,
    mtime: Option<i64>,
    offset: u64,
    truncate: bool,
    atomic: bool,
) -> io::Result<PutTarget> {
    if atomic {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "put: path has no file name")
        })?;
        let counter = PUT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = name.to_os_string();
        temp_name.push(format!(".mysh-tmp.{}.{counter}", std::process::id()));
        let temp = path.with_file_name(temp_name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .await?;
        return Ok(PutTarget {
            file,
            path,
            temp: Some(temp),
            mode,
            mtime,
        });
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(truncate)
        .mode(mode)
        .open(&path)
        .await?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset)).await?;
    }
    Ok(PutTarget {
        file,
        path,
        temp: None,
        mode,
        mtime,
    })
}

async fn list(path: &Path) -> io::Result<Vec<DirEntry>> {
    let mut dir = fs::read_dir(path).await?;
    let mut entries = Vec::new();
    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let md = entry.metadata().await?;
        let attrs = attrs(&entry.path(), &md).await;
        entries.push(DirEntry { name, attrs });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

async fn mkdir(path: &Path, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(mode);
    match builder.create(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => match fs::metadata(path).await {
            Ok(md) if md.is_dir() => Ok(()),
            _ => Err(err),
        },
        Err(err) => Err(err),
    }
}

async fn remove(path: &Path, recursive: bool) -> io::Result<()> {
    let md = fs::symlink_metadata(path).await?;
    if !md.is_dir() {
        return fs::remove_file(path).await;
    }
    if recursive {
        fs::remove_dir_all(path).await
    } else {
        fs::remove_dir(path).await
    }
}

/// Set a path's mtime. Files are opened for writing; directories cannot be,
/// so fall back to a read-only descriptor (`futimens` only needs ownership).
async fn set_mtime(path: PathBuf, mtime: i64) -> io::Result<()> {
    let file = tokio::task::spawn_blocking(move || {
        std::fs::File::options()
            .write(true)
            .open(&path)
            .or_else(|_| std::fs::File::open(&path))
    })
    .await
    .map_err(|err| io::Error::other(err.to_string()))??;
    set_file_mtime(file, mtime).await
}

async fn set_file_mtime(file: std::fs::File, mtime: i64) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        file.set_times(FileTimes::new().set_modified(system_time(mtime)))
    })
    .await
    .map_err(|err| io::Error::other(err.to_string()))?
}

fn system_time(secs: i64) -> SystemTime {
    match u64::try_from(secs) {
        Ok(secs) => UNIX_EPOCH + Duration::from_secs(secs),
        Err(_) => UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH),
    }
}

async fn attrs(path: &Path, md: &std::fs::Metadata) -> Attrs {
    let ft = md.file_type();
    let kind = if ft.is_symlink() {
        let target = fs::read_link(path)
            .await
            .map(|target| target.to_string_lossy().into_owned())
            .unwrap_or_default();
        FileKind::Symlink { target }
    } else if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    };
    Attrs {
        kind,
        size: md.len(),
        mode: md.mode() & 0o7777,
        mtime: md.mtime(),
        uid: md.uid(),
        gid: md.gid(),
    }
}

/// Map an OS error to the protocol code (docs/03-protocol.md §5).
pub(crate) fn error_code(err: &io::Error) -> ErrorCode {
    match err.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::Denied,
        _ => ErrorCode::Io,
    }
}

/// Send `Err { code, message }` then half-close; failures are logged only.
pub(crate) async fn send_error(stream: &mut Stream, code: ErrorCode, message: &str) {
    let reply = OpenReply::Err {
        code,
        message: message.to_owned(),
    };
    if let Err(err) = write_reply(stream, &reply).await {
        debug!(%err, "error reply failed");
        return;
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::sync::Arc;

    use mysh_net::handshake::{ClientAuth, Peer, client_handshake, server_handshake};
    use mysh_net::keys::SecretKey;
    use mysh_net::mux::{Incoming, Mode, Mux, OpenError, accept_open};
    use mysh_proto::handshake::ServerHello;
    use mysh_proto::open::Open;
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::server::Policy;

    /// Unique temp directory, removed on drop.
    pub(crate) struct TempDir(pub(crate) PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let path = std::env::temp_dir().join(format!("mysh-{tag}-{pid}-{n}-{nanos}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Client-side handles to an in-process server connection whose
    /// accepted streams are dispatched to the `server::files` / `forward`
    /// handlers exactly as `server::mod` would.
    pub(crate) struct Harness {
        pub(crate) client: Mux,
        pub(crate) client_in: Incoming,
        pub(crate) server: Mux,
        pub(crate) home: TempDir,
    }

    pub(crate) async fn harness(deny: &[Feature]) -> Harness {
        let home = TempDir::new("home");
        let client_key = SecretKey::generate();
        let server_key = SecretKey::generate();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = client_handshake(a, &client_key, 0, |_, _| Ok(()), ClientAuth::Static);
        let server = server_handshake(
            b,
            &server_key,
            ServerHello {
                name: "test".into(),
                caps: 0,
            },
            |_, _| Ok(()),
        );
        let (client, server) = tokio::join!(client, server);
        let (client, _hello) = client.expect("client handshake");
        let server = server.expect("server handshake");
        let (client_mux, client_in) = Mux::new(client.stream, Mode::Client);
        let (server_mux, mut server_in) = Mux::new(server.stream, Mode::Server);

        let policy = Arc::new(Policy {
            deny: deny.iter().copied().collect::<HashSet<_>>(),
            accept_env: Vec::new(),
            shell: None,
            name: "test".into(),
            home: home.path().to_path_buf(),
            user: "tester".into(),
            path: "/usr/bin:/bin".into(),
            forced_command: None,
            handshakes_per_minute: 0,
            idle_timeout: mysh_proto::limits::SERVER_IDLE,
            detach_grace: mysh_proto::limits::DETACH_GRACE,
            signature_auth: true,
        });
        let peer: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let local: SocketAddr = "127.0.0.1:2".parse().expect("addr");
        let ctx = ConnCtx::for_tests(
            policy,
            server_mux.clone(),
            peer,
            local,
            Peer::Static(client_key.public()),
        );
        tokio::spawn(async move {
            while let Some(mut stream) = server_in.accept().await {
                let open = match accept_open(&mut stream).await {
                    Ok(Ok(open)) => open,
                    other => panic!("bad open: {other:?}"),
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    match open {
                        Open::File { op, cwd } => handle_file(stream, op, cwd, ctx).await,
                        Open::DirectTcp { host, port } => {
                            crate::server::forward::handle_direct_tcp(stream, host, port, ctx)
                                .await;
                        }
                        Open::ForwardListen { host, port } => {
                            crate::server::forward::handle_forward_listen(stream, host, port, ctx)
                                .await;
                        }
                        other => panic!("unexpected open {other:?}"),
                    }
                });
            }
        });
        Harness {
            client: client_mux,
            client_in,
            server: server_mux,
            home,
        }
    }

    impl Harness {
        async fn file(&self, op: FileOp) -> Result<Stream, OpenError> {
            self.client.open(&Open::File { op, cwd: None }).await
        }

        async fn file_ok(&self, op: FileOp) -> Stream {
            self.file(op).await.expect("file op accepted")
        }

        /// Run an op with no body; the stream must end cleanly.
        async fn simple(&self, op: FileOp) -> Result<(), OpenError> {
            let mut stream = self.file(op).await?;
            let mut buf = [0u8; 1];
            assert_eq!(stream.read(&mut buf).await.expect("eof"), 0);
            Ok(())
        }

        fn rejected(result: Result<Stream, OpenError>) -> (ErrorCode, String) {
            match result {
                Err(OpenError::Rejected { code, message }) => (code, message),
                Ok(_) => panic!("expected rejection"),
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    async fn read_to_end(stream: &mut Stream) -> Vec<u8> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read to end");
        out
    }

    #[tokio::test]
    async fn stat_reports_attrs() {
        let h = harness(&[]).await;
        let file = h.home.path().join("hello.txt");
        std::fs::write(&file, b"hello world").expect("write");
        std::fs::set_permissions(&file, Permissions::from_mode(0o640)).expect("chmod");
        let md = std::fs::metadata(&file).expect("stat");

        let mut stream = h
            .file_ok(FileOp::Stat {
                path: "hello.txt".into(),
            })
            .await;
        let attrs: Attrs = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("attrs");
        assert_eq!(attrs.kind, FileKind::File);
        assert_eq!(attrs.size, 11);
        assert_eq!(attrs.mode, 0o640);
        assert_eq!(attrs.mtime, md.mtime());
        assert_eq!(attrs.uid, md.uid());
        assert_eq!(attrs.gid, md.gid());
        assert_eq!(read_to_end(&mut stream).await.len(), 0);

        // `~/` expansion and symlink kind.
        std::os::unix::fs::symlink("hello.txt", h.home.path().join("link")).expect("symlink");
        let mut stream = h
            .file_ok(FileOp::Stat {
                path: "~/link".into(),
            })
            .await;
        let attrs: Attrs = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("attrs");
        assert_eq!(
            attrs.kind,
            FileKind::Symlink {
                target: "hello.txt".into()
            }
        );
    }

    #[tokio::test]
    async fn list_pages_at_limit() {
        let h = harness(&[]).await;
        let dir = h.home.path().join("many");
        std::fs::create_dir(&dir).expect("mkdir");
        for i in 0..=limits::LIST_PAGE {
            std::fs::write(dir.join(format!("f{i:05}")), b"").expect("write");
        }
        let mut stream = h
            .file_ok(FileOp::List {
                path: dir.to_string_lossy().into_owned(),
            })
            .await;
        let first: ListPage = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("page 1");
        assert!(first.more);
        assert_eq!(first.entries.len(), limits::LIST_PAGE);
        assert_eq!(first.entries[0].name, "f00000");
        let second: ListPage = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("page 2");
        assert!(!second.more);
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].name, format!("f{:05}", limits::LIST_PAGE));
        assert_eq!(read_to_end(&mut stream).await.len(), 0);

        // Empty directory: exactly one page.
        std::fs::create_dir(h.home.path().join("empty")).expect("mkdir");
        let mut stream = h
            .file_ok(FileOp::List {
                path: "empty".into(),
            })
            .await;
        let page: ListPage = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("page");
        assert!(!page.more);
        assert_eq!(page.entries.len(), 0);
    }

    #[tokio::test]
    async fn mkdir_existing_dir_is_ok() {
        let h = harness(&[]).await;
        h.simple(FileOp::Mkdir {
            path: "sub".into(),
            mode: 0o750,
        })
        .await
        .expect("mkdir");
        let md = std::fs::metadata(h.home.path().join("sub")).expect("stat");
        assert!(md.is_dir());
        assert_eq!(md.mode() & 0o777, 0o750 & !umask());

        h.simple(FileOp::Mkdir {
            path: "sub".into(),
            mode: 0o750,
        })
        .await
        .expect("mkdir on existing dir");

        std::fs::write(h.home.path().join("file"), b"x").expect("write");
        let (code, _) = Harness::rejected(
            h.file(FileOp::Mkdir {
                path: "file".into(),
                mode: 0o750,
            })
            .await,
        );
        assert_eq!(code, ErrorCode::Io);
    }

    /// Umask probe using mkdir (the crate forbids `unsafe`, so no libc).
    fn umask() -> u32 {
        let probe = TempDir::new("umask");
        let dir = probe.path().join("p");
        std::fs::DirBuilder::new()
            .mode(0o777)
            .create(&dir)
            .expect("probe mkdir");
        0o777 & !(std::fs::metadata(&dir).expect("stat").mode() & 0o777)
    }

    fn pattern(len: u32, modulus: u32) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % modulus).expect("fits"))
            .collect()
    }

    fn len64(data: &[u8]) -> u64 {
        u64::try_from(data.len()).expect("fits")
    }

    #[tokio::test]
    async fn get_round_trip_with_offset() {
        let h = harness(&[]).await;
        let data = pattern(200_000, 251);
        std::fs::write(h.home.path().join("big"), &data).expect("write");

        let mut stream = h
            .file_ok(FileOp::Get {
                path: "big".into(),
                offset: 0,
                follow: false,
            })
            .await;
        let attrs: Attrs = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("attrs");
        assert_eq!(attrs.size, len64(&data));
        assert_eq!(read_to_end(&mut stream).await, data);

        let mut stream = h
            .file_ok(FileOp::Get {
                path: "big".into(),
                offset: 150_000,
                follow: false,
            })
            .await;
        let _attrs: Attrs = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("attrs");
        assert_eq!(read_to_end(&mut stream).await, &data[150_000..]);
    }

    async fn put(h: &Harness, op: FileOp, data: &[u8]) -> PutDone {
        let mut stream = h.file_ok(op).await;
        stream.write_all(data).await.expect("write body");
        stream.flush().await.expect("flush");
        stream.shutdown().await.expect("half-close");
        let done: PutDone = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("PutDone");
        assert_eq!(read_to_end(&mut stream).await.len(), 0);
        done
    }

    #[tokio::test]
    async fn put_atomic_applies_mode_and_leaves_no_temp() {
        let h = harness(&[]).await;
        let data = pattern(300_000, 253);
        let done = put(
            &h,
            FileOp::Put {
                path: "out.bin".into(),
                mode: 0o640,
                mtime: Some(1_000_000_000),
                offset: 0,
                truncate: true,
                atomic: true,
            },
            &data,
        )
        .await;
        assert_eq!(done.written, len64(&data));
        let path = h.home.path().join("out.bin");
        assert_eq!(std::fs::read(&path).expect("read"), data);
        let md = std::fs::metadata(&path).expect("stat");
        assert_eq!(md.mode() & 0o7777, 0o640);
        assert_eq!(md.mtime(), 1_000_000_000);
        let names: Vec<String> = std::fs::read_dir(h.home.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["out.bin".to_owned()],
            "no temp file left behind"
        );
    }

    #[tokio::test]
    async fn put_resume_appends_at_offset() {
        let h = harness(&[]).await;
        let path = h.home.path().join("resume");
        std::fs::write(&path, b"hello ").expect("write");
        let done = put(
            &h,
            FileOp::Put {
                path: "resume".into(),
                mode: 0o600,
                mtime: None,
                offset: 6,
                truncate: false,
                atomic: false,
            },
            b"world",
        )
        .await;
        assert_eq!(done.written, 5);
        assert_eq!(std::fs::read(&path).expect("read"), b"hello world");

        // truncate: true starts over.
        put(
            &h,
            FileOp::Put {
                path: "resume".into(),
                mode: 0o600,
                mtime: None,
                offset: 0,
                truncate: true,
                atomic: false,
            },
            b"x",
        )
        .await;
        assert_eq!(std::fs::read(&path).expect("read"), b"x");
    }

    #[tokio::test]
    async fn remove_rename_realpath_setattr() {
        let h = harness(&[]).await;
        let tree = h.home.path().join("tree");
        std::fs::create_dir_all(tree.join("a/b")).expect("mkdir");
        std::fs::write(tree.join("a/b/f"), b"1").expect("write");

        let (code, _) = Harness::rejected(
            h.file(FileOp::Remove {
                path: "tree".into(),
                recursive: false,
            })
            .await,
        );
        assert_eq!(
            code,
            ErrorCode::Io,
            "non-recursive remove of a non-empty dir"
        );
        h.simple(FileOp::Remove {
            path: "tree".into(),
            recursive: true,
        })
        .await
        .expect("recursive remove");
        assert!(!tree.exists());

        std::fs::write(h.home.path().join("from"), b"1").expect("write");
        h.simple(FileOp::Rename {
            from: "from".into(),
            to: "to".into(),
        })
        .await
        .expect("rename");
        assert!(!h.home.path().join("from").exists());
        assert!(h.home.path().join("to").exists());

        h.simple(FileOp::SetAttr {
            path: "to".into(),
            mode: Some(0o600),
            mtime: Some(1_234_567_890),
        })
        .await
        .expect("setattr");
        let md = std::fs::metadata(h.home.path().join("to")).expect("stat");
        assert_eq!(md.mode() & 0o7777, 0o600);
        assert_eq!(md.mtime(), 1_234_567_890);

        let mut stream = h.file_ok(FileOp::Realpath { path: "~".into() }).await;
        let real: String = mysh_net::framing::read_msg(&mut stream)
            .await
            .expect("path");
        let expected = std::fs::canonicalize(h.home.path()).expect("canon");
        assert_eq!(PathBuf::from(real), expected);
    }

    #[tokio::test]
    async fn missing_path_maps_to_not_found() {
        let h = harness(&[]).await;
        let (code, message) = Harness::rejected(
            h.file(FileOp::Stat {
                path: "nope".into(),
            })
            .await,
        );
        assert_eq!(code, ErrorCode::NotFound);
        assert_ne!(message.len(), 0);
        let (code, _) = Harness::rejected(
            h.file(FileOp::Get {
                path: "nope".into(),
                offset: 0,
                follow: false,
            })
            .await,
        );
        assert_eq!(code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn files_feature_denied() {
        let h = harness(&[Feature::Files]).await;
        let (code, _) = Harness::rejected(h.file(FileOp::Realpath { path: "~".into() }).await);
        assert_eq!(code, ErrorCode::Denied);
        h.client.close().await;
        h.server.closed().await;
    }
}
