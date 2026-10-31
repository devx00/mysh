//! Port forwarding (docs/03-protocol.md §8, docs/04-sessions.md "Port
//! forwarding"): `-L` local listeners → `DirectTcp`, `-R` remote listeners
//! (`ForwardListen` + `ForwardedTcp`), `-D` SOCKS5 → `DirectTcp`.
//!
//! Every forward is a numbered entry owning one tokio task: the accept loop
//! for `-L`/`-D`, the reader that keeps the `ForwardListen` stream alive for
//! `-R`. Removing an entry aborts that task; dropping a `ForwardListen`
//! stream cancels the listener on the server.

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use mysh_net::{
    framing::{read_msg, write_reply},
    mux::{OpenError, Stream},
};
use mysh_proto::{
    forward::Bound,
    open::{ErrorCode, Open, OpenReply},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tracing::{debug, warn};

use super::{conn::Connection, console::Console};
use crate::config::ForwardSpec;

/// Buffer size per direction of a forwarded connection.
const COPY_BUF: usize = 64 * 1024;

/// SOCKS5 negotiation must finish within this long.
const SOCKS_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest SOCKS5 request we accept (header + 255-byte domain + port).
const SOCKS_MAX_REQUEST: usize = 4 + 1 + 255 + 2;

/// Kind of a forward, as shown by `forward ls` and `info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

impl fmt::Display for ForwardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Dynamic => "dynamic",
        })
    }
}

/// Snapshot of one forward for `forward ls` / `info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    pub id: u32,
    pub kind: ForwardKind,
    /// Listening address: the local socket for `-L`/`-D`, the server-side
    /// bind for `-R` (port as actually bound).
    pub bind: SocketAddr,
    /// Destination for `-L`/`-R`; `None` for `-D`.
    pub target: Option<(String, u16)>,
    /// Connections accepted so far.
    pub accepted: u64,
}

#[derive(Debug)]
struct Entry {
    kind: ForwardKind,
    bind: SocketAddr,
    target: Option<(String, u16)>,
    accepted: Arc<AtomicU64>,
    /// Server-side listener id (`Bound.listener`) for `-R`.
    listener: Option<u32>,
    task: JoinHandle<()>,
}

#[derive(Debug)]
struct Inner {
    conn: Connection,
    console: Console,
    next_id: AtomicU32,
    entries: Mutex<HashMap<u32, Entry>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(entries) = self.entries.get_mut() {
            for entry in entries.values() {
                entry.task.abort();
            }
        }
    }
}

/// All forwards of one connection. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Forwards {
    inner: Arc<Inner>,
}

impl Forwards {
    /// Creates the registry and installs it as the connection's
    /// `ForwardedTcp` handler.
    #[allow(clippy::needless_pass_by_value)] // Connection contract requires owned value
    pub fn new(conn: Connection, console: Console) -> Self {
        let inner = Arc::new(Inner {
            conn: conn.clone(),
            console,
            next_id: AtomicU32::new(1),
            entries: Mutex::new(HashMap::new()),
        });
        let weak: Weak<Inner> = Arc::downgrade(&inner);
        conn.set_forwarded_handler(Box::new(move |stream, listener, peer| {
            if let Some(inner) = weak.upgrade() {
                tokio::spawn(handle_forwarded(inner, stream, listener, peer));
            } else {
                tokio::spawn(reject(stream, ErrorCode::NotFound, "no forward registry"));
            }
        }));
        Self { inner }
    }

    fn alloc_id(&self) -> u32 {
        self.inner.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn insert(&self, id: u32, entry: Entry) -> Result<u32> {
        let mut entries = self
            .inner
            .entries
            .lock()
            .map_err(|_| anyhow!("forward registry poisoned"))?;
        entries.insert(id, entry);
        Ok(id)
    }

    /// `-L [bind:]port:host:hostport`: listen locally, `DirectTcp` per
    /// accepted connection.
    pub async fn add_local(&self, spec: &ForwardSpec) -> Result<u32> {
        let (host, port) = spec
            .target
            .clone()
            .ok_or_else(|| anyhow!("local forward needs a target host:port"))?;
        let listener = TcpListener::bind((spec.bind.as_str(), spec.port))
            .await
            .with_context(|| format!("bind {}:{}", spec.bind, spec.port))?;
        let bind = listener.local_addr().context("local_addr")?;
        let accepted = Arc::new(AtomicU64::new(0));
        let id = self.alloc_id();
        let task = tokio::spawn(run_local(
            self.inner.conn.clone(),
            self.inner.console.clone(),
            id,
            listener,
            host.clone(),
            port,
            Arc::clone(&accepted),
        ));
        let entry = Entry {
            kind: ForwardKind::Local,
            bind,
            target: Some((host, port)),
            accepted,
            listener: None,
            task,
        };
        self.insert(id, entry)
    }

    /// `-R [bind:]port:host:hostport`: the server listens; each
    /// `ForwardedTcp` is dialled to `host:hostport` here.
    pub async fn add_remote(&self, spec: &ForwardSpec) -> Result<u32> {
        let (host, port) = spec
            .target
            .clone()
            .ok_or_else(|| anyhow!("remote forward needs a target host:port"))?;
        let open = Open::ForwardListen {
            host: spec.bind.clone(),
            port: spec.port,
        };
        let mut stream = self
            .inner
            .conn
            .open(&open)
            .await
            .with_context(|| format!("remote listen {}:{}", spec.bind, spec.port))?;
        let bound: Bound = read_msg(&mut stream).await.with_context(|| {
            format!(
                "remote listen {}:{}: waiting for Bound",
                spec.bind, spec.port
            )
        })?;
        let ip = spec
            .bind
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let bind = SocketAddr::new(ip, bound.port);
        let accepted = Arc::new(AtomicU64::new(0));
        let id = self.alloc_id();
        let task = tokio::spawn(run_remote(Arc::downgrade(&self.inner), id, stream));
        let entry = Entry {
            kind: ForwardKind::Remote,
            bind,
            target: Some((host, port)),
            accepted,
            listener: Some(bound.listener),
            task,
        };
        self.insert(id, entry)
    }

    /// `-D [bind:]port`: local SOCKS5 (CONNECT only) → `DirectTcp`.
    pub async fn add_dynamic(&self, spec: &ForwardSpec) -> Result<u32> {
        let listener = TcpListener::bind((spec.bind.as_str(), spec.port))
            .await
            .with_context(|| format!("bind {}:{}", spec.bind, spec.port))?;
        let bind = listener.local_addr().context("local_addr")?;
        let accepted = Arc::new(AtomicU64::new(0));
        let id = self.alloc_id();
        let task = tokio::spawn(run_dynamic(
            self.inner.conn.clone(),
            self.inner.console.clone(),
            id,
            listener,
            Arc::clone(&accepted),
        ));
        let entry = Entry {
            kind: ForwardKind::Dynamic,
            bind,
            target: None,
            accepted,
            listener: None,
            task,
        };
        self.insert(id, entry)
    }

    /// Snapshot of every forward, ordered by id.
    pub fn list(&self) -> Vec<ForwardInfo> {
        let Ok(entries) = self.inner.entries.lock() else {
            return Vec::new();
        };
        let mut out: Vec<ForwardInfo> = entries
            .iter()
            .map(|(&id, e)| ForwardInfo {
                id,
                kind: e.kind,
                bind: e.bind,
                target: e.target.clone(),
                accepted: e.accepted.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by_key(|f| f.id);
        out
    }

    /// Stop forward `id`; `false` when there is no such forward.
    pub async fn remove(&self, id: u32) -> bool {
        let entry = self
            .inner
            .entries
            .lock()
            .ok()
            .and_then(|mut entries| entries.remove(&id));
        if let Some(entry) = entry {
            stop(entry).await;
            true
        } else {
            false
        }
    }

    /// Stop every forward.
    pub async fn shutdown(&self) {
        let entries: Vec<Entry> = self
            .inner
            .entries
            .lock()
            .map(|mut entries| entries.drain().map(|(_, e)| e).collect())
            .unwrap_or_default();
        for entry in entries {
            stop(entry).await;
        }
    }
}

/// Abort an entry's task and wait until it is gone, so that its listener
/// socket or `ForwardListen` stream is released before we return.
async fn stop(entry: Entry) {
    entry.task.abort();
    let _ = entry.task.await;
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// Reply `Err` on an accepted stream and drop it.
async fn reject(mut stream: Stream, code: ErrorCode, message: &str) {
    let reply = OpenReply::Err {
        code,
        message: message.to_owned(),
    };
    if let Err(e) = write_reply(&mut stream, &reply).await {
        debug!("forwarded stream: reply failed: {e}");
    }
}

/// Bidirectional copy with half-close propagation; an error on either side
/// drops both ends (yamux reset, TCP close).
async fn pump(mut stream: Stream, mut tcp: TcpStream) -> std::io::Result<(u64, u64)> {
    tokio::io::copy_bidirectional_with_sizes(&mut stream, &mut tcp, COPY_BUF, COPY_BUF).await
}

fn describe_open_error(err: &OpenError) -> String {
    match err {
        OpenError::Rejected { code, message } if message.is_empty() => code.to_string(),
        OpenError::Rejected { code, message } => format!("{code}: {message}"),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// -L
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)] // a spawned task owns its handles
async fn run_local(
    conn: Connection,
    console: Console,
    id: u32,
    listener: TcpListener,
    host: String,
    port: u16,
    accepted: Arc<AtomicU64>,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                console.notice(&format!("forward {id}: accept failed: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let conn = conn.clone();
        let console = console.clone();
        let host = host.clone();
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            let open = Open::DirectTcp {
                host: host.clone(),
                port,
            };
            let stream = match conn.open(&open).await {
                Ok(s) => s,
                Err(e) => {
                    console.notice(&format!(
                        "forward {id}: {host}:{port}: {}",
                        describe_open_error(&e)
                    ));
                    return;
                }
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            debug!("forward {id}: {peer} → {host}:{port}");
            if let Err(e) = pump(stream, tcp).await {
                debug!("forward {id}: {peer}: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// -R
// ---------------------------------------------------------------------------

/// Keeps the `ForwardListen` stream alive and notices when the server ends
/// it (listener gone); the entry is then removed.
#[allow(clippy::needless_pass_by_value)] // a spawned task owns its handles
async fn run_remote(inner: Weak<Inner>, id: u32, mut stream: Stream) {
    let mut buf = [0u8; 64];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                debug!("forward {id}: listener stream: {e}");
                break;
            }
        }
    }
    drop(stream);
    if let Some(inner) = inner.upgrade() {
        let removed = inner.entries.lock().ok().and_then(|mut e| e.remove(&id));
        if let Some(entry) = removed {
            // We are that task; never await ourselves.
            drop(entry);
            inner.console.notice(&format!(
                "forward {id}: remote listener closed by the server"
            ));
        }
    }
}

/// `ForwardedTcp { listener, peer }` from the server: dial the configured
/// target, reply, copy.
#[allow(clippy::needless_pass_by_value)] // a spawned task owns its handles
async fn handle_forwarded(inner: Arc<Inner>, mut stream: Stream, listener: u32, peer: String) {
    let found = inner.entries.lock().ok().and_then(|entries| {
        entries
            .iter()
            .find(|(_, e)| e.kind == ForwardKind::Remote && e.listener == Some(listener))
            .map(|(&id, e)| (id, e.target.clone(), Arc::clone(&e.accepted)))
    });
    let Some((id, Some((host, port)), accepted)) = found else {
        warn!("forwarded connection for unknown listener {listener} from {peer}");
        reject(stream, ErrorCode::NotFound, "no such listener").await;
        return;
    };
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(t) => t,
        Err(e) => {
            inner
                .console
                .notice(&format!("forward {id}: {peer}: dial {host}:{port}: {e}"));
            reject(stream, ErrorCode::Io, &e.to_string()).await;
            return;
        }
    };
    if let Err(e) = write_reply(&mut stream, &OpenReply::Ok).await {
        debug!("forward {id}: {peer}: reply failed: {e}");
        return;
    }
    accepted.fetch_add(1, Ordering::Relaxed);
    debug!("forward {id}: {peer} → {host}:{port}");
    if let Err(e) = pump(stream, tcp).await {
        debug!("forward {id}: {peer}: {e}");
    }
}

// ---------------------------------------------------------------------------
// -D (SOCKS5)
// ---------------------------------------------------------------------------

const SOCKS_VERSION: u8 = 5;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes (RFC 1928 §6).
const SOCKS_REP_OK: u8 = 0x00;
const SOCKS_REP_GENERAL: u8 = 0x01;
const SOCKS_REP_NOT_ALLOWED: u8 = 0x02;
const SOCKS_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS_REP_REFUSED: u8 = 0x05;
const SOCKS_REP_CMD_UNSUPPORTED: u8 = 0x07;
const SOCKS_REP_ATYP_UNSUPPORTED: u8 = 0x08;

/// Outcome of parsing a prefix of the client's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed<T> {
    /// More bytes are needed.
    Incomplete,
    /// Parsed `T`, consuming this many bytes.
    Done(T, usize),
    /// Well-formed but unacceptable; answer with this reply code
    /// (`0xFF` for the greeting) and close.
    Reply(u8),
    /// Not SOCKS5; close without a reply.
    Invalid,
}

/// Greeting `VER NMETHODS METHODS...`: `Done(())` when "no authentication"
/// is offered, `Reply(0xFF)` otherwise.
fn parse_greeting(buf: &[u8]) -> Parsed<()> {
    let [ver, n, rest @ ..] = buf else {
        return Parsed::Incomplete;
    };
    if *ver != SOCKS_VERSION {
        return Parsed::Invalid;
    }
    let n = usize::from(*n);
    if n == 0 {
        return Parsed::Invalid;
    }
    if rest.len() < n {
        return Parsed::Incomplete;
    }
    if rest[..n].contains(&SOCKS_NO_AUTH) {
        Parsed::Done((), 2 + n)
    } else {
        Parsed::Reply(SOCKS_NO_ACCEPTABLE)
    }
}

/// Request `VER CMD RSV ATYP DST.ADDR DST.PORT` → `(host, port)`.
fn parse_request(buf: &[u8]) -> Parsed<(String, u16)> {
    let [ver, cmd, _rsv, atyp, rest @ ..] = buf else {
        return Parsed::Incomplete;
    };
    if *ver != SOCKS_VERSION {
        return Parsed::Invalid;
    }
    if *cmd != SOCKS_CMD_CONNECT {
        return Parsed::Reply(SOCKS_REP_CMD_UNSUPPORTED);
    }
    let (host, addr_len) = match *atyp {
        SOCKS_ATYP_IPV4 => {
            let Some(b) = rest.get(..4) else {
                return Parsed::Incomplete;
            };
            let octets: [u8; 4] = [b[0], b[1], b[2], b[3]];
            (Ipv4Addr::from(octets).to_string(), 4)
        }
        SOCKS_ATYP_IPV6 => {
            let Some(b) = rest.get(..16) else {
                return Parsed::Incomplete;
            };
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            (Ipv6Addr::from(octets).to_string(), 16)
        }
        SOCKS_ATYP_DOMAIN => {
            let Some(&len) = rest.first() else {
                return Parsed::Incomplete;
            };
            let len = usize::from(len);
            if len == 0 {
                return Parsed::Reply(SOCKS_REP_ATYP_UNSUPPORTED);
            }
            let Some(name) = rest.get(1..=len) else {
                return Parsed::Incomplete;
            };
            match std::str::from_utf8(name) {
                Ok(s) => (s.to_owned(), 1 + len),
                Err(_) => return Parsed::Reply(SOCKS_REP_ATYP_UNSUPPORTED),
            }
        }
        _ => return Parsed::Reply(SOCKS_REP_ATYP_UNSUPPORTED),
    };
    let Some(p) = rest.get(addr_len..addr_len + 2) else {
        return Parsed::Incomplete;
    };
    let port = u16::from_be_bytes([p[0], p[1]]);
    Parsed::Done((host, port), 4 + addr_len + 2)
}

/// `VER REP RSV ATYP=IPv4 0.0.0.0 PORT=0`.
fn socks_reply(rep: u8) -> [u8; 10] {
    [SOCKS_VERSION, rep, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// Map a `DirectTcp` open failure to a SOCKS5 reply code.
fn socks_code_for(err: &OpenError) -> u8 {
    match err {
        OpenError::Rejected {
            code: ErrorCode::NotFound,
            ..
        } => SOCKS_REP_HOST_UNREACHABLE,
        OpenError::Rejected {
            code: ErrorCode::Denied | ErrorCode::Unauthorized,
            ..
        } => SOCKS_REP_NOT_ALLOWED,
        OpenError::Rejected { .. } => SOCKS_REP_REFUSED,
        OpenError::Io(_) | OpenError::Timeout | OpenError::Closed => SOCKS_REP_GENERAL,
    }
}

/// Why a SOCKS5 negotiation stopped before `CONNECT` succeeded.
#[derive(Debug)]
enum SocksFail {
    /// A reply code was (or must be) sent.
    Reply(u8),
    /// Not SOCKS5 / oversized / EOF: nothing to say.
    Invalid,
    Io(std::io::Error),
}

impl From<std::io::Error> for SocksFail {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read from `tcp` into `buf` until `parse` is satisfied; consumed bytes are
/// drained from `buf`.
async fn read_parsed<T>(
    tcp: &mut TcpStream,
    buf: &mut Vec<u8>,
    parse: fn(&[u8]) -> Parsed<T>,
) -> Result<T, SocksFail> {
    loop {
        match parse(buf) {
            Parsed::Done(v, n) => {
                buf.drain(..n);
                return Ok(v);
            }
            Parsed::Reply(code) => return Err(SocksFail::Reply(code)),
            Parsed::Invalid => return Err(SocksFail::Invalid),
            Parsed::Incomplete => {
                if buf.len() >= SOCKS_MAX_REQUEST {
                    return Err(SocksFail::Invalid);
                }
                let mut chunk = [0u8; 512];
                let n = tcp.read(&mut chunk).await?;
                if n == 0 {
                    return Err(SocksFail::Invalid);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

/// Greeting and request; returns the target once the client is ready for
/// the final reply.
async fn socks_negotiate(tcp: &mut TcpStream) -> Result<(String, u16), SocksFail> {
    let mut buf = Vec::with_capacity(64);
    match read_parsed(tcp, &mut buf, parse_greeting).await {
        Ok(()) => tcp.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?,
        Err(SocksFail::Reply(code)) => {
            let _ = tcp.write_all(&[SOCKS_VERSION, code]).await;
            return Err(SocksFail::Reply(code));
        }
        Err(e) => return Err(e),
    }
    match read_parsed(tcp, &mut buf, parse_request).await {
        Ok(target) => Ok(target),
        Err(SocksFail::Reply(code)) => {
            let _ = tcp.write_all(&socks_reply(code)).await;
            Err(SocksFail::Reply(code))
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::needless_pass_by_value)] // a spawned task owns its handles
async fn socks_session(
    conn: Connection,
    console: Console,
    id: u32,
    mut tcp: TcpStream,
    peer: SocketAddr,
    accepted: Arc<AtomicU64>,
) {
    let (host, port) = match tokio::time::timeout(SOCKS_TIMEOUT, socks_negotiate(&mut tcp)).await {
        Ok(Ok(target)) => target,
        Ok(Err(SocksFail::Reply(code))) => {
            debug!("forward {id}: {peer}: socks5 refused with {code:#04x}");
            return;
        }
        Ok(Err(SocksFail::Invalid)) => {
            debug!("forward {id}: {peer}: not a SOCKS5 CONNECT");
            return;
        }
        Ok(Err(SocksFail::Io(e))) => {
            debug!("forward {id}: {peer}: {e}");
            return;
        }
        Err(_) => {
            debug!("forward {id}: {peer}: socks5 negotiation timed out");
            return;
        }
    };
    let open = Open::DirectTcp {
        host: host.clone(),
        port,
    };
    let stream = match conn.open(&open).await {
        Ok(s) => s,
        Err(e) => {
            console.notice(&format!(
                "forward {id}: {host}:{port}: {}",
                describe_open_error(&e)
            ));
            let _ = tcp.write_all(&socks_reply(socks_code_for(&e))).await;
            return;
        }
    };
    if let Err(e) = tcp.write_all(&socks_reply(SOCKS_REP_OK)).await {
        debug!("forward {id}: {peer}: {e}");
        return;
    }
    accepted.fetch_add(1, Ordering::Relaxed);
    debug!("forward {id}: {peer} → {host}:{port}");
    if let Err(e) = pump(stream, tcp).await {
        debug!("forward {id}: {peer}: {e}");
    }
}

#[allow(clippy::needless_pass_by_value)] // a spawned task owns its handles
async fn run_dynamic(
    conn: Connection,
    console: Console,
    id: u32,
    listener: TcpListener,
    accepted: Arc<AtomicU64>,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                console.notice(&format!("forward {id}: accept failed: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        tokio::spawn(socks_session(
            conn.clone(),
            console.clone(),
            id,
            tcp,
            peer,
            Arc::clone(&accepted),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_accepts_no_auth() {
        assert_eq!(parse_greeting(&[5, 1, 0]), Parsed::Done((), 3));
        assert_eq!(parse_greeting(&[5, 2, 2, 0]), Parsed::Done((), 4));
        // Trailing bytes (a pipelined request) are left alone.
        assert_eq!(parse_greeting(&[5, 1, 0, 5, 1, 0]), Parsed::Done((), 3));
    }

    #[test]
    fn greeting_rejects_or_waits() {
        assert_eq!(parse_greeting(&[5, 1, 2]), Parsed::Reply(0xFF));
        assert_eq!(parse_greeting(&[5, 2, 1]), Parsed::Incomplete);
        assert_eq!(parse_greeting(&[5]), Parsed::Incomplete);
        assert_eq!(parse_greeting(&[]), Parsed::Incomplete);
        assert_eq!(parse_greeting(&[4, 1, 0]), Parsed::Invalid);
        assert_eq!(parse_greeting(&[5, 0]), Parsed::Invalid);
    }

    #[test]
    fn request_ipv4() {
        let req = [5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90];
        assert_eq!(
            parse_request(&req),
            Parsed::Done(("127.0.0.1".to_owned(), 8080), 10)
        );
        assert_eq!(parse_request(&req[..9]), Parsed::Incomplete);
    }

    #[test]
    fn request_domain() {
        let mut req = vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&[0, 80]);
        assert_eq!(
            parse_request(&req),
            Parsed::Done(("example.com".to_owned(), 80), req.len())
        );
        assert_eq!(parse_request(&req[..8]), Parsed::Incomplete);
        assert_eq!(parse_request(&[5, 1, 0, 3]), Parsed::Incomplete);
        assert_eq!(parse_request(&[5, 1, 0, 3, 0, 0, 80]), Parsed::Reply(0x08));
        assert_eq!(
            parse_request(&[5, 1, 0, 3, 2, 0xFF, 0xFE, 0, 80]),
            Parsed::Reply(0x08)
        );
    }

    #[test]
    fn request_ipv6() {
        let mut req = vec![5, 1, 0, 4];
        req.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        req.extend_from_slice(&[0x01, 0xBB]);
        assert_eq!(
            parse_request(&req),
            Parsed::Done(("::1".to_owned(), 443), 22)
        );
        assert_eq!(parse_request(&req[..20]), Parsed::Incomplete);
    }

    #[test]
    fn request_errors() {
        assert_eq!(
            parse_request(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 1]),
            Parsed::Reply(0x07)
        );
        assert_eq!(parse_request(&[5, 3, 0, 1]), Parsed::Reply(0x07));
        assert_eq!(parse_request(&[5, 1, 0, 9, 0, 0]), Parsed::Reply(0x08));
        assert_eq!(parse_request(&[4, 1, 0, 1]), Parsed::Invalid);
        assert_eq!(parse_request(&[5, 1]), Parsed::Incomplete);
    }

    #[test]
    fn reply_bytes_and_error_mapping() {
        assert_eq!(socks_reply(0), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(socks_reply(5)[1], 5);
        let rejected = |code| OpenError::Rejected {
            code,
            message: String::new(),
        };
        assert_eq!(
            socks_code_for(&rejected(ErrorCode::NotFound)),
            SOCKS_REP_HOST_UNREACHABLE
        );
        assert_eq!(socks_code_for(&rejected(ErrorCode::Io)), SOCKS_REP_REFUSED);
        assert_eq!(
            socks_code_for(&rejected(ErrorCode::Denied)),
            SOCKS_REP_NOT_ALLOWED
        );
        assert_eq!(socks_code_for(&OpenError::Closed), SOCKS_REP_GENERAL);
    }

    #[test]
    fn open_error_description() {
        let e = OpenError::Rejected {
            code: ErrorCode::Io,
            message: "connection refused".to_owned(),
        };
        assert_eq!(describe_open_error(&e), "i/o error: connection refused");
        let e = OpenError::Rejected {
            code: ErrorCode::Denied,
            message: String::new(),
        };
        assert_eq!(describe_open_error(&e), "denied by server policy");
    }

    #[test]
    fn forward_kind_display() {
        assert_eq!(ForwardKind::Local.to_string(), "local");
        assert_eq!(ForwardKind::Dynamic.to_string(), "dynamic");
    }
}
