//! Accepting connections a server opens itself (docs/02-security.md
//! "Callers", docs/07-embedding.md "Accepting connections").
//!
//! A server started with `--connect-back` dials this client; after TCP
//! nothing changes — the client is still the Noise initiator and the
//! server still authorizes the client's key. What does change is the
//! client's side of the trust question: a connecting-back server's source
//! address says nothing, so its key is looked up by fingerprint in the
//! [`Callers`] store instead of `known_hosts`.
//!
//! [`Acceptor::bind`] listens, runs the handshakes concurrently (a slow
//! consumer never eats into a handshake deadline) and hands the finished
//! connections to [`Acceptor::next`] in the order they arrived. Refused and
//! failed handshakes never reach it.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use mysh_net::ratelimit::RateLimiter;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{
    client::Client,
    conn::accept_connection,
    identity::{Caller, Callers, ClientIdentity},
    report::Reporter,
    types::{AcceptedServer, Event},
};

/// Bound on one inbound handshake; the server allows itself 5 s.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Completed connections waiting for [`Acceptor::next`].
const QUEUE: usize = 64;

/// How [`Acceptor::bind`] treats inbound connections.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptOpts {
    /// Record an unknown server key in the callers file and accept it
    /// (first contact), instead of refusing it.
    pub accept_new: bool,
    /// Per-address token bucket on inbound handshakes; 0 switches it off.
    pub handshakes_per_minute: u32,
}

/// One accepted connection.
#[derive(Debug)]
pub struct Inbound {
    /// The connection, ready to use.
    pub client: Client,
    /// Which caller it is.
    pub caller: Caller,
    /// Where it came from. Informational: trust is by key, never by address.
    pub peer: SocketAddr,
    /// `ServerHello.name` (the server's hostname by default). Informational.
    pub name: String,
}

/// A listener for connections servers open themselves.
#[derive(Debug)]
pub struct Acceptor {
    local: SocketAddr,
    rx: mpsc::Receiver<Inbound>,
    tasks: Vec<JoinHandle<()>>,
}

impl Acceptor {
    /// Listen on `addr` for servers in connect-back mode.
    ///
    /// `identity` is what this client authenticates as (the server checks
    /// it against its `authorized_keys`), `callers` decides which server
    /// keys are accepted, and `reporter` receives [`Event::Accepted`],
    /// [`Event::Closed`] and [`Event::Refused`].
    pub async fn bind(
        addr: SocketAddr,
        identity: ClientIdentity,
        callers: Callers,
        reporter: Arc<dyn Reporter>,
        opts: AcceptOpts,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        let local = listener.local_addr().context("listener address")?;
        info!(addr = %local, fingerprint = %identity.fingerprint(), callers = callers.len(), "accepting connections");
        // Handshakes run concurrently; their results are released in the
        // order the connections arrived, so a slow handshake holds back
        // only the connections accepted after it.
        let (order_tx, order_rx) = mpsc::unbounded_channel();
        let (ready_tx, rx) = mpsc::channel(QUEUE);
        let accept = tokio::spawn(accept_loop(
            listener,
            Arc::new(identity),
            Arc::new(callers),
            reporter,
            opts,
            order_tx,
        ));
        let forward = tokio::spawn(forward_loop(order_rx, ready_tx));
        Ok(Self {
            local,
            rx,
            tasks: vec![accept, forward],
        })
    }

    /// The address actually bound (port 0 resolved).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The next accepted connection; `None` once the acceptor is closed.
    pub async fn next(&mut self) -> Option<Inbound> {
        self.rx.recv().await
    }

    /// Stop listening. Connections already handed out stay open.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Accept, rate limit, and start one handshake task per connection,
/// queueing their slots so results come out in arrival order.
async fn accept_loop(
    listener: TcpListener,
    identity: Arc<ClientIdentity>,
    callers: Arc<Callers>,
    reporter: Arc<dyn Reporter>,
    opts: AcceptOpts,
    order: mpsc::UnboundedSender<oneshot::Receiver<Inbound>>,
) {
    let mut limiter =
        (opts.handshakes_per_minute > 0).then(|| RateLimiter::new(opts.handshakes_per_minute));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "inbound accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if let Some(limiter) = limiter.as_mut() {
            let now = tokio::time::Instant::now();
            if !limiter.check(peer.ip(), now) {
                if limiter.should_warn(peer.ip(), now) {
                    warn!(%peer, rate = opts.handshakes_per_minute, "inbound handshake rate limited");
                }
                continue;
            }
        }
        if let Err(e) = stream.set_nodelay(true) {
            debug!(%peer, error = %e, "set_nodelay failed");
        }
        let (slot_tx, slot_rx) = oneshot::channel();
        if order.send(slot_rx).is_err() {
            debug!("acceptor consumer gone; stopping");
            return;
        }
        tokio::spawn(handshake(
            stream,
            peer,
            Arc::clone(&identity),
            Arc::clone(&callers),
            Arc::clone(&reporter),
            opts.accept_new,
            slot_tx,
        ));
    }
}

/// One inbound handshake; the slot stays empty when it is refused or fails.
async fn handshake(
    stream: TcpStream,
    peer: SocketAddr,
    identity: Arc<ClientIdentity>,
    callers: Arc<Callers>,
    reporter: Arc<dyn Reporter>,
    accept_new: bool,
    slot: oneshot::Sender<Inbound>,
) {
    let result = timeout(
        HANDSHAKE_TIMEOUT,
        accept_connection(
            stream,
            &identity,
            &callers,
            accept_new,
            Arc::clone(&reporter),
        ),
    )
    .await;
    let (conn, caller) = match result {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            debug!(%peer, error = %format_args!("{e:#}"), "inbound connection not established");
            return;
        }
        Err(_) => {
            warn!(%peer, "inbound handshake timed out");
            return;
        }
    };
    let name = caller.label();
    info!(%peer, caller = %name, fingerprint = %caller.fingerprint, via = %caller.via, "accepted connection");
    reporter.event(&Event::Accepted {
        name: name.clone(),
        fingerprint: caller.fingerprint.to_string(),
        addr: peer.to_string(),
        server: AcceptedServer {
            name: conn.server_hello().name.clone(),
            version: conn.version(),
        },
    });
    // The `closed` event belongs to the connection, not to whoever holds
    // it: report it wherever it ends.
    tokio::spawn({
        let conn = conn.clone();
        let reporter = Arc::clone(&reporter);
        let name = name.clone();
        let fingerprint = caller.fingerprint.to_string();
        async move {
            conn.closed().await;
            reporter.event(&Event::Closed {
                name,
                fingerprint,
                reason: conn.close_reason().unwrap_or_else(|| "closed".to_owned()),
            });
        }
    });
    let server_name = conn.server_hello().name.clone();
    let inbound = Inbound {
        client: Client::from_connection(conn, reporter),
        caller,
        peer,
        name: server_name,
    };
    if slot.send(inbound).is_err() {
        debug!(%peer, "accepted connection dropped: nobody is consuming");
    }
}

/// Release finished handshakes in arrival order.
async fn forward_loop(
    mut order: mpsc::UnboundedReceiver<oneshot::Receiver<Inbound>>,
    ready: mpsc::Sender<Inbound>,
) {
    while let Some(slot) = order.recv().await {
        // `Err` is a refused or failed handshake: skip it silently, it was
        // reported where it happened.
        if let Ok(inbound) = slot.await
            && ready.send(inbound).await.is_err()
        {
            return;
        }
    }
}
