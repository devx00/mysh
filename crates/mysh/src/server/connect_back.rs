//! Connect-back mode (`mysh serve --connect-back ADDR`): the server opens
//! the TCP connection to a client that accepts such connections
//! (`mysh accept`), then runs the ordinary handshake as the Noise responder
//! — nothing after TCP differs from an accepted connection
//! (docs/03-protocol.md §1).
//!
//! One [`run_loop`] task per address, strictly sequential: dial, serve the
//! connection to its end, sleep until the next period boundary, repeat. A
//! loop therefore never has two connections open and only dials again after
//! the previous connection has fully ended — the invariant is the loop's
//! shape, not a check.

use std::{fmt, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail};
use mysh_proto::DEFAULT_PORT;
use rand_core::RngCore as _;
use tokio::{
    net::TcpStream,
    sync::watch,
    time::{Instant, timeout},
};
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::{Shared, audit::Direction, handle_connection};
use crate::{
    cli::ServeArgs,
    config::{HostSpec, parse_duration},
};

/// How long one dial may take before it counts as failed.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// First retry delay after a failed attempt; doubles per failure up to the
/// period.
const BACKOFF_START: Duration = Duration::from_secs(5);

/// Longest a doubling backoff is computed for (beyond that it is the cap
/// anyway).
const BACKOFF_STEPS: u32 = 16;

/// `ControlMsg::Shutdown` reason sent when `--connect-max` expires.
pub const MAX_CONNECTION_REASON: &str = "connect-back: max connection time";

/// A `--connect-back` address: `host[:port]`, default port 7722.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub host: String,
    pub port: u16,
}

impl Addr {
    /// Parse `host`, `host:port` or `[v6]:port`.
    pub fn parse(text: &str) -> Result<Self> {
        let spec: HostSpec = text
            .parse()
            .map_err(|e| anyhow::anyhow!("--connect-back {text}: {e}"))?;
        Ok(Self {
            host: spec.host,
            port: spec.port.unwrap_or(DEFAULT_PORT),
        })
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// `--connect-back` and its timing knobs.
#[derive(Debug, Clone)]
pub struct ConnectBackConfig {
    /// Clients to connect back to; empty switches the mode off.
    pub addrs: Vec<Addr>,
    /// Time from the start of one attempt to the start of the next
    /// (`--connect-period`).
    pub period: Duration,
    /// Uniform ± spread applied to every period (`--connect-jitter`).
    pub jitter_percent: u32,
    /// A connection older than this is closed by the server
    /// (`--connect-max`).
    pub max_connection: Duration,
}

impl Default for ConnectBackConfig {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            period: Duration::from_mins(5),
            jitter_percent: 10,
            max_connection: Duration::from_mins(30),
        }
    }
}

impl ConnectBackConfig {
    /// From `mysh serve` options; durations use the config-file syntax
    /// (`30s`, `5m`, `1h`).
    pub fn from_args(args: &ServeArgs) -> Result<Self> {
        let defaults = Self::default();
        let addrs = args
            .connect_back
            .iter()
            .map(|s| Addr::parse(s))
            .collect::<Result<Vec<_>>>()?;
        let period = match &args.connect_period {
            None => defaults.period,
            Some(text) => {
                parse_duration(text).map_err(|e| anyhow::anyhow!("--connect-period {text}: {e}"))?
            }
        };
        if period.is_zero() {
            bail!("--connect-period must be positive");
        }
        let max_connection = match &args.connect_max {
            None => defaults.max_connection,
            Some(text) => {
                parse_duration(text).map_err(|e| anyhow::anyhow!("--connect-max {text}: {e}"))?
            }
        };
        if max_connection.is_zero() {
            bail!("--connect-max must be positive");
        }
        Ok(Self {
            addrs,
            period,
            jitter_percent: args.connect_jitter.unwrap_or(defaults.jitter_percent),
            max_connection,
        })
    }
}

/// `period` scaled by a factor uniform in `[1 - p, 1 + p]` for `p =
/// jitter_percent / 100`; `unit` is the random draw in `[0, 1]`.
pub(crate) fn jittered(period: Duration, jitter_percent: u32, unit: f64) -> Duration {
    let spread = f64::from(jitter_percent.min(100)) / 100.0;
    let factor = (unit.clamp(0.0, 1.0) * 2.0 - 1.0).mul_add(spread, 1.0);
    period.mul_f64(factor)
}

/// Delay before the next attempt after `failures` consecutive failures
/// (at least one): 5 s, 10 s, 20 s, … capped at `period`.
pub(crate) fn backoff(failures: u32, period: Duration) -> Duration {
    let steps = failures.saturating_sub(1).min(BACKOFF_STEPS);
    BACKOFF_START.saturating_mul(1 << steps).min(period)
}

/// A uniform draw in `[0, 1]` from the OS.
fn random_unit() -> f64 {
    f64::from(rand_core::OsRng.next_u32()) / f64::from(u32::MAX)
}

/// Connect back to `addr` forever: one connection at a time, the next
/// attempt `period ± jitter` after the start of the previous one (sooner
/// only if that moment has already passed), failures backed off. Ends after
/// the current connection once `shutdown` carries a reason.
#[allow(clippy::needless_pass_by_value)] // owned by the spawned task
pub(crate) async fn run_loop(
    addr: Addr,
    shared: Arc<Shared>,
    cfg: ConnectBackConfig,
    tracker: TaskTracker,
    mut shutdown: watch::Receiver<Option<String>>,
) {
    let mut failures: u32 = 0;
    loop {
        if shutdown.borrow().is_some() {
            break;
        }
        let attempt_start = Instant::now();
        let next = match attempt(&addr, &shared, &cfg, &tracker, &shutdown).await {
            Ok(()) => {
                failures = 0;
                attempt_start + jittered(cfg.period, cfg.jitter_percent, random_unit())
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let delay = backoff(failures, cfg.period);
                if failures == 1 {
                    warn!(%addr, error = %e, "connect-back failed; retrying in {delay:?}");
                } else {
                    debug!(%addr, error = %e, failures, "connect-back failed again; retrying in {delay:?}");
                }
                Instant::now() + delay
            }
        };
        tokio::select! {
            () = tokio::time::sleep_until(next) => {}
            _ = shutdown.changed() => break,
        }
    }
    debug!(%addr, "connect-back loop stopped");
}

/// One attempt: dial, then serve the connection until it ends. `Err` for a
/// failed dial or a refused/failed handshake (the caller backs off).
async fn attempt(
    addr: &Addr,
    shared: &Arc<Shared>,
    cfg: &ConnectBackConfig,
    tracker: &TaskTracker,
    shutdown: &watch::Receiver<Option<String>>,
) -> Result<()> {
    let stream = match timeout(
        DIAL_TIMEOUT,
        TcpStream::connect((addr.host.as_str(), addr.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(e).with_context(|| format!("dial {addr}")),
        Err(_) => bail!("dial {addr}: timed out after {DIAL_TIMEOUT:?}"),
    };
    let peer = stream.peer_addr().context("peer address")?;
    let local = stream.local_addr().context("local address")?;
    debug!(%addr, %peer, "connected back; starting the handshake");
    let Ok(permit) = Arc::clone(&shared.handshakes).acquire_owned().await else {
        bail!("handshake limiter closed");
    };

    // The connection's own shutdown notice: the server's, or the
    // `--connect-max` deadline, whichever comes first.
    let (reason_tx, reason_rx) = watch::channel(None::<String>);
    let served = tracker.track_future(handle_connection(
        stream,
        peer,
        local,
        Arc::clone(shared),
        permit,
        reason_rx,
        Direction::Outbound,
    ));
    tokio::pin!(served);
    let deadline = tokio::time::sleep(cfg.max_connection);
    tokio::pin!(deadline);
    let mut server_shutdown = shutdown.clone();
    let mut notified = false;
    let authenticated = loop {
        tokio::select! {
            authenticated = &mut served => break authenticated,
            () = &mut deadline, if !notified => {
                notified = true;
                info!(%peer, max = ?cfg.max_connection, "connect-back: closing after the maximum connection time");
                let _ = reason_tx.send(Some(MAX_CONNECTION_REASON.to_owned()));
            }
            changed = server_shutdown.changed(), if !notified => {
                notified = true;
                let reason = if changed.is_ok() {
                    server_shutdown.borrow_and_update().clone()
                } else {
                    None
                }
                .unwrap_or_else(|| "server stopped".to_owned());
                let _ = reason_tx.send(Some(reason));
            }
        }
    };
    if authenticated {
        Ok(())
    } else {
        bail!("handshake with {addr} failed or was refused")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_defaults_the_port() {
        let a = Addr::parse("example.org").unwrap();
        assert_eq!(a.host, "example.org");
        assert_eq!(a.port, DEFAULT_PORT);
        assert_eq!(a.to_string(), "example.org:7722");
        let b = Addr::parse("10.0.0.1:9000").unwrap();
        assert_eq!((b.host.as_str(), b.port), ("10.0.0.1", 9000));
        let c = Addr::parse("[::1]:1").unwrap();
        assert_eq!((c.host.as_str(), c.port), ("::1", 1));
        assert_eq!(c.to_string(), "[::1]:1");
        assert!(Addr::parse("").is_err());
        assert!(Addr::parse("host:notaport").is_err());
    }

    #[test]
    fn jitter_spreads_symmetrically_and_zero_is_exact() {
        let period = Duration::from_secs(100);
        assert_eq!(jittered(period, 0, 0.0), period);
        assert_eq!(jittered(period, 0, 1.0), period);
        assert_eq!(jittered(period, 10, 0.0), Duration::from_secs(90));
        assert_eq!(jittered(period, 10, 0.5), period);
        assert_eq!(jittered(period, 10, 1.0), Duration::from_secs(110));
        // Out-of-range draws and percentages are clamped.
        assert_eq!(jittered(period, 250, 2.0), Duration::from_secs(200));
        assert_eq!(jittered(period, 100, -1.0), Duration::ZERO);
    }

    #[test]
    fn backoff_doubles_from_five_seconds_up_to_the_period() {
        let period = Duration::from_secs(300);
        assert_eq!(backoff(0, period), Duration::from_secs(5));
        assert_eq!(backoff(1, period), Duration::from_secs(5));
        assert_eq!(backoff(2, period), Duration::from_secs(10));
        assert_eq!(backoff(3, period), Duration::from_secs(20));
        assert_eq!(backoff(7, period), Duration::from_secs(300));
        assert_eq!(backoff(u32::MAX, period), period);
        // A period shorter than the first step caps immediately.
        assert_eq!(backoff(1, Duration::from_secs(1)), Duration::from_secs(1));
    }

    #[test]
    fn config_from_args_parses_durations_and_rejects_zero() {
        let defaults = ConnectBackConfig::from_args(&ServeArgs::default()).unwrap();
        assert!(defaults.addrs.is_empty(), "{:?}", defaults.addrs);
        assert_eq!(defaults.period, Duration::from_mins(5));
        assert_eq!(defaults.jitter_percent, 10);
        assert_eq!(defaults.max_connection, Duration::from_mins(30));

        let args = ServeArgs {
            connect_back: vec!["a".to_owned(), "b:1".to_owned()],
            connect_period: Some("1s".to_owned()),
            connect_jitter: Some(0),
            connect_max: Some("2m".to_owned()),
            ..ServeArgs::default()
        };
        let cfg = ConnectBackConfig::from_args(&args).unwrap();
        assert_eq!(cfg.addrs.len(), 2);
        assert_eq!(cfg.addrs[1].port, 1);
        assert_eq!(cfg.period, Duration::from_secs(1));
        assert_eq!(cfg.jitter_percent, 0);
        assert_eq!(cfg.max_connection, Duration::from_secs(120));

        let zero = ServeArgs {
            connect_period: Some("0".to_owned()),
            ..ServeArgs::default()
        };
        assert!(ConnectBackConfig::from_args(&zero).is_err());
        let bad = ServeArgs {
            connect_max: Some("soon".to_owned()),
            ..ServeArgs::default()
        };
        assert!(ConnectBackConfig::from_args(&bad).is_err());
    }
}
