//! Pairing on the server (docs/02-security.md "Pairing"): the single-use
//! code window, and the `Open::Pair` handler that runs SPAKE2 with the
//! client and installs its key in `authorized_keys`.
//!
//! A pairing-only connection (`Verdict::Pairing`) reaches
//! [`dispatch`] instead of the normal dispatcher: `Control` is taken by the
//! connection setup, `Pair` runs the protocol, everything else is `Denied`.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mysh_net::{
    agent::ed25519_blob,
    framing::{read_msg, write_msg, write_reply},
    handshake::Peer,
    keys::{PublicKey, SSH_ED25519_TYPE},
    mux::{Stream, accept_open},
    pairing::{Pake, Transcript},
    trust::AuthorizedKeys,
};
use mysh_proto::{
    limits::{self, OPEN_REPLY_DEADLINE},
    open::{ErrorCode, Open, OpenReply},
    pair::{CODE_WORDS, PairMsg, normalize_code},
};
use tokio::{io::AsyncWriteExt as _, time::timeout};
use tracing::{debug, info, warn};

use crate::{output::rfc3339, wordlist::WORDS};

use super::{audit, files::send_error};

/// Pairing settings of one server ([`super::ServerConfig::pairing`]).
#[derive(Debug, Clone)]
pub struct PairConfig {
    /// Where paired client keys are appended.
    pub authorized_keys: PathBuf,
    /// A window to open at start: `(code, duration)`.
    pub window: Option<(String, Duration)>,
}

/// One pairing window: a code valid until `until`, single use.
#[derive(Debug, Clone)]
pub struct PairWindow {
    /// Normalized (`normalize_code`).
    pub code: String,
    pub opened: Instant,
    pub until: Instant,
    pub used: bool,
}

impl PairWindow {
    fn is_open(&self, now: Instant) -> bool {
        !self.used && now < self.until
    }
}

/// Server-wide pairing state: the current window (if any) and the file
/// paired keys go to.
#[derive(Debug)]
pub struct PairState {
    authorized_keys: PathBuf,
    window: Mutex<Option<PairWindow>>,
}

impl PairState {
    pub fn new(cfg: &PairConfig) -> Self {
        let state = Self {
            authorized_keys: cfg.authorized_keys.clone(),
            window: Mutex::new(None),
        };
        if let Some((code, duration)) = &cfg.window {
            state.open(code, *duration);
        }
        state
    }

    /// Open a window with `code` for `duration`, replacing any current one.
    /// Returns the normalized code.
    pub fn open(&self, code: &str, duration: Duration) -> String {
        let code = normalize_code(code);
        let now = Instant::now();
        let window = PairWindow {
            code: code.clone(),
            opened: now,
            until: now + duration,
            used: false,
        };
        *self.window.lock().unwrap_or_else(PoisonError::into_inner) = Some(window);
        code
    }

    /// Open a window with a fresh random code and announce it on stderr and
    /// in the log (`mysh serve --pair`, `SIGUSR1`).
    pub fn open_random(&self, duration: Duration) -> String {
        let code = self.open(
            &mysh_net::pairing::generate_code(WORDS, CODE_WORDS),
            duration,
        );
        let valid = format_duration(duration);
        eprintln!("pairing code: {code} (valid {valid}, single use)");
        info!(%code, %valid, "pairing window open");
        code
    }

    /// Whether a client asking to pair may be admitted right now.
    pub fn is_open(&self) -> bool {
        self.window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|w| w.is_open(Instant::now()))
    }

    /// The code of the open window, if any (expiry checked now).
    fn code(&self) -> Option<String> {
        self.window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|w| w.is_open(Instant::now()))
            .map(|w| w.code.clone())
    }

    /// Mark the window used (success or a wrong code both close it).
    fn close(&self) {
        if let Some(w) = self
            .window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            w.used = true;
        }
    }
}

/// `5m`, `90s`, `250ms`: how `--pair` durations are echoed.
fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(60_000) && ms > 0 {
        format!("{}m", ms / 60_000)
    } else if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

/// What a pairing-only connection's stream handler needs.
#[derive(Debug, Clone)]
pub struct PairCtx {
    pub state: std::sync::Arc<PairState>,
    pub peer: SocketAddr,
    /// Who the client proved to be (the key that gets installed).
    pub client: Peer,
    /// The client's Noise static (SPAKE2 identity A).
    pub client_static: PublicKey,
    /// The server's static public key (SPAKE2 identity B).
    pub server_static: PublicKey,
    /// `ServerHello.name`, used as the comment of the host line.
    pub server_name: String,
    pub audit: audit::Handle,
}

/// Stream dispatcher for pairing-only connections.
pub async fn dispatch(mut stream: Stream, ctx: PairCtx) {
    let open = match timeout(OPEN_REPLY_DEADLINE, accept_open(&mut stream)).await {
        Err(_) | Ok(Err(_)) => return,
        Ok(Ok(Err(tag))) => {
            send_error(
                &mut stream,
                ErrorCode::Unsupported,
                &format!("unknown stream kind {tag}"),
            )
            .await;
            return;
        }
        Ok(Ok(Ok(open))) => open,
    };
    match open {
        Open::Pair => handle_pair(stream, ctx).await,
        Open::Control => {
            send_error(
                &mut stream,
                ErrorCode::Protocol,
                "control stream already open",
            )
            .await;
        }
        other => {
            debug!(peer = %ctx.peer, kind = ?other.kind(), "denied on a pairing-only connection");
            send_error(
                &mut stream,
                ErrorCode::Denied,
                "this connection is pairing-only",
            )
            .await;
        }
    }
}

/// Run the pairing protocol on an accepted `Open::Pair` stream.
async fn handle_pair(mut stream: Stream, ctx: PairCtx) {
    if write_reply(&mut stream, &OpenReply::Ok).await.is_err() {
        return;
    }
    let outcome = timeout(limits::HANDSHAKE_DEADLINE, run(&mut stream, &ctx)).await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => {
            warn!(peer = %ctx.peer, client = %ctx.client, %reason, "pairing failed");
            ctx.audit.denied("pair", reason);
            let _ = write_msg(
                &mut stream,
                &PairMsg::Failed {
                    reason: reason.to_owned(),
                },
            )
            .await;
        }
        Err(_) => {
            warn!(peer = %ctx.peer, "pairing timed out");
        }
    }
    let _ = stream.shutdown().await;
}

/// The protocol proper; an `Err` is the reason sent in `Failed`.
async fn run(stream: &mut Stream, ctx: &PairCtx) -> Result<(), &'static str> {
    let Some(code) = ctx.state.code() else {
        return Err("no pairing window");
    };
    let client_msg = match read_msg::<_, PairMsg>(stream).await {
        Ok(PairMsg::ClientStart { msg }) => msg,
        Ok(PairMsg::Failed { reason }) => {
            debug!(peer = %ctx.peer, %reason, "client aborted pairing");
            return Err("client aborted");
        }
        Ok(_) => return Err("protocol error: expected ClientStart"),
        Err(_) => return Err("connection lost"),
    };
    let (pake, server_msg) = Pake::start_server(&code, &ctx.client_static, &ctx.server_static);
    if write_msg(
        stream,
        &PairMsg::ServerStart {
            msg: server_msg.clone(),
        },
    )
    .await
    .is_err()
    {
        return Err("connection lost");
    }
    let Ok(key) = pake.finish(&client_msg) else {
        ctx.state.close();
        return Err("bad code");
    };
    let transcript = Transcript {
        client_static: ctx.client_static,
        server_static: ctx.server_static,
        client_msg,
        server_msg,
    };
    let mac = match read_msg::<_, PairMsg>(stream).await {
        Ok(PairMsg::ClientConfirm { mac }) => mac,
        Ok(_) => return Err("protocol error: expected ClientConfirm"),
        Err(_) => return Err("connection lost"),
    };
    // Either way the window is spent: a wrong code must not be retried
    // against the same code (docs/02-security.md "Pairing").
    ctx.state.close();
    if key.verify_client(&transcript, &mac).is_err() {
        return Err("bad code");
    }
    let authorized_line = authorized_line(&ctx.client);
    if let Err(e) = AuthorizedKeys::append_raw_line(&ctx.state.authorized_keys, &authorized_line) {
        warn!(
            path = %ctx.state.authorized_keys.display(),
            error = %e,
            "cannot append the paired key"
        );
        return Err("cannot write authorized_keys");
    }
    info!(
        peer = %ctx.peer,
        client = %ctx.client,
        path = %ctx.state.authorized_keys.display(),
        "paired: client key installed"
    );
    ctx.audit.emit(audit::Event::Pair, || {
        serde_json::json!({
            "outcome": "paired",
            "path": ctx.state.authorized_keys.display().to_string(),
        })
    });
    let host_line = ctx.server_static.to_line(Some(&ctx.server_name));
    let confirm = PairMsg::ServerConfirm {
        mac: key.confirm_server(&transcript),
    };
    let done = PairMsg::Done {
        authorized_line: authorized_line.trim_end().to_owned(),
        host_line: host_line.trim_end().to_owned(),
    };
    if write_msg(stream, &confirm).await.is_err() || write_msg(stream, &done).await.is_err() {
        return Err("connection lost");
    }
    Ok(())
}

/// The `authorized_keys` line for a paired client, dated.
fn authorized_line(client: &Peer) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let comment = format!("paired {}", rfc3339(now));
    match client {
        Peer::Static(key) => key.to_line(Some(&comment)),
        Peer::Ed25519(pk) => format!(
            "{SSH_ED25519_TYPE} {} {comment}\n",
            STANDARD.encode(ed25519_blob(pk))
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_single_use_and_expires() {
        let state = PairState::new(&PairConfig {
            authorized_keys: PathBuf::from("/nonexistent"),
            window: None,
        });
        assert!(!state.is_open());
        assert_eq!(
            state.open("Apple Bread", Duration::from_secs(60)),
            "apple-bread"
        );
        assert!(state.is_open());
        assert_eq!(state.code().as_deref(), Some("apple-bread"));
        state.close();
        assert!(!state.is_open());
        assert!(state.code().is_none());
        // Reopening replaces the spent window.
        state.open("x-y", Duration::ZERO);
        assert!(!state.is_open(), "an already expired window is closed");
    }

    #[test]
    fn random_codes_use_the_word_list() {
        let state = PairState::new(&PairConfig {
            authorized_keys: PathBuf::from("/nonexistent"),
            window: None,
        });
        let code = state.open_random(Duration::from_secs(1));
        let words: Vec<&str> = code.split('-').collect();
        assert_eq!(words.len(), CODE_WORDS);
        assert!(words.iter().all(|w| WORDS.binary_search(w).is_ok()));
    }

    #[test]
    fn authorized_lines_parse_back() {
        let key = mysh_net::keys::SecretKey::generate().public();
        let line = authorized_line(&Peer::Static(key));
        let keys = AuthorizedKeys::parse(&line, "t");
        assert!(keys.contains(&key));
        assert!(line.contains(" paired 20"));
        // The Ed25519 base point: a valid public key.
        let mut ed = [0x66u8; 32];
        ed[0] = 0x58;
        let line = authorized_line(&Peer::Ed25519(ed));
        let keys = AuthorizedKeys::parse(&line, "t");
        assert!(keys.find_ed25519(&ed).is_some());
    }

    #[test]
    fn durations_format() {
        assert_eq!(format_duration(Duration::from_secs(300)), "5m");
        assert_eq!(format_duration(Duration::from_secs(90)), "90s");
        assert_eq!(format_duration(Duration::from_millis(250)), "250ms");
    }
}
