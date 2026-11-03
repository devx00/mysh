//! `mysh pair HOST CODE` (docs/02-security.md "Pairing"): connect with the
//! normal identity but an *unverified* server key, ask for a pairing-only
//! connection (`caps::PAIR_REQUEST`), run SPAKE2 with the one-time code,
//! and only after the server's confirmation MAC verifies pin its key in
//! `known_hosts`. The server installs our key on its side.

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_net::{
    framing::{read_msg, write_msg},
    handshake::{ClientAuth, HandshakeError, Handshaken, client_handshake},
    keys::{PublicKey, SecretKey},
    mux::{Mode, Mux},
    pairing::{Pake, Transcript},
    trust::KnownHosts,
};
use mysh_proto::{
    caps,
    control::ControlMsg,
    open::Open,
    pair::{PairMsg, normalize_code},
};
use tokio::time::timeout;
use tracing::{debug, info};

use crate::{
    client::{
        conn::{AgentSigner, dial},
        console::Console,
    },
    config::{Paths, Target},
    identity::{Baked, ClientIdentity, client_identities},
    output::{Mode as OutputMode, PairOut, coded, codes},
};

/// Client-side bound on the whole exchange.
const PAIR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Run `mysh pair`; returns the process exit code (0 on success). Errors
/// are usage/trust failures (exit 2 by the caller).
pub async fn run(
    target: &Target,
    code: &str,
    paths: &Paths,
    baked: &Baked,
    mode: OutputMode,
) -> Result<i32> {
    let console = Console::with_mode(mode);
    let code = normalize_code(code);
    if code.is_empty() {
        bail!("empty pairing code");
    }
    let identities = client_identities(target, paths, baked).await?;
    let identity = identities
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no client identity"))?;
    let result = timeout(PAIR_TIMEOUT, pair(target, &identity, &code, paths)).await;
    let out = match result {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            console.flush().await;
            return Err(e);
        }
        Err(_) => {
            console.flush().await;
            return Err(coded(codes::TIMEOUT, anyhow!("pairing timed out")));
        }
    };
    console.report(&out, || {
        format!(
            "paired with {}\n  server {}\n  client {}\n  installed on the server: {}\n  installed in {}: {}\n",
            out.host,
            out.server_fingerprint,
            out.client_fingerprint,
            out.authorized_line,
            paths.known_hosts.display(),
            out.host_line,
        )
    });
    console.flush().await;
    Ok(0)
}

/// Dial and handshake as a pairing-only connection: the server key is
/// accepted unverified and returned alongside our Noise static for the
/// PAKE to bind; nothing is pinned here.
async fn pairing_handshake(
    target: &Target,
    identity: &ClientIdentity,
) -> Result<(Handshaken<tokio::net::TcpStream>, PublicKey)> {
    let fresh;
    let mut signer;
    let (static_key, auth) = match identity {
        ClientIdentity::Static(id) => (&id.secret, ClientAuth::Static),
        ClientIdentity::Agent { socket, key } => {
            signer = AgentSigner::connect(socket, key.clone()).await?;
            fresh = SecretKey::generate();
            (
                &fresh,
                ClientAuth::Ed25519 {
                    public: key.public,
                    sign: &mut signer,
                },
            )
        }
    };
    let client_static = static_key.public();
    let tcp = dial(&target.host, target.port).await?;
    let verify = |_key: &PublicKey,
                  _hello: &mysh_proto::handshake::ServerHello|
     -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) };
    let (handshaken, hello) = match client_handshake(
        tcp,
        static_key,
        caps::PAIR_REQUEST,
        verify,
        auth,
    )
    .await
    {
        Ok(ok) => ok,
        Err(HandshakeError::Denied { code, message }) => {
            return Err(coded(
                codes::UNAUTHORIZED,
                anyhow!(
                    "server has no pairing window open ({code}: {message}); run `mysh serve --pair` or send it SIGUSR1"
                ),
            ));
        }
        Err(e) => {
            return Err(anyhow::Error::from(e).context(format!(
                "handshake with {}:{} failed",
                target.host, target.port
            )));
        }
    };
    if !handshaken.pairing {
        // Our key is already authorized; nothing to pair.
        bail!(
            "server has no pairing window open (it accepted our key {} as already authorized)",
            identity.fingerprint()
        );
    }
    debug!(
        server = %hello.name,
        version = handshaken.version,
        fingerprint = %handshaken.remote.fingerprint(),
        "pairing connection"
    );
    Ok((handshaken, client_static))
}

/// Run the whole pairing against `target` and pin the server key.
async fn pair(
    target: &Target,
    identity: &ClientIdentity,
    code: &str,
    paths: &Paths,
) -> Result<PairOut> {
    let (handshaken, client_static) = pairing_handshake(target, identity).await?;
    let server_static = handshaken.remote;
    let (mux, _incoming) = Mux::new(handshaken.stream, Mode::Client);
    let mut control = mux
        .open(&Open::Control)
        .await
        .context("opening control stream")?;
    let mut stream = mux
        .open(&Open::Pair)
        .await
        .context("opening the pairing stream")?;

    let authorized_line = exchange(&mut stream, code, client_static, server_static).await?;

    // Both MACs verified: the server key is now trusted for this host.
    KnownHosts::append(
        &paths.known_hosts,
        &target.host,
        target.port,
        &server_static,
    )
    .with_context(|| format!("writing {}", paths.known_hosts.display()))?;
    let host_line = known_hosts_line(&target.host, target.port, &server_static);
    info!(
        host = %target.display,
        server = %server_static.fingerprint(),
        client = %identity.fingerprint(),
        "paired"
    );

    let _ = timeout(
        std::time::Duration::from_secs(1),
        write_msg(
            &mut control,
            &ControlMsg::Shutdown {
                reason: "paired".to_owned(),
            },
        ),
    )
    .await;
    mux.close().await;
    Ok(PairOut {
        host: target.display.clone(),
        server_fingerprint: server_static.fingerprint().to_string(),
        client_fingerprint: identity.fingerprint().to_string(),
        authorized_line,
        host_line,
    })
}

/// The `PairMsg` exchange on an open `Pair` stream; returns the
/// `authorized_keys` line the server installed. Nothing is written
/// locally in here.
async fn exchange(
    stream: &mut mysh_net::mux::Stream,
    code: &str,
    client_static: PublicKey,
    server_static: PublicKey,
) -> Result<String> {
    let (pake, client_msg) = Pake::start_client(code, &client_static, &server_static);
    write_msg(
        stream,
        &PairMsg::ClientStart {
            msg: client_msg.clone(),
        },
    )
    .await?;
    let server_msg = match read_msg::<_, PairMsg>(stream).await? {
        PairMsg::ServerStart { msg } => msg,
        PairMsg::Failed { reason } => bail!("server refused pairing: {reason}"),
        other => bail!("protocol error: unexpected {other:?}"),
    };
    let key = pake
        .finish(&server_msg)
        .context("server sent a malformed pairing message")?;
    let transcript = Transcript {
        client_static,
        server_static,
        client_msg,
        server_msg,
    };
    write_msg(
        stream,
        &PairMsg::ClientConfirm {
            mac: key.confirm_client(&transcript),
        },
    )
    .await?;
    let mac = match read_msg::<_, PairMsg>(stream).await? {
        PairMsg::ServerConfirm { mac } => mac,
        PairMsg::Failed { reason } => {
            return Err(coded(
                codes::UNAUTHORIZED,
                anyhow!("server did not know the code ({reason})"),
            ));
        }
        other => bail!("protocol error: unexpected {other:?}"),
    };
    if key.verify_server(&transcript, &mac).is_err() {
        return Err(coded(
            codes::TRUST_MISMATCH,
            anyhow!("server did not know the code (confirmation failed); nothing was written"),
        ));
    }
    match read_msg::<_, PairMsg>(stream).await? {
        PairMsg::Done {
            authorized_line, ..
        } => Ok(authorized_line),
        PairMsg::Failed { reason } => bail!("server could not install our key: {reason}"),
        other => bail!("protocol error: unexpected {other:?}"),
    }
}

/// The line [`KnownHosts::append`] writes, without its newline.
fn known_hosts_line(host: &str, port: u16, key: &PublicKey) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let host_field = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    format!("{host_field} {}", key.to_line(None).trim_end())
}
