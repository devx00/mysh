//! Client identity and trust resolution (docs/02-security.md: "Identity
//! resolution", "Server trust", "Baked keys"): which keys the client
//! offers, how it judges the server's key, and the compiled-in material.
//!
//! Nothing here prompts: encrypted keys get their passphrase from a
//! caller-supplied [`PassphraseFn`], and TOFU decisions are made by the
//! [`crate::TrustPrompt`] of [`crate::conn::connect`].

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mysh_net::agent::{Agent, AgentKey, parse_ed25519_blob};
use mysh_net::keys::{
    Fingerprint, Identity, PUBLIC_KEY_TYPE, PublicKey, SSH_ED25519_TYPE, load_secret_key,
    parse_secret_key,
};
use mysh_net::trust::{AuthorizedKeys, HostMatch, KnownHosts, Pin};
use mysh_proto::limits::MAX_AGENT_KEYS;
use tracing::{debug, warn};

use crate::config::{IdentitySource, Paths, Target, client_identity_candidates, expand_tilde};

/// Source label used for compiled-in material.
pub const BAKED: &str = "baked";

/// Supplies the passphrase of an encrypted key file named by its source
/// label; an error leaves the key unusable.
pub type PassphraseFn<'a> = &'a mut (dyn FnMut(&str) -> io::Result<String> + Send);

/// Key material compiled in with `--features baked`, parsed once at startup.
#[derive(Debug, Default, Clone)]
pub struct Baked {
    /// The compiled-in private identity, if any.
    pub identity: Option<Identity>,
    /// Compiled-in trusted peers (empty without the feature).
    pub peers: AuthorizedKeys,
}

impl Baked {
    /// Parse the compiled-in private key and `authorized_keys`-format
    /// peers. A passphrase-protected baked identity is an error: nobody
    /// is there to type it.
    pub fn parse(identity: Option<&str>, peers: Option<&str>) -> Result<Self> {
        let identity = match identity {
            Some(text) => {
                let mut no_passphrase = |_hint: &str| -> io::Result<String> {
                    Err(io::Error::other(
                        "baked identity must not be passphrase-protected",
                    ))
                };
                Some(
                    parse_secret_key(text, BAKED, &mut no_passphrase)
                        .context("compiled-in identity is unusable")?,
                )
            }
            None => None,
        };
        let peers = peers
            .map(|text| AuthorizedKeys::parse(text, BAKED))
            .unwrap_or_default();
        Ok(Self { identity, peers })
    }
}

/// Home directory for `~` expansion of configured paths and for display.
fn home_dir(paths: &Paths) -> Option<PathBuf> {
    paths
        .ssh_dir
        .as_ref()
        .and_then(|d| d.parent().map(Path::to_path_buf))
        .or_else(dirs::home_dir)
}

/// Render `path` with the home directory abbreviated to `~`, for messages
/// such as `~/.config/mysh/known_hosts:12`.
fn tildify(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home
        && let Ok(rest) = path.strip_prefix(home)
    {
        if rest.as_os_str().is_empty() {
            return "~".to_owned();
        }
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

/// `PATH (flag)`, `PATH (environment)`, `baked`, or the file path.
pub fn describe(source: &IdentitySource) -> String {
    match source {
        IdentitySource::Flag(p) => format!("{} (flag)", p.display()),
        IdentitySource::Env(p) => format!("{} (environment)", p.display()),
        IdentitySource::Baked => BAKED.to_owned(),
        IdentitySource::File(p) => p.display().to_string(),
    }
}

/// Try the candidates in order. Explicit sources (flag, environment) must
/// exist; well-known files are skipped when missing. A candidate that exists
/// but fails to load is an error, never skipped.
///
/// Returns `Ok(None)` when every candidate was skipped; `missing_file`
/// receives the first well-known file that did not exist so the caller can
/// decide to generate it.
pub fn load_first(
    candidates: &[IdentitySource],
    baked: &Baked,
    missing_file: &mut Option<PathBuf>,
    passphrase: PassphraseFn<'_>,
) -> Result<Option<Identity>> {
    let mut prompt = passphrase;
    for candidate in candidates {
        match candidate {
            IdentitySource::Baked => {
                if let Some(id) = &baked.identity {
                    debug!("using compiled-in identity");
                    return Ok(Some(id.clone()));
                }
            }
            IdentitySource::Flag(path) | IdentitySource::Env(path) => {
                let id = load_secret_key(path, &mut prompt)
                    .with_context(|| format!("loading identity {}", describe(candidate)))?;
                return Ok(Some(id));
            }
            IdentitySource::File(path) => {
                if !path.exists() {
                    if missing_file.is_none() {
                        *missing_file = Some(path.clone());
                    }
                    continue;
                }
                let id = load_secret_key(path, &mut prompt)
                    .with_context(|| format!("loading identity {}", path.display()))?;
                debug!(path = %path.display(), "using identity");
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

/// Who the client authenticates as (docs/02-security.md, "Identity
/// resolution" and "Signature authentication").
#[derive(Debug, Clone)]
pub enum ClientIdentity {
    /// A loaded private key: the Noise static is the identity.
    Static(Identity),
    /// An ed25519 key held by the `ssh-agent` at `socket`: the Noise static
    /// is fresh per connection and the agent signs the handshake hash.
    Agent {
        /// SSH agent socket path.
        socket: PathBuf,
        /// SSH agent key.
        key: AgentKey,
    },
}

impl ClientIdentity {
    /// Fingerprint of the identity's public key.
    pub fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Static(id) => id.public.fingerprint(),
            Self::Agent { key, .. } => Fingerprint::of_ssh_ed25519(&key.public),
        }
    }

    /// The public key as an `authorized_keys` line (for `authorize`):
    /// `mysh-x25519 …` for a key file, `ssh-ed25519 …` for an agent key.
    pub fn public_line(&self) -> String {
        match self {
            Self::Static(id) => id.public.to_line(id.comment.as_deref()),
            Self::Agent { key, .. } => {
                let b64 = STANDARD.encode(&key.blob);
                match key.comment.trim() {
                    "" => format!("{SSH_ED25519_TYPE} {b64}\n"),
                    comment => format!("{SSH_ED25519_TYPE} {b64} {comment}\n"),
                }
            }
        }
    }

    /// `x25519 SHA256:… (path)` or `ssh-ed25519 SHA256:… (agent: comment)`.
    pub fn describe(&self) -> String {
        match self {
            Self::Static(id) => format!("x25519 {} ({})", id.public.fingerprint(), id.source),
            Self::Agent { key, .. } => format!(
                "{SSH_ED25519_TYPE} {} (agent: {})",
                self.fingerprint(),
                key.comment
            ),
        }
    }
}

/// `Some(pk)` when `path` holds an `ssh-ed25519` public key line (an OpenSSH
/// `.pub` file), naming a key the agent must hold. `None` for a private key
/// (loaded by the caller) and for unreadable files (the caller's loader
/// reports those). A public key of another type is an error: nothing can
/// authenticate with it.
fn ssh_ed25519_public_file(path: &Path) -> Result<Option<[u8; 32]>> {
    let is_pub = path.extension().is_some_and(|e| e == "pub");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if is_pub => return Err(e).with_context(|| format!("reading {}", path.display())),
        Err(_) => return Ok(None),
    };
    let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    else {
        if is_pub {
            bail!("{}: empty public key file", path.display());
        }
        return Ok(None);
    };
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some(SSH_ED25519_TYPE) => {
            let pk = tokens
                .next()
                .and_then(|b64| STANDARD.decode(b64).ok())
                .and_then(|blob| parse_ed25519_blob(&blob))
                .ok_or_else(|| {
                    anyhow!(
                        "{}: malformed {SSH_ED25519_TYPE} public key",
                        path.display()
                    )
                })?;
            Ok(Some(pk))
        }
        Some(PUBLIC_KEY_TYPE) => bail!(
            "{}: a {PUBLIC_KEY_TYPE} public key cannot authenticate; pass the private key file",
            path.display()
        ),
        _ if is_pub => bail!("{}: not an {SSH_ED25519_TYPE} public key", path.display()),
        _ => Ok(None),
    }
}

/// The agent identity for the ed25519 key `pk` named by `path`.
async fn agent_key_named(paths: &Paths, path: &Path, pk: [u8; 32]) -> Result<ClientIdentity> {
    let fingerprint = Fingerprint::of_ssh_ed25519(&pk);
    let Some(socket) = &paths.agent_socket else {
        bail!(
            "{}: a public key selects an ssh-agent key, but $SSH_AUTH_SOCK is not set",
            path.display()
        );
    };
    let mut agent = Agent::connect(socket)
        .await
        .with_context(|| format!("connecting to ssh-agent at {}", socket.display()))?;
    let keys = agent
        .list_ed25519()
        .await
        .context("listing ssh-agent keys")?;
    let key = keys.into_iter().find(|k| k.public == pk).ok_or_else(|| {
        anyhow!(
            "{}: key {fingerprint} not in agent ({})",
            path.display(),
            socket.display()
        )
    })?;
    debug!(%fingerprint, comment = %key.comment, "using ssh-agent key named by -i");
    Ok(ClientIdentity::Agent {
        socket: socket.clone(),
        key,
    })
}

/// Up to [`MAX_AGENT_KEYS`] ed25519 keys from `$SSH_AUTH_SOCK`, in agent
/// order. An unreachable or failing agent is skipped with a `debug` log.
async fn agent_identities(paths: &Paths) -> Vec<ClientIdentity> {
    let Some(socket) = &paths.agent_socket else {
        return Vec::new();
    };
    let mut agent = match Agent::connect(socket).await {
        Ok(agent) => agent,
        Err(e) => {
            debug!(socket = %socket.display(), error = %e, "ssh-agent unreachable; skipping agent keys");
            return Vec::new();
        }
    };
    let keys = match agent.list_ed25519().await {
        Ok(keys) => keys,
        Err(e) => {
            debug!(socket = %socket.display(), error = %e, "ssh-agent listing failed; skipping agent keys");
            return Vec::new();
        }
    };
    if keys.len() > MAX_AGENT_KEYS {
        debug!(
            held = keys.len(),
            limit = MAX_AGENT_KEYS,
            "ssh-agent holds more ed25519 keys than will be tried"
        );
    }
    keys.into_iter()
        .take(MAX_AGENT_KEYS)
        .map(|key| ClientIdentity::Agent {
            socket: socket.clone(),
            key,
        })
        .collect()
}

/// Resolve the identities the client offers, in order.
///
/// `-i PATH` alone: a private key as before, or a `.pub` / `ssh-ed25519`
/// public line naming a key the agent must hold. Otherwise the first
/// existing key (`$MYSH_IDENTITY` → baked → `~/.config/mysh/id` →
/// `~/.ssh/id_ed25519`) followed by up to [`MAX_AGENT_KEYS`] agent keys;
/// `--baked-only` offers the baked identity only.
pub async fn client_identities(
    target: &Target,
    paths: &Paths,
    baked: &Baked,
    passphrase: PassphraseFn<'_>,
) -> Result<Vec<ClientIdentity>> {
    let home = home_dir(paths);
    let flag = target.identity.as_ref().map(|p| match (p.to_str(), &home) {
        (Some(s), Some(home)) => expand_tilde(s, home),
        _ => p.clone(),
    });
    if let Some(path) = &flag
        && let Some(pk) = ssh_ed25519_public_file(path)?
    {
        return Ok(vec![agent_key_named(paths, path, pk).await?]);
    }
    let candidates = client_identity_candidates(
        flag.as_deref(),
        paths,
        baked.identity.is_some(),
        target.baked_only,
    );
    let mut missing = None;
    let mut identities = Vec::new();
    if let Some(id) = load_first(&candidates, baked, &mut missing, passphrase)? {
        identities.push(ClientIdentity::Static(id));
    }
    let use_agent = flag.is_none() && !target.baked_only;
    if use_agent {
        identities.extend(agent_identities(paths).await);
    }
    if identities.is_empty() {
        let mut tried: Vec<String> = candidates.iter().map(describe).collect();
        if use_agent {
            tried.push(match &paths.agent_socket {
                Some(socket) => format!("ssh-agent at {}", socket.display()),
                None => "ssh-agent ($SSH_AUTH_SOCK unset)".to_owned(),
            });
        }
        bail!(
            "no client identity found (tried: {}); run `mysh keygen`, pass -i PATH, or add a key to ssh-agent",
            if tried.is_empty() {
                "nothing".to_owned()
            } else {
                tried.join(", ")
            }
        )
    }
    Ok(identities)
}

/// `PATH.pub` next to a private key.
pub fn pub_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Read a trust file, ignoring a missing one. Other errors are logged and
/// treated as empty: a transiently unreadable file must not grant access, and
/// it cannot, since "empty" only ever removes keys from the union.
pub fn read_trust_file(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read trust file; ignoring it");
            None
        }
    }
}

/// How the client decides whether to trust a server key.
#[derive(Debug, Clone)]
pub struct ClientTrust {
    /// `--pin`, checked first.
    pub pin: Option<Pin>,
    /// Compiled-in peers.
    pub baked: AuthorizedKeys,
    /// `known_hosts` files in check order: mysh's, then `~/.ssh/known_hosts`.
    pub known_hosts: Vec<PathBuf>,
    /// Where TOFU acceptances are appended (`~/.config/mysh/known_hosts`).
    pub write_to: PathBuf,
    /// `--accept-new`.
    pub accept_new: bool,
    /// `--strict`.
    pub strict: bool,
}

/// Outcome of [`ClientTrust::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// The key is trusted; `via` names the source (`pin`, `baked`,
    /// `~/.config/mysh/known_hosts:12`).
    Trusted {
        /// Human-readable source of the trust.
        via: String,
    },
    /// A different key is recorded for this host (or the pin disagrees).
    Mismatch {
        /// File (or `pin`) holding the conflicting entry.
        source: String,
        /// 1-based line within `source`; 0 for the pin.
        line: usize,
        /// Fingerprint of the key that was expected.
        expected: Fingerprint,
    },
    /// Nothing known about this host.
    Unknown,
}

impl fmt::Display for TrustDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trusted { via } => write!(f, "trusted via {via}"),
            Self::Mismatch {
                source,
                line,
                expected,
            } => write!(f, "mismatch against {source}:{line} (expected {expected})"),
            Self::Unknown => f.write_str("unknown host key"),
        }
    }
}

impl ClientTrust {
    /// Build the trust policy for `target`. Fails only when `--pin` is not a
    /// fingerprint or public key.
    pub fn for_target(target: &Target, paths: &Paths, baked: &Baked) -> Result<Self> {
        let pin = match &target.pin {
            Some(s) => Some(
                s.parse::<Pin>()
                    .with_context(|| format!("--pin {s:?} is not a fingerprint or public key"))?,
            ),
            None => None,
        };
        let known_hosts = if target.baked_only {
            Vec::new()
        } else {
            let mut files = vec![paths.known_hosts.clone()];
            if let Some(ssh) = &paths.ssh_dir {
                files.push(ssh.join("known_hosts"));
            }
            files
        };
        Ok(Self {
            pin,
            baked: baked.peers.clone(),
            known_hosts,
            write_to: paths.known_hosts.clone(),
            accept_new: target.accept_new,
            strict: target.strict,
        })
    }

    /// Check `key` for `host:port`: pin → baked peers → `known_hosts` files in
    /// order. A match anywhere wins; otherwise a mismatch from any file wins
    /// over unknown.
    pub fn evaluate(&self, host: &str, port: u16, key: &PublicKey) -> TrustDecision {
        if let Some(pin) = &self.pin {
            if pin.matches(key) {
                return TrustDecision::Trusted {
                    via: "pin".to_owned(),
                };
            }
            let expected = match pin {
                Pin::Fingerprint(fp) => fp.clone(),
                Pin::Key(k) => k.fingerprint(),
            };
            return TrustDecision::Mismatch {
                source: "pin".to_owned(),
                line: 0,
                expected,
            };
        }
        if self.baked.contains(key) {
            return TrustDecision::Trusted {
                via: BAKED.to_owned(),
            };
        }
        let home = dirs::home_dir();
        let mut mismatch = None;
        for path in &self.known_hosts {
            let Some(text) = read_trust_file(path) else {
                continue;
            };
            let label = tildify(path, home.as_deref());
            match KnownHosts::parse(&text, &label).check(host, port, key) {
                HostMatch::Match { source, line } => {
                    return TrustDecision::Trusted {
                        via: format!("{source}:{line}"),
                    };
                }
                HostMatch::Mismatch {
                    source,
                    line,
                    expected,
                } => {
                    if mismatch.is_none() {
                        mismatch = Some(TrustDecision::Mismatch {
                            source,
                            line,
                            expected,
                        });
                    }
                }
                HostMatch::Unknown => {}
            }
        }
        mismatch.unwrap_or(TrustDecision::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use mysh_net::keys::{SecretKey, write_secret_key};

    use super::*;

    fn no_pass(source: &str) -> io::Result<String> {
        Err(io::Error::other(format!(
            "{source}: no passphrase in tests"
        )))
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "mysh-identity-{tag}-{}-{}-{n}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key() -> PublicKey {
        SecretKey::generate().public()
    }

    fn paths_in(dir: &TempDir) -> Paths {
        let mut paths = Paths::with_config_dir(dir.path("config"));
        paths.ssh_dir = Some(dir.path("ssh"));
        // Never consult the developer's real agent from a unit test.
        paths.agent_socket = None;
        paths
    }

    fn target() -> Target {
        Target {
            display: "h".into(),
            host: "h".into(),
            port: 7722,
            identity: None,
            pin: None,
            local: vec![],
            remote: vec![],
            dynamic: vec![],
            env: vec![],
            shell: false,
            meta_key: None,
            accept_new: false,
            strict: false,
            quiet: false,
            baked_only: false,
            force_pty: false,
            no_pty: false,
            no_session: false,
            attach: None,
            no_ctl: false,
            timeout: None,
            cwd: None,
            master: crate::config::MasterMode::Never,
        }
    }

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, text).expect("write");
    }

    fn trust(dir: &TempDir, pin: Option<Pin>, peers: AuthorizedKeys) -> ClientTrust {
        let paths = paths_in(dir);
        ClientTrust {
            pin,
            baked: peers,
            known_hosts: vec![
                paths.known_hosts.clone(),
                dir.path("ssh").join("known_hosts"),
            ],
            write_to: paths.known_hosts,
            accept_new: false,
            strict: false,
        }
    }

    #[test]
    fn evaluate_pin_wins_and_pin_mismatch_is_hard() {
        let dir = TempDir::new("pin");
        let k = key();
        let t = trust(&dir, Some(Pin::Key(k)), AuthorizedKeys::new());
        assert_eq!(
            t.evaluate("h", 7722, &k),
            TrustDecision::Trusted { via: "pin".into() }
        );
        let other = key();
        match t.evaluate("h", 7722, &other) {
            TrustDecision::Mismatch {
                source, expected, ..
            } => {
                assert_eq!(source, "pin");
                assert_eq!(expected, k.fingerprint());
            }
            d => panic!("unexpected {d:?}"),
        }
    }

    #[test]
    fn evaluate_baked_then_known_hosts() {
        let dir = TempDir::new("baked");
        let baked_key = key();
        let peers = AuthorizedKeys::parse(&baked_key.to_line(Some("fleet")), BAKED);
        let paths = paths_in(&dir);
        let file_key = key();
        write(
            &paths.known_hosts,
            &format!("# comment\nh:7722 {}", file_key.to_line(None)),
        );
        let t = trust(&dir, None, peers);
        assert_eq!(
            t.evaluate("h", 7722, &baked_key),
            TrustDecision::Trusted {
                via: "baked".into()
            }
        );
        let via = match t.evaluate("h", 7722, &file_key) {
            TrustDecision::Trusted { via } => via,
            d => panic!("unexpected {d:?}"),
        };
        assert!(via.ends_with("known_hosts:2"), "{via}");
        assert_eq!(
            t.evaluate("h", 7722, &key()),
            TrustDecision::Mismatch {
                source: via.rsplit_once(':').expect("colon").0.to_owned(),
                line: 2,
                expected: file_key.fingerprint(),
            }
        );
        assert_eq!(t.evaluate("elsewhere", 1, &key()), TrustDecision::Unknown);
    }

    #[test]
    fn evaluate_mismatch_in_second_file_beats_unknown_in_first() {
        let dir = TempDir::new("mismatch");
        let paths = paths_in(&dir);
        write(
            &paths.known_hosts,
            &format!("other {}", key().to_line(None)),
        );
        let ssh_key = key();
        write(
            &dir.path("ssh").join("known_hosts"),
            &format!("h {}", ssh_key.to_line(None)),
        );
        let t = trust(&dir, None, AuthorizedKeys::new());
        match t.evaluate("h", 7722, &key()) {
            TrustDecision::Mismatch { line, expected, .. } => {
                assert_eq!(line, 1);
                assert_eq!(expected, ssh_key.fingerprint());
            }
            d => panic!("unexpected {d:?}"),
        }
        match t.evaluate("h", 7722, &ssh_key) {
            TrustDecision::Trusted { via } => assert!(via.ends_with("known_hosts:1"), "{via}"),
            d => panic!("unexpected {d:?}"),
        }
    }

    #[tokio::test]
    async fn client_identity_uses_first_existing_file() {
        let dir = TempDir::new("clientid");
        let paths = paths_in(&dir);
        let baked = Baked::default();
        let t = target();
        let err = client_identities(&t, &paths, &baked, &mut no_pass)
            .await
            .expect_err("no identity");
        assert!(
            err.to_string().contains("$SSH_AUTH_SOCK unset"),
            "names the agent: {err}"
        );
        let secret = SecretKey::generate();
        write_secret_key(&paths.identity, &secret).expect("write");
        let ids = client_identities(&t, &paths, &baked, &mut no_pass)
            .await
            .expect("load");
        assert_eq!(ids.len(), 1);
        let ClientIdentity::Static(id) = &ids[0] else {
            panic!("expected a static identity, got {:?}", ids[0]);
        };
        assert_eq!(id.public, secret.public());
        assert_eq!(ids[0].fingerprint(), secret.public().fingerprint());
        assert_eq!(ids[0].public_line(), secret.public().to_line(None));
        assert!(ids[0].describe().starts_with("x25519 SHA256:"));
        let missing = Target {
            identity: Some(dir.path("nope")),
            ..t.clone()
        };
        assert!(
            client_identities(&missing, &paths, &baked, &mut no_pass)
                .await
                .is_err()
        );

        // An unreachable agent socket is skipped, not fatal.
        let mut dead = paths.clone();
        dead.agent_socket = Some(dir.path("no-such-agent"));
        let ids = client_identities(&t, &dead, &baked, &mut no_pass)
            .await
            .expect("load");
        assert_eq!(ids.len(), 1);

        // `.pub` files name agent keys and need an agent.
        let pubfile = dir.path("k.pub");
        let ed = [7u8; 32];
        write(
            &pubfile,
            &format!(
                "{SSH_ED25519_TYPE} {} it\n",
                STANDARD.encode(mysh_net::agent::ed25519_blob(&ed))
            ),
        );
        let with_pub = Target {
            identity: Some(pubfile.clone()),
            ..t.clone()
        };
        let err = client_identities(&with_pub, &paths, &baked, &mut no_pass)
            .await
            .expect_err("no agent");
        assert!(
            err.to_string().contains("$SSH_AUTH_SOCK"),
            "unexpected: {err}"
        );
        let err = client_identities(&with_pub, &dead, &baked, &mut no_pass)
            .await
            .expect_err("agent down");
        assert!(
            format!("{err:#}").contains("connecting to ssh-agent"),
            "unexpected: {err:#}"
        );
        write(&pubfile, &secret.public().to_line(None));
        let err = client_identities(&with_pub, &paths, &baked, &mut no_pass)
            .await
            .expect_err("x25519 public key");
        assert!(
            err.to_string().contains("cannot authenticate"),
            "unexpected: {err}"
        );
        write(&pubfile, "garbage\n");
        assert!(
            client_identities(&with_pub, &paths, &baked, &mut no_pass)
                .await
                .is_err()
        );
    }

    #[test]
    fn agent_identity_lines_and_descriptions() {
        // The ed25519 basepoint (compressed y = 4/5): a valid curve point,
        // so the authorized_keys parser accepts the line.
        let mut ed = [0x66u8; 32];
        ed[0] = 0x58;
        let id = ClientIdentity::Agent {
            socket: PathBuf::from("/tmp/agent"),
            key: AgentKey {
                public: ed,
                blob: mysh_net::agent::ed25519_blob(&ed),
                comment: "me@box".to_owned(),
            },
        };
        assert_eq!(id.fingerprint(), Fingerprint::of_ssh_ed25519(&ed));
        let line = id.public_line();
        assert!(line.starts_with(&format!("{SSH_ED25519_TYPE} ")));
        assert!(line.ends_with(" me@box\n"));
        // The line round-trips through the authorized_keys parser as an
        // ed25519 entry.
        let set = AuthorizedKeys::parse(&line, "t");
        assert_eq!(set.find_ed25519(&ed).map(|e| e.line), Some(1));
        assert_eq!(
            id.describe(),
            format!("{SSH_ED25519_TYPE} {} (agent: me@box)", id.fingerprint())
        );
        let no_comment = ClientIdentity::Agent {
            socket: PathBuf::from("/tmp/agent"),
            key: AgentKey {
                public: ed,
                blob: mysh_net::agent::ed25519_blob(&ed),
                comment: String::new(),
            },
        };
        assert!(!no_comment.public_line().trim_end().ends_with(' '));
    }

    #[test]
    fn tildify_abbreviates_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            tildify(Path::new("/home/u/.config/mysh/known_hosts"), Some(home)),
            "~/.config/mysh/known_hosts"
        );
        assert_eq!(tildify(Path::new("/etc/x"), Some(home)), "/etc/x");
        assert_eq!(tildify(Path::new("/etc/x"), None), "/etc/x");
    }
}
