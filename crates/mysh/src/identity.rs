//! Identity and trust resolution for both roles (docs/02-security.md:
//! "Identity resolution", "Authorization", "Server trust", "Baked keys"),
//! plus the `keygen` and `fingerprint` utilities.
//!
//! This module is the only place that turns flags, environment, baked
//! material and well-known files into loaded keys and trust stores; the
//! client and server consume the results.

use std::fmt;
use std::io::{self, IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_net::keys::{
    Fingerprint, Identity, PublicKey, SECRET_KEY_TYPE, SecretKey, load_secret_key,
    parse_public_key, parse_secret_key, write_public_key, write_secret_key,
};
use mysh_net::trust::{AuthorizedKeys, HostMatch, KnownHosts, Pin};
use tracing::{debug, info, warn};

use crate::cli::{FingerprintArgs, KeygenArgs, ServeArgs};
use crate::config::{
    IdentitySource, Paths, Target, client_identity_candidates, expand_tilde,
    server_identity_candidates,
};

/// Source label used for compiled-in material.
const BAKED: &str = "baked";

/// Key material compiled in with `--features baked`, parsed once at startup.
#[derive(Debug, Default)]
pub struct Baked {
    /// The compiled-in private identity, if any.
    pub identity: Option<Identity>,
    /// Compiled-in trusted peers (empty without the feature).
    pub peers: AuthorizedKeys,
}

/// Parse `crate::baked::{IDENTITY, PEERS}`. A passphrase-protected baked
/// identity is an error: nobody is there to type it.
pub fn baked() -> Result<Baked> {
    let identity = match crate::baked::IDENTITY {
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
    let peers = crate::baked::PEERS
        .map(|text| AuthorizedKeys::parse(text, BAKED))
        .unwrap_or_default();
    Ok(Baked { identity, peers })
}

/// Interactive passphrase callback for encrypted OpenSSH keys. The prompt
/// names the key source; when stdin is not a terminal the callback fails so
/// non-interactive callers get a clear error instead of hanging.
pub fn passphrase_prompt() -> impl FnMut(&str) -> io::Result<String> {
    |source: &str| {
        if !io::stdin().is_terminal() {
            return Err(io::Error::other(format!(
                "{source}: key is passphrase-protected and stdin is not a terminal"
            )));
        }
        rpassword::prompt_password(format!("Enter passphrase for {source}: "))
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

fn describe(source: &IdentitySource) -> String {
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
fn load_first(
    candidates: &[IdentitySource],
    baked: &Baked,
    missing_file: &mut Option<PathBuf>,
) -> Result<Option<Identity>> {
    let mut prompt = passphrase_prompt();
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

/// Resolve the client identity: `-i` → `$MYSH_IDENTITY` → baked →
/// `~/.config/mysh/id` → `~/.ssh/id_ed25519` (files skipped with
/// `--baked-only`).
pub fn load_client_identity(target: &Target, paths: &Paths, baked: &Baked) -> Result<Identity> {
    let home = home_dir(paths);
    let flag = target.identity.as_ref().map(|p| match (p.to_str(), &home) {
        (Some(s), Some(home)) => expand_tilde(s, home),
        _ => p.clone(),
    });
    let candidates = client_identity_candidates(
        flag.as_deref(),
        paths,
        baked.identity.is_some(),
        target.baked_only,
    );
    let mut missing = None;
    if let Some(id) = load_first(&candidates, baked, &mut missing)? {
        return Ok(id);
    }
    let tried: Vec<String> = candidates.iter().map(describe).collect();
    bail!(
        "no client identity found (tried: {}); run `mysh keygen` or pass -i PATH",
        if tried.is_empty() {
            "nothing".to_owned()
        } else {
            tried.join(", ")
        }
    )
}

/// Resolve the server identity: `--key` → `$MYSH_HOST_KEY` → baked →
/// `~/.config/mysh/host_key`. A missing `host_key` is generated (0600)
/// unless `--no-generate-key` is given.
pub fn load_server_identity(args: &ServeArgs, paths: &Paths, baked: &Baked) -> Result<Identity> {
    let candidates = server_identity_candidates(
        args.key.as_deref(),
        paths,
        baked.identity.is_some(),
        args.baked_only,
    );
    let mut missing = None;
    if let Some(id) = load_first(&candidates, baked, &mut missing)? {
        return Ok(id);
    }
    let Some(path) = missing else {
        bail!(
            "no server identity found (tried: {}); pass --key PATH or drop --baked-only",
            candidates
                .iter()
                .map(describe)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    if args.no_generate_key {
        bail!(
            "host key {} does not exist and --no-generate-key was given",
            path.display()
        );
    }
    let secret = SecretKey::generate();
    let public = secret.public();
    write_secret_key(&path, &secret)
        .with_context(|| format!("writing host key {}", path.display()))?;
    let pub_path = pub_path_for(&path);
    write_public_key(&pub_path, &public, None)
        .with_context(|| format!("writing host public key {}", pub_path.display()))?;
    info!(
        path = %path.display(),
        fingerprint = %public.fingerprint(),
        "generated new host key"
    );
    load_secret_key(&path, &mut passphrase_prompt())
        .with_context(|| format!("re-reading generated host key {}", path.display()))
}

/// `PATH.pub` next to a private key.
fn pub_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Read a trust file, ignoring a missing one. Other errors are logged and
/// treated as empty: a transiently unreadable file must not grant access, and
/// it cannot, since "empty" only ever removes keys from the union.
fn read_trust_file(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read trust file; ignoring it");
            None
        }
    }
}

/// Where the server's trusted client keys come from. Files are re-read on
/// every [`TrustSource::load`] so edits take effect per connection.
#[derive(Debug, Clone)]
pub struct TrustSource {
    /// Compiled-in peers.
    pub baked: AuthorizedKeys,
    /// `--authorized-key` lines.
    pub inline: AuthorizedKeys,
    /// `~/.config/mysh/authorized_keys` and `--authorized-keys` files.
    pub files: Vec<PathBuf>,
    /// `~/.ssh/authorized_keys` unless disabled.
    pub ssh_ed25519_file: Option<PathBuf>,
}

impl TrustSource {
    /// Build the source set from the serve flags. Fails when the union is
    /// empty at startup (fail closed).
    pub fn for_server(args: &ServeArgs, paths: &Paths, baked: &Baked) -> Result<Self> {
        let inline_text = args.authorized_key.join("\n");
        let inline = AuthorizedKeys::parse(&inline_text, "--authorized-key");
        let inline_lines = args
            .authorized_key
            .iter()
            .filter(|l| !l.trim().is_empty())
            .count();
        if inline.len() != inline_lines {
            bail!(
                "--authorized-key: {} of {inline_lines} values are not usable public keys",
                inline_lines - inline.len()
            );
        }
        let (files, ssh_ed25519_file) = if args.baked_only {
            (Vec::new(), None)
        } else {
            let mut files = vec![paths.authorized_keys.clone()];
            files.extend(args.authorized_keys.iter().cloned());
            let ssh = if args.no_ssh_authorized_keys {
                None
            } else {
                paths.ssh_dir.as_ref().map(|d| d.join("authorized_keys"))
            };
            (files, ssh)
        };
        for path in &args.authorized_keys {
            if !path.exists() {
                bail!("--authorized-keys {}: file not found", path.display());
            }
        }
        let source = Self {
            baked: baked.peers.clone(),
            inline,
            files,
            ssh_ed25519_file,
        };
        let set = source.load();
        if set.is_empty() {
            bail!(
                "no authorized client keys (checked baked peers, --authorized-key, {}); refusing to start",
                source.describe_files()
            );
        }
        info!(keys = set.len(), "authorized client keys loaded");
        Ok(source)
    }

    fn describe_files(&self) -> String {
        let mut names: Vec<String> = self.files.iter().map(|p| p.display().to_string()).collect();
        if let Some(ssh) = &self.ssh_ed25519_file {
            names.push(ssh.display().to_string());
        }
        if names.is_empty() {
            "no files (--baked-only)".to_owned()
        } else {
            names.join(", ")
        }
    }

    /// The current union: baked peers, inline keys, and every file re-read
    /// now. Missing files are ignored.
    pub fn load(&self) -> AuthorizedKeys {
        let mut all = self.baked.clone();
        all.extend(self.inline.clone());
        for path in self.files.iter().chain(self.ssh_ed25519_file.iter()) {
            if let Some(text) = read_trust_file(path) {
                all.extend(AuthorizedKeys::parse(&text, &path.display().to_string()));
            }
        }
        all
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

/// `mysh keygen [-o PATH] [-C COMMENT]`: write `PATH` (0600) and `PATH.pub`,
/// refusing to overwrite either.
pub fn keygen(args: &KeygenArgs, paths: &Paths) -> Result<()> {
    let path = args
        .output
        .clone()
        .unwrap_or_else(|| paths.identity.clone());
    let pub_path = pub_path_for(&path);
    for p in [&path, &pub_path] {
        if p.exists() {
            bail!("{} already exists; refusing to overwrite", p.display());
        }
    }
    let secret = SecretKey::generate();
    let public = secret.public();
    write_secret_key(&path, &secret).with_context(|| format!("writing {}", path.display()))?;
    write_public_key(&pub_path, &public, args.comment.as_deref())
        .with_context(|| format!("writing {}", pub_path.display()))?;
    println!("Your identification has been saved in {}", path.display());
    println!("Your public key has been saved in {}", pub_path.display());
    println!("The key fingerprint is:");
    match &args.comment {
        Some(c) if !c.trim().is_empty() => println!("{} {}", public.fingerprint(), c.trim()),
        _ => println!("{}", public.fingerprint()),
    }
    Ok(())
}

/// `mysh fingerprint [FILE]`: print `SHA256:… [comment]` for a private or
/// public key in either format; `-` (or no file) reads stdin.
pub fn fingerprint(args: &FingerprintArgs) -> Result<()> {
    let (text, source) = match args.file.as_deref() {
        Some(p) if p.as_os_str() != "-" => (
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            p.display().to_string(),
        ),
        _ => {
            let mut text = String::new();
            io::stdin()
                .read_to_string(&mut text)
                .context("reading key from stdin")?;
            (text, "stdin".to_owned())
        }
    };
    let (public, comment) = key_from_text(&text, &source)?;
    match comment {
        Some(c) => println!("{} {c}", public.fingerprint()),
        None => println!("{}", public.fingerprint()),
    }
    Ok(())
}

/// Public key and comment from key-file text: a native or OpenSSH private
/// key, or the first public key line.
fn key_from_text(text: &str, source: &str) -> Result<(PublicKey, Option<String>)> {
    let trimmed = text.trim_start();
    if trimmed.starts_with(SECRET_KEY_TYPE) || trimmed.starts_with("-----BEGIN") {
        let id = parse_secret_key(text, source, &mut passphrase_prompt())
            .with_context(|| format!("{source}: not a readable private key"))?;
        return Ok((id.public, id.comment));
    }
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("{source}: empty key file"))?;
    parse_public_key(line).with_context(|| format!("{source}: not a mysh or OpenSSH key"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

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

    #[test]
    fn trust_source_union_and_reread() {
        let dir = TempDir::new("trust");
        let baked_key = key();
        let inline_key = key();
        let file_key = key();
        let ssh_key = key();
        let file = dir.path("authorized_keys");
        write(&file, &file_key.to_line(None));
        let ssh_file = dir.path("ssh_authorized_keys");
        write(&ssh_file, &ssh_key.to_line(None));
        let source = TrustSource {
            baked: AuthorizedKeys::parse(&baked_key.to_line(None), BAKED),
            inline: AuthorizedKeys::parse(&inline_key.to_line(None), "--authorized-key"),
            files: vec![file.clone(), dir.path("missing")],
            ssh_ed25519_file: Some(ssh_file),
        };
        let set = source.load();
        assert_eq!(set.len(), 4);
        for k in [&baked_key, &inline_key, &file_key, &ssh_key] {
            assert!(set.contains(k));
        }
        let appended = key();
        assert!(!set.contains(&appended));
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .expect("open");
        f.write_all(appended.to_line(None).as_bytes())
            .expect("append");
        drop(f);
        let set = source.load();
        assert_eq!(set.len(), 5);
        assert!(set.contains(&appended));
    }

    #[test]
    fn trust_source_for_server_fails_closed() {
        let dir = TempDir::new("closed");
        let paths = paths_in(&dir);
        let args = ServeArgs {
            no_ssh_authorized_keys: true,
            ..ServeArgs::default()
        };
        assert!(TrustSource::for_server(&args, &paths, &Baked::default()).is_err());
        let args = ServeArgs {
            authorized_key: vec![key().to_line(None).trim().to_owned()],
            ..args
        };
        let source = TrustSource::for_server(&args, &paths, &Baked::default()).expect("inline");
        assert_eq!(source.load().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn server_identity_is_generated_once() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("hostkey");
        let paths = paths_in(&dir);
        let baked = Baked::default();
        let args = ServeArgs {
            no_generate_key: true,
            ..ServeArgs::default()
        };
        assert!(load_server_identity(&args, &paths, &baked).is_err());
        let args = ServeArgs::default();
        let first = load_server_identity(&args, &paths, &baked).expect("generate");
        let mode = fs::metadata(&paths.host_key)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(pub_path_for(&paths.host_key).exists());
        let second = load_server_identity(&args, &paths, &baked).expect("reuse");
        assert_eq!(first.public, second.public);
        assert_eq!(second.source, paths.host_key.display().to_string());
    }

    #[test]
    fn client_identity_uses_first_existing_file() {
        let dir = TempDir::new("clientid");
        let paths = paths_in(&dir);
        let baked = Baked::default();
        let t = target();
        assert!(load_client_identity(&t, &paths, &baked).is_err());
        let secret = SecretKey::generate();
        write_secret_key(&paths.identity, &secret).expect("write");
        let id = load_client_identity(&t, &paths, &baked).expect("load");
        assert_eq!(id.public, secret.public());
        let missing = Target {
            identity: Some(dir.path("nope")),
            ..t
        };
        assert!(load_client_identity(&missing, &paths, &baked).is_err());
    }

    #[test]
    fn keygen_refuses_to_overwrite() {
        let dir = TempDir::new("keygen");
        let paths = paths_in(&dir);
        let args = KeygenArgs {
            output: Some(dir.path("k")),
            comment: Some("c".into()),
        };
        keygen(&args, &paths).expect("first keygen");
        assert!(dir.path("k").exists());
        assert!(dir.path("k.pub").exists());
        assert!(keygen(&args, &paths).is_err());
        let default_args = KeygenArgs::default();
        keygen(&default_args, &paths).expect("default output");
        assert!(paths.identity.exists());
        assert!(keygen(&default_args, &paths).is_err());
    }

    #[test]
    fn fingerprint_from_private_and_public_text() {
        let secret = SecretKey::generate();
        let (pk, c) = key_from_text(&secret.to_line(), "t").expect("private");
        assert_eq!(pk, secret.public());
        assert!(c.is_none());
        let (pk, c) =
            key_from_text(&format!("\n# hdr\n{}", pk.to_line(Some("me"))), "t").expect("public");
        assert_eq!(pk, secret.public());
        assert_eq!(c.as_deref(), Some("me"));
        assert!(key_from_text("", "t").is_err());
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
