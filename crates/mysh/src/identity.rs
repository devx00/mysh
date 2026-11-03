//! Identity and trust for the binary (docs/02-security.md): the compiled-in
//! material, the interactive passphrase prompt, the server's trust source
//! and host key, and the `keygen` / `fingerprint` utilities. The client
//! side (identities offered, server trust, TOFU) lives in
//! [`mysh_client::identity`] and is re-exported here.

use std::io::{self, IsTerminal as _, Read as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_net::keys::{
    Identity, PublicKey, SECRET_KEY_TYPE, SecretKey, load_secret_key, parse_public_key,
    parse_secret_key, write_public_key, write_secret_key,
};
use mysh_net::trust::AuthorizedKeys;
use tracing::info;

pub use mysh_client::identity::*;

use crate::cli::{FingerprintArgs, KeygenArgs, ServeArgs};
use crate::config::{Paths, server_identity_candidates};

/// Parse `crate::baked::{IDENTITY, PEERS}`. A passphrase-protected baked
/// identity is an error: nobody is there to type it.
pub fn baked() -> Result<Baked> {
    Baked::parse(crate::baked::IDENTITY, crate::baked::PEERS)
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
    if let Some(id) = load_first(&candidates, baked, &mut missing, &mut passphrase_prompt())? {
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
        // Never consult the developer's real agent from a unit test.
        paths.agent_socket = None;
        paths
    }

    fn write(path: &std::path::Path, text: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, text).expect("write");
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
}
