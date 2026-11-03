//! Key material: native X25519 keys, OpenSSH ed25519 reuse, fingerprints,
//! and key files (see `docs/02-security.md`, "Key material").
//!
//! Text formats, one line each:
//!
//! ```text
//! mysh-x25519-secret <base64 32B>
//! mysh-x25519 <base64 32B> [comment]
//! ```
//!
//! Fingerprints are `SHA256:<base64-unpadded(sha256(raw public key))>`.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, STANDARD_PAD_INDIFFERENT};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::clamp_integer;
use sha2::{Digest as _, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Key type token of a native secret key line.
pub const SECRET_KEY_TYPE: &str = "mysh-x25519-secret";
/// Key type token of a native public key line.
pub const PUBLIC_KEY_TYPE: &str = "mysh-x25519";
/// OpenSSH key type token accepted wherever a public key is accepted.
pub const SSH_ED25519_TYPE: &str = "ssh-ed25519";

const OPENSSH_PEM_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// Errors from key parsing and key files.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed key: {0}")]
    Format(String),
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("incorrect passphrase")]
    BadPassphrase,
    #[error(
        "refusing {path}: permissions {mode:#o} are too open (must not be group/world accessible)"
    )]
    Permissions { path: PathBuf, mode: u32 },
    #[error("openssh key error: {0}")]
    Ssh(String),
}

/// An X25519 secret scalar. Zeroized on drop; `Debug` never prints bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// Generates a fresh, clamped random scalar from the OS RNG.
    pub fn generate() -> Self {
        use rand_core::RngCore as _;
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(clamp_integer(bytes))
    }

    /// Wraps raw scalar bytes (clamping is applied at use).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `X25519(sk, basepoint)`.
    pub fn public(&self) -> PublicKey {
        PublicKey(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }

    /// `"mysh-x25519-secret <b64>\n"`.
    pub fn to_line(&self) -> String {
        format!("{SECRET_KEY_TYPE} {}\n", STANDARD.encode(self.0))
    }
}

/// An X25519 public key (Montgomery u-coordinate).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.fingerprint(), f)
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let digest = Sha256::digest(self.0);
        Fingerprint(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
    }

    /// `"mysh-x25519 <b64>[ comment]\n"`.
    pub fn to_line(&self, comment: Option<&str>) -> String {
        let b64 = STANDARD.encode(self.0);
        match comment.map(str::trim).filter(|c| !c.is_empty()) {
            Some(c) => format!("{PUBLIC_KEY_TYPE} {b64} {c}\n"),
            None => format!("{PUBLIC_KEY_TYPE} {b64}\n"),
        }
    }
}

/// `SHA256:<base64-unpadded(sha256(pk))>`, OpenSSH-shaped.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Fingerprint of an OpenSSH ed25519 public key: SHA256 over the wire
    /// blob (`string "ssh-ed25519" ‖ string pk`), matching `ssh-add -l` and
    /// `ssh-keygen -lf`.
    #[must_use]
    pub fn of_ssh_ed25519(public: &[u8; 32]) -> Self {
        let digest = Sha256::digest(crate::agent::ed25519_blob(public));
        Self(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Fingerprint {
    type Err = KeyError;

    /// Accepts `SHA256:<b64>` or bare `<b64>` (padded or not); normalizes to
    /// the prefixed, unpadded form.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let body = s.strip_prefix("SHA256:").unwrap_or(s);
        let digest = STANDARD_PAD_INDIFFERENT
            .decode(body)
            .map_err(|e| KeyError::Format(format!("fingerprint base64: {e}")))?;
        if digest.len() != 32 {
            return Err(KeyError::Format(format!(
                "fingerprint digest is {} bytes, expected 32",
                digest.len()
            )));
        }
        Ok(Self(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))))
    }
}

/// Which on-disk format an identity came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    Native,
    OpenSsh,
}

/// A loaded private identity.
#[derive(Debug, Clone)]
pub struct Identity {
    pub secret: SecretKey,
    pub public: PublicKey,
    pub format: KeyFormat,
    pub comment: Option<String>,
    /// Path, `"baked"`, or `"env"`.
    pub source: String,
}

/// Callback used to obtain a passphrase for an encrypted OpenSSH key; the
/// argument is a hint (usually the key path).
pub type PassphraseFn<'a> = &'a mut dyn FnMut(&str) -> std::io::Result<String>;

/// Converts an ed25519 public key (compressed Edwards y) to the X25519
/// Montgomery u-coordinate. `None` if the bytes are not a valid point.
pub fn ed25519_pk_to_x25519(ed_pk: &[u8; 32]) -> Option<[u8; 32]> {
    CompressedEdwardsY(*ed_pk)
        .decompress()
        .map(|p| p.to_montgomery().to_bytes())
}

/// The ed25519 signing scalar `clamp(sha512(seed)[0..32])`, which is also the
/// X25519 secret matching [`ed25519_pk_to_x25519`] of the same key.
pub fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> [u8; 32] {
    let hash: Zeroizing<[u8; 64]> = Zeroizing::new(Sha512::digest(seed).into());
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    clamp_integer(scalar)
}

fn decode_key_b64(b64: &str, what: &str) -> Result<[u8; 32], KeyError> {
    let bytes = Zeroizing::new(
        STANDARD_PAD_INDIFFERENT
            .decode(b64)
            .map_err(|e| KeyError::Format(format!("{what}: invalid base64: {e}")))?,
    );
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| KeyError::Format(format!("{what}: expected 32 bytes, got {}", bytes.len())))
}

/// Reads one SSH wire `string` (u32 BE length ‖ bytes) from `rest`.
fn take_ssh_string<'a>(rest: &mut &'a [u8], what: &str) -> Result<&'a [u8], KeyError> {
    let truncated = || KeyError::Format(format!("ssh-ed25519 blob: truncated {what}"));
    let (len, after) = rest.split_first_chunk::<4>().ok_or_else(truncated)?;
    let len = u32::from_be_bytes(*len) as usize;
    if after.len() < len {
        return Err(truncated());
    }
    let (s, after) = after.split_at(len);
    *rest = after;
    Ok(s)
}

/// Parses the OpenSSH `ssh-ed25519` wire blob: `string "ssh-ed25519" ‖ string key`.
pub(crate) fn decode_ssh_ed25519_blob(b64: &str) -> Result<[u8; 32], KeyError> {
    let blob = STANDARD_PAD_INDIFFERENT
        .decode(b64)
        .map_err(|e| KeyError::Format(format!("ssh-ed25519: invalid base64: {e}")))?;
    let mut rest = blob.as_slice();
    let kind = take_ssh_string(&mut rest, "type")?;
    if kind != SSH_ED25519_TYPE.as_bytes() {
        return Err(KeyError::UnsupportedKeyType(
            String::from_utf8_lossy(kind).into_owned(),
        ));
    }
    let key = take_ssh_string(&mut rest, "key")?;
    <[u8; 32]>::try_from(key).map_err(|_| {
        KeyError::Format(format!(
            "ssh-ed25519 blob: key is {} bytes, expected 32",
            key.len()
        ))
    })
}

fn non_empty(comment: &str) -> Option<String> {
    let c = comment.trim();
    (!c.is_empty()).then(|| c.to_owned())
}

/// Splits `type b64 [comment...]`; the comment is the rest of the line with
/// surrounding whitespace trimmed (internal whitespace preserved).
fn split_key_line(line: &str) -> Option<(&str, &str, Option<String>)> {
    let line = line.trim();
    let (kind, rest) = line.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    let (b64, comment) = match rest.split_once(char::is_whitespace) {
        Some((b64, comment)) => (b64, non_empty(comment)),
        None => (rest, None),
    };
    if b64.is_empty() {
        return None;
    }
    Some((kind, b64, comment))
}

/// Parses a public key line: `mysh-x25519 <b64> [comment]` or
/// `ssh-ed25519 <b64> [comment]` (the OpenSSH `.pub` / `authorized_keys` form).
/// Returns the X25519 key and the optional comment.
pub fn parse_public_key(line: &str) -> Result<(PublicKey, Option<String>), KeyError> {
    let (kind, b64, comment) = split_key_line(line).ok_or_else(|| {
        let kind = line.split_whitespace().next().unwrap_or_default();
        if kind.is_empty() {
            KeyError::Format("empty public key line".into())
        } else {
            KeyError::Format(format!("{kind}: missing key data"))
        }
    })?;
    let key = match kind {
        PUBLIC_KEY_TYPE => decode_key_b64(b64, PUBLIC_KEY_TYPE)?,
        SSH_ED25519_TYPE => {
            let ed = decode_ssh_ed25519_blob(b64)?;
            ed25519_pk_to_x25519(&ed)
                .ok_or_else(|| KeyError::Format("ssh-ed25519: not a valid curve point".into()))?
        }
        other => return Err(KeyError::UnsupportedKeyType(other.to_owned())),
    };
    Ok((PublicKey(key), comment))
}

/// Parses a private key: a native `mysh-x25519-secret` line or an OpenSSH
/// private key (`ssh-ed25519` only). Encrypted OpenSSH keys invoke
/// `passphrase` with `source` as the hint; a wrong passphrase yields
/// [`KeyError::BadPassphrase`].
pub fn parse_secret_key(
    text: &str,
    source: &str,
    passphrase: PassphraseFn<'_>,
) -> Result<Identity, KeyError> {
    let trimmed = text.trim_start();
    if trimmed.starts_with(SECRET_KEY_TYPE) {
        return parse_native_secret(trimmed, source);
    }
    if trimmed.starts_with(OPENSSH_PEM_HEADER) {
        return parse_openssh_secret(trimmed, source, passphrase);
    }
    let first = trimmed.split_whitespace().next().unwrap_or_default();
    if first.is_empty() {
        return Err(KeyError::Format(format!("{source}: empty key file")));
    }
    if first.starts_with("-----BEGIN") {
        // PEM/PKCS#8/RSA-style containers; only the OpenSSH container is read.
        return Err(KeyError::UnsupportedKeyType(first.to_owned()));
    }
    Err(KeyError::Format(format!(
        "{source}: not a mysh or OpenSSH private key"
    )))
}

fn parse_native_secret(text: &str, source: &str) -> Result<Identity, KeyError> {
    let line = text.lines().next().unwrap_or_default();
    let (kind, b64, comment) = split_key_line(line)
        .ok_or_else(|| KeyError::Format(format!("{source}: missing key data")))?;
    if kind != SECRET_KEY_TYPE {
        return Err(KeyError::Format(format!("{source}: bad key type {kind}")));
    }
    let secret = SecretKey(decode_key_b64(b64, SECRET_KEY_TYPE)?);
    let public = secret.public();
    Ok(Identity {
        secret,
        public,
        format: KeyFormat::Native,
        comment,
        source: source.to_owned(),
    })
}

fn parse_openssh_secret(
    text: &str,
    source: &str,
    passphrase: PassphraseFn<'_>,
) -> Result<Identity, KeyError> {
    let key = ssh_key::PrivateKey::from_openssh(text).map_err(|e| KeyError::Ssh(e.to_string()))?;
    // The public half is in the clear even when encrypted: reject unsupported
    // algorithms before asking for a passphrase.
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(KeyError::UnsupportedKeyType(
            key.algorithm().as_str().to_owned(),
        ));
    }
    let key = if key.is_encrypted() {
        let pw = Zeroizing::new(passphrase(source)?);
        key.decrypt(pw.as_bytes()).map_err(|e| {
            tracing::debug!(source, error = %e, "openssh key decryption failed");
            KeyError::BadPassphrase
        })?
    } else {
        key
    };
    let kp = key
        .key_data()
        .ed25519()
        .ok_or_else(|| KeyError::UnsupportedKeyType(key.algorithm().as_str().to_owned()))?;
    let mut seed = Zeroizing::new(kp.private.to_bytes());
    let secret = SecretKey(ed25519_seed_to_x25519(&seed));
    seed.zeroize();
    let public = secret.public();
    // Cross-check against the independently converted ed25519 public key.
    if ed25519_pk_to_x25519(&kp.public.0) != Some(*public.as_bytes()) {
        return Err(KeyError::Format(format!(
            "{source}: ed25519 public key does not match its private half"
        )));
    }
    Ok(Identity {
        secret,
        public,
        format: KeyFormat::OpenSsh,
        comment: non_empty(key.comment()),
        source: source.to_owned(),
    })
}

/// Loads and parses a private key file. On unix, refuses files with any
/// group/world permission bits set.
pub fn load_secret_key(path: &Path, passphrase: PassphraseFn<'_>) -> Result<Identity, KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeyError::Permissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    let text = Zeroizing::new(fs::read_to_string(path)?);
    parse_secret_key(&text, &path.display().to_string(), passphrase)
}

fn create_parent_private(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(parent)
}

fn open_new_with_mode(path: &Path, mode: u32, append: bool) -> std::io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if append {
        opts.append(true).create(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
}

/// Opens `path` for appending (creating it with `mode` and its parent with
/// 0700 if needed).
pub(crate) fn open_append_private(path: &Path, mode: u32) -> std::io::Result<fs::File> {
    create_parent_private(path)?;
    open_new_with_mode(path, mode, true)
}

/// Writes `key` as a native secret key line. Creates the parent directory
/// 0700, the file 0600, and fails if the file already exists.
pub fn write_secret_key(path: &Path, key: &SecretKey) -> std::io::Result<()> {
    create_parent_private(path)?;
    let mut file = open_new_with_mode(path, 0o600, false)?;
    let line = Zeroizing::new(key.to_line());
    file.write_all(line.as_bytes())?;
    file.sync_all()
}

/// Writes `key` as a native public key line, mode 0644.
pub fn write_public_key(
    path: &Path,
    key: &PublicKey,
    comment: Option<&str>,
) -> std::io::Result<()> {
    create_parent_private(path)?;
    let mut file = open_new_with_mode(path, 0o644, false)?;
    file.write_all(key.to_line(comment).as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use curve25519_dalek::edwards::EdwardsPoint;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique, cleaned-up temp directory for a test.
    pub(crate) struct TempDir(pub(crate) PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "mysh-test-{tag}-{}-{}-{n}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        pub(crate) fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn no_passphrase() -> impl FnMut(&str) -> std::io::Result<String> {
        |hint: &str| {
            Err(std::io::Error::other(format!(
                "unexpected passphrase prompt for {hint}"
            )))
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex(s).try_into().expect("32 bytes")
    }

    #[test]
    fn rfc7748_basepoint_vector() {
        // RFC 7748 §6.1: Alice's private key → public key.
        let sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(*SecretKey::from_bytes(sk).public().as_bytes(), pk);
        // §5.2 scalar-mult vector with u = 9 (the base point).
        let k = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(MontgomeryPoint(u).mul_clamped(k).to_bytes(), out);
    }

    #[test]
    fn ed25519_conversion_identity() {
        for i in 0..8u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[31] = 0xA5 ^ i;
            let x_sk = ed25519_seed_to_x25519(&seed);
            // ed25519 public key = clamped scalar × Edwards basepoint.
            let ed_pk = EdwardsPoint::mul_base_clamped(x_sk).compress().to_bytes();
            // Agrees with an independent ed25519 implementation.
            let kp = ssh_key::private::Ed25519Keypair::from_seed(&seed);
            assert_eq!(kp.public.0, ed_pk);
            let from_public = ed25519_pk_to_x25519(&ed_pk).expect("valid point");
            let from_secret = SecretKey::from_bytes(x_sk).public();
            assert_eq!(*from_secret.as_bytes(), from_public);
        }
        // y = 2 is not the y-coordinate of any point on edwards25519
        // ((y²−1)/(dy²+1) is a non-residue), so decompression must fail.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert!(ed25519_pk_to_x25519(&not_a_point).is_none());
    }

    #[test]
    fn generate_is_clamped_and_distinct() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes()[0] & 0b111, 0);
        assert_eq!(a.as_bytes()[31] & 0b1100_0000, 0b0100_0000);
        assert_eq!(format!("{a:?}"), "SecretKey(..)");
    }

    #[test]
    fn native_text_round_trips() {
        let sk = SecretKey::generate();
        let line = sk.to_line();
        assert!(line.starts_with("mysh-x25519-secret "));
        assert!(line.ends_with('\n'));
        let id = parse_secret_key(&line, "test", &mut no_passphrase()).expect("parse");
        assert_eq!(id.secret.as_bytes(), sk.as_bytes());
        assert_eq!(id.public, sk.public());
        assert_eq!(id.format, KeyFormat::Native);
        assert_eq!(id.source, "test");
        assert!(id.comment.is_none());

        let pk = sk.public();
        let pub_line = pk.to_line(Some("alice@host"));
        assert!(pub_line.starts_with("mysh-x25519 "));
        assert!(pub_line.ends_with(" alice@host\n"));
        let (parsed, comment) = parse_public_key(&pub_line).expect("parse pub");
        assert_eq!(parsed, pk);
        assert_eq!(comment.as_deref(), Some("alice@host"));
        let (parsed, comment) = parse_public_key(&pk.to_line(None)).expect("parse pub");
        assert_eq!(parsed, pk);
        assert!(comment.is_none());
        let (_, comment) = parse_public_key(&format!("{}  two words ", pk.to_line(None).trim()))
            .expect("parse pub");
        assert_eq!(comment.as_deref(), Some("two words"));
    }

    #[test]
    fn public_key_errors() {
        assert!(matches!(
            parse_public_key("ssh-rsa AAAAB3Nza comment"),
            Err(KeyError::UnsupportedKeyType(t)) if t == "ssh-rsa"
        ));
        assert!(matches!(parse_public_key(""), Err(KeyError::Format(_))));
        assert!(matches!(
            parse_public_key("mysh-x25519"),
            Err(KeyError::Format(_))
        ));
        assert!(matches!(
            parse_public_key("mysh-x25519 AAAA"),
            Err(KeyError::Format(_))
        ));
        assert!(matches!(
            parse_public_key("mysh-x25519 !!!!"),
            Err(KeyError::Format(_))
        ));
    }

    #[test]
    fn fingerprint_matches_sha256() {
        let zero = PublicKey::from_bytes([0u8; 32]);
        let expected = format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest([0u8; 32]))
        );
        assert_eq!(zero.fingerprint().to_string(), expected);
        assert_eq!(
            zero.fingerprint().to_string(),
            "SHA256:Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU"
        );
        assert_eq!(format!("{zero:?}"), expected);

        let fp: Fingerprint = expected.parse().expect("prefixed");
        assert_eq!(fp, zero.fingerprint());
        let bare: Fingerprint = "Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU"
            .parse()
            .expect("bare");
        assert_eq!(bare, fp);
        let padded: Fingerprint = "Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU="
            .parse()
            .expect("padded");
        assert_eq!(padded, fp);
        assert!("SHA256:AAAA".parse::<Fingerprint>().is_err());
        assert!("not base64!".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn ssh_ed25519_public_line() {
        let kp = ssh_key::private::Ed25519Keypair::from_seed(&[7u8; 32]);
        let ssh_pub =
            ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(kp.public), "me@box");
        let line = ssh_pub.to_openssh().expect("encode");
        let (pk, comment) = parse_public_key(&line).expect("parse");
        assert_eq!(comment.as_deref(), Some("me@box"));
        assert_eq!(
            *pk.as_bytes(),
            ed25519_pk_to_x25519(&kp.public.0).expect("point")
        );
        assert_eq!(
            pk,
            SecretKey::from_bytes(ed25519_seed_to_x25519(&[7u8; 32])).public()
        );
    }

    #[test]
    fn openssh_private_key_plain_and_encrypted() {
        let mut key =
            ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .expect("random key");
        key.set_comment("gen@test");
        let ed_pk = key.public_key().key_data().ed25519().expect("ed25519").0;
        let expected = ed25519_pk_to_x25519(&ed_pk).expect("point");

        let pem = key.to_openssh(ssh_key::LineEnding::LF).expect("encode");
        let id = parse_secret_key(&pem, "plain", &mut no_passphrase()).expect("parse");
        assert_eq!(*id.public.as_bytes(), expected);
        assert_eq!(id.format, KeyFormat::OpenSsh);
        assert_eq!(id.comment.as_deref(), Some("gen@test"));
        assert_eq!(id.secret.public(), id.public);

        let enc = key
            .encrypt(&mut rand_core::OsRng, "hunter2")
            .expect("encrypt");
        let enc_pem = enc.to_openssh(ssh_key::LineEnding::LF).expect("encode");
        let mut hints = Vec::new();
        let mut good = |hint: &str| {
            hints.push(hint.to_owned());
            Ok("hunter2".to_owned())
        };
        let id = parse_secret_key(&enc_pem, "/some/path", &mut good).expect("decrypt");
        assert_eq!(*id.public.as_bytes(), expected);
        assert_eq!(hints, ["/some/path"]);

        let mut bad = |_: &str| Ok("wrong".to_owned());
        assert!(matches!(
            parse_secret_key(&enc_pem, "enc", &mut bad),
            Err(KeyError::BadPassphrase)
        ));

        let mut failing = |_: &str| Err(std::io::Error::other("no tty"));
        assert!(matches!(
            parse_secret_key(&enc_pem, "enc", &mut failing),
            Err(KeyError::Io(_))
        ));
    }

    #[test]
    fn openssh_non_ed25519_rejected() {
        let key = ssh_key::PrivateKey::random(
            &mut rand_core::OsRng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        );
        // ecdsa key generation needs the `p256` feature; when unavailable the
        // random() call itself fails and there is nothing to test here.
        let Ok(key) = key else { return };
        let pem = key.to_openssh(ssh_key::LineEnding::LF).expect("encode");
        assert!(matches!(
            parse_secret_key(&pem, "ecdsa", &mut no_passphrase()),
            Err(KeyError::UnsupportedKeyType(_))
        ));
    }

    #[test]
    fn garbage_secret_rejected() {
        assert!(matches!(
            parse_secret_key("", "empty", &mut no_passphrase()),
            Err(KeyError::Format(_))
        ));
        assert!(matches!(
            parse_secret_key(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n",
                "rsa",
                &mut no_passphrase()
            ),
            Err(KeyError::UnsupportedKeyType(_))
        ));
        assert!(matches!(
            parse_secret_key("mysh-x25519-secret AAAA\n", "short", &mut no_passphrase()),
            Err(KeyError::Format(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_modes_and_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = TempDir::new("keys");
        let dir = tmp.path("sub");
        let path = dir.join("id");
        let sk = SecretKey::generate();
        write_secret_key(&path, &sk).expect("write secret");
        write_public_key(&dir.join("id.pub"), &sk.public(), Some("c")).expect("write public");

        assert_eq!(
            fs::metadata(&dir).expect("dir").permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).expect("file").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.join("id.pub"))
                .expect("pub")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );

        // O_EXCL: a second write fails.
        assert_eq!(
            write_secret_key(&path, &sk).expect_err("exists").kind(),
            std::io::ErrorKind::AlreadyExists
        );

        let id = load_secret_key(&path, &mut no_passphrase()).expect("load");
        assert_eq!(id.secret.as_bytes(), sk.as_bytes());
        assert_eq!(id.source, path.display().to_string());

        let (pk, comment) =
            parse_public_key(&fs::read_to_string(dir.join("id.pub")).expect("read"))
                .expect("parse");
        assert_eq!(pk, sk.public());
        assert_eq!(comment.as_deref(), Some("c"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        match load_secret_key(&path, &mut no_passphrase()) {
            Err(KeyError::Permissions { path: p, mode }) => {
                assert_eq!(p, path);
                assert_eq!(mode, 0o640);
            }
            other => panic!("expected Permissions error, got {other:?}"),
        }

        assert!(matches!(
            load_secret_key(&tmp.path("missing"), &mut no_passphrase()),
            Err(KeyError::Io(_))
        ));
    }
}
