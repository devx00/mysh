//! Trust stores: `authorized_keys` (server side), `known_hosts` (client
//! side), and `--pin` values. See `docs/02-security.md`, "Authorization" and
//! "Server trust".
//!
//! Both stores accept native `mysh-x25519` lines and OpenSSH `ssh-ed25519`
//! lines (converted to X25519). Other key types are skipped.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT;
use hmac::Mac as _;

use crate::keys::{
    Fingerprint, KeyError, PUBLIC_KEY_TYPE, PublicKey, SSH_ED25519_TYPE, open_append_private,
    parse_public_key,
};

/// Key type tokens accepted in trust stores.
const KNOWN_TYPES: [&str; 2] = [PUBLIC_KEY_TYPE, SSH_ED25519_TYPE];

/// Key type tokens we recognise as "a key, but not one we can use" so the
/// warning can name them.
const UNSUPPORTED_TYPE_PREFIXES: [&str; 4] = ["ssh-", "ecdsa-", "sk-", "x509v3-"];

fn is_key_type(token: &str) -> bool {
    KNOWN_TYPES.contains(&token)
}

fn looks_like_key_type(token: &str) -> bool {
    UNSUPPORTED_TYPE_PREFIXES
        .iter()
        .any(|p| token.starts_with(p))
        && token.len() > 4
        && !token.contains('=')
}

/// Splits a line on whitespace, keeping double-quoted sections (with `\"`
/// escapes) inside a single token — the OpenSSH `authorized_keys` option
/// syntax (`command="echo hi",no-pty ssh-ed25519 ...`).
fn tokenize_quoted(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if start.is_none() {
            if c.is_whitespace() {
                continue;
            }
            start = Some(i);
        }
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c.is_whitespace()
            && !in_quotes
            && let Some(s) = start.take()
        {
            tokens.push(&line[s..i]);
        }
    }
    if let Some(s) = start {
        tokens.push(&line[s..]);
    }
    tokens
}

/// Iterates `(1-based line number, trimmed line)` over non-blank,
/// non-comment lines.
fn content_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

fn read_optional(path: &Path) -> std::io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Appends `line` to `path`, inserting a newline first if the existing
/// content does not end with one. Creates the file 0600 / parent 0700.
fn append_line_to(path: &Path, line: &str) -> std::io::Result<()> {
    let needs_newline = match fs::read(path) {
        Ok(existing) => existing.last().is_some_and(|&b| b != b'\n'),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    let mut file = open_append_private(path, 0o600)?;
    let mut buf = String::with_capacity(line.len() + 1);
    if needs_newline {
        buf.push('\n');
    }
    buf.push_str(line);
    file.write_all(buf.as_bytes())?;
    file.sync_all()
}

// ---------------------------------------------------------------------------
// authorized_keys

/// One trusted client key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: PublicKey,
    pub comment: Option<String>,
    /// File path or other origin label (`"baked"`, `"--authorized-key"`).
    pub source: String,
    /// 1-based line number within `source`.
    pub line: usize,
}

/// The set of trusted client public keys.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeys {
    entries: Vec<Entry>,
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses `authorized_keys` text. Blank and `#` lines are skipped;
    /// OpenSSH option prefixes before the key type are tolerated and
    /// ignored; unknown key types and malformed lines are skipped with a
    /// warning.
    pub fn parse(text: &str, source: &str) -> Self {
        let mut entries = Vec::new();
        for (line_no, line) in content_lines(text) {
            let tokens = tokenize_quoted(line);
            let Some(pos) = tokens.iter().position(|t| is_key_type(t)) else {
                let kind = tokens
                    .iter()
                    .find(|t| looks_like_key_type(t))
                    .map_or("<unrecognised line>", |t| *t);
                tracing::warn!(
                    source,
                    line = line_no,
                    key_type = kind,
                    "authorized_keys: skipping unsupported entry"
                );
                continue;
            };
            let key_part = tokens[pos..].join(" ");
            match parse_public_key(&key_part) {
                Ok((key, comment)) => entries.push(Entry {
                    key,
                    comment,
                    source: source.to_owned(),
                    line: line_no,
                }),
                Err(e) => {
                    tracing::warn!(source, line = line_no, error = %e, "authorized_keys: skipping malformed entry");
                }
            }
        }
        Self { entries }
    }

    /// Reads and parses a file; the path is used as `source`.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Ok(Self::parse(&text, &path.display().to_string()))
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.find(key).is_some()
    }

    pub fn find(&self, key: &PublicKey) -> Option<&Entry> {
        self.entries.iter().find(|e| e.key == *key)
    }

    pub fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// Appends `key` as a `mysh-x25519` line unless the file already lists
    /// it. Returns `false` if it was already present. Creates the file 0600
    /// and its parent 0700.
    pub fn append_line(
        path: &Path,
        key: &PublicKey,
        comment: Option<&str>,
    ) -> std::io::Result<bool> {
        if let Some(text) = read_optional(path)?
            && Self::parse(&text, &path.display().to_string()).contains(key)
        {
            return Ok(false);
        }
        append_line_to(path, &key.to_line(comment))?;
        Ok(true)
    }
}

impl<'a> IntoIterator for &'a AuthorizedKeys {
    type Item = &'a Entry;
    type IntoIter = std::slice::Iter<'a, Entry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

// ---------------------------------------------------------------------------
// known_hosts

/// Result of checking a server key against the known hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatch {
    /// The key is recorded for this host.
    Match { source: String, line: usize },
    /// A different key is recorded for this host.
    Mismatch {
        source: String,
        line: usize,
        expected: Fingerprint,
    },
    /// No entry for this host.
    Unknown,
}

/// One host pattern from a `known_hosts` line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    /// `host`, `host:port` (mysh) or `[host]:port` (OpenSSH). `host` may
    /// contain `*` / `?` wildcards (OpenSSH).
    Plain { host: String, port: Option<u16> },
    /// `|1|salt|hash`: HMAC-SHA1(salt, host-as-written).
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

/// How strongly a pattern matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Specificity {
    /// Host and port both matched.
    Exact,
    /// Bare host entry (no port) matched.
    Bare,
}

impl HostPattern {
    fn parse(pattern: &str) -> Option<Self> {
        if pattern.is_empty() || pattern.starts_with('!') {
            // Negated patterns are not supported; treat as non-matching.
            return None;
        }
        if let Some(rest) = pattern.strip_prefix("|1|") {
            let (salt, hash) = rest.split_once('|')?;
            let salt = STANDARD_PAD_INDIFFERENT.decode(salt).ok()?;
            let hash = STANDARD_PAD_INDIFFERENT.decode(hash).ok()?;
            return Some(Self::Hashed { salt, hash });
        }
        if let Some(rest) = pattern.strip_prefix('[') {
            // OpenSSH `[host]:port`.
            let (host, port) = rest.split_once("]:")?;
            let port = port.parse().ok()?;
            return Some(Self::Plain {
                host: host.to_ascii_lowercase(),
                port: Some(port),
            });
        }
        // mysh `host:port` — exactly one colon with a numeric suffix. Bare IPv6
        // addresses contain several colons and are taken whole.
        if let Some((host, port)) = pattern.split_once(':')
            && !host.is_empty()
            && !port.contains(':')
            && let Ok(port) = port.parse::<u16>()
        {
            return Some(Self::Plain {
                host: host.to_ascii_lowercase(),
                port: Some(port),
            });
        }
        Some(Self::Plain {
            host: pattern.to_ascii_lowercase(),
            port: None,
        })
    }

    fn matches(&self, host: &str, port: u16) -> Option<Specificity> {
        match self {
            Self::Plain {
                host: pat,
                port: Some(p),
            } => (*p == port && glob_match(pat, host)).then_some(Specificity::Exact),
            Self::Plain {
                host: pat,
                port: None,
            } => glob_match(pat, host).then_some(Specificity::Bare),
            Self::Hashed { salt, hash } => {
                if hmac_sha1_eq(salt, format!("[{host}]:{port}").as_bytes(), hash) {
                    Some(Specificity::Exact)
                } else if hmac_sha1_eq(salt, host.as_bytes(), hash) {
                    Some(Specificity::Bare)
                } else {
                    None
                }
            }
        }
    }
}

fn hmac_sha1_eq(salt: &[u8], message: &[u8], expected: &[u8]) -> bool {
    let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(salt) else {
        return false;
    };
    mac.update(message);
    mac.verify_slice(expected).is_ok()
}

/// OpenSSH-style host pattern match: `*` matches any run, `?` one byte;
/// case-insensitive on ASCII. `pattern` is already lowercased.
fn glob_match(pattern: &str, host: &str) -> bool {
    fn rec(p: &[u8], h: &[u8]) -> bool {
        match (p.first(), h.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], h) || (!h.is_empty() && rec(p, &h[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &h[1..]),
            (Some(pc), Some(hc)) => pc.eq_ignore_ascii_case(hc) && rec(&p[1..], &h[1..]),
            _ => false,
        }
    }
    if !pattern.contains(['*', '?']) {
        return pattern.eq_ignore_ascii_case(host);
    }
    rec(pattern.as_bytes(), host.as_bytes())
}

#[derive(Debug, Clone)]
struct HostEntry {
    patterns: Vec<HostPattern>,
    key: PublicKey,
    source: String,
    line: usize,
}

/// Known server keys, keyed by host (and optionally port).
///
/// Port semantics: an entry written with a port (`host:port`, `[host]:port`,
/// or a hashed `[host]:port`) matches only that port. A bare `host` entry
/// matches any port, whether it came from a mysh or an OpenSSH file. OpenSSH
/// itself treats a bare host as "port 22", but that default is meaningless
/// for mysh (which never listens on 22), so a bare host from
/// `~/.ssh/known_hosts` is taken to identify the machine rather than a port.
/// When both an exact-port and a bare entry exist, the exact-port entry
/// decides a mismatch; any match anywhere wins.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    entries: Vec<HostEntry>,
}

impl KnownHosts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses `known_hosts` text in either grammar:
    ///
    /// - mysh: `host[:port] (mysh-x25519|ssh-ed25519) b64 [comment]`
    /// - OpenSSH: `hostpatterns ssh-ed25519 b64 [comment]` where
    ///   `hostpatterns` is a comma list of `host`, `[host]:port`, or
    ///   `|1|salt|hash`.
    ///
    /// `@cert-authority` / `@revoked` lines and other key types are skipped.
    pub fn parse(text: &str, source: &str) -> Self {
        let mut entries = Vec::new();
        for (line_no, line) in content_lines(text) {
            if line.starts_with('@') {
                tracing::debug!(source, line = line_no, "known_hosts: skipping marker line");
                continue;
            }
            let mut tokens = line.split_whitespace();
            let (Some(hosts), Some(kind)) = (tokens.next(), tokens.next()) else {
                tracing::warn!(
                    source,
                    line = line_no,
                    "known_hosts: skipping malformed line"
                );
                continue;
            };
            if !is_key_type(kind) {
                tracing::debug!(
                    source,
                    line = line_no,
                    key_type = kind,
                    "known_hosts: skipping unsupported key type"
                );
                continue;
            }
            let key_part = line[hosts.len()..].trim_start();
            let key = match parse_public_key(key_part) {
                Ok((key, _comment)) => key,
                Err(e) => {
                    tracing::warn!(source, line = line_no, error = %e, "known_hosts: skipping malformed entry");
                    continue;
                }
            };
            let patterns: Vec<HostPattern> =
                hosts.split(',').filter_map(HostPattern::parse).collect();
            if patterns.is_empty() {
                tracing::warn!(
                    source,
                    line = line_no,
                    "known_hosts: no usable host pattern"
                );
                continue;
            }
            entries.push(HostEntry {
                patterns,
                key,
                source: source.to_owned(),
                line: line_no,
            });
        }
        Self { entries }
    }

    /// Reads and parses a file; the path is used as `source`.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Ok(Self::parse(&text, &path.display().to_string()))
    }

    /// Checks `key` for `host:port`. See the type docs for port semantics.
    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> HostMatch {
        let host = normalize_host(host);
        let mut exact_mismatch: Option<&HostEntry> = None;
        let mut bare_mismatch: Option<&HostEntry> = None;
        for entry in &self.entries {
            let best = entry
                .patterns
                .iter()
                .filter_map(|p| p.matches(host, port))
                .min_by_key(|s| match s {
                    Specificity::Exact => 0,
                    Specificity::Bare => 1,
                });
            let Some(spec) = best else { continue };
            if entry.key == *key {
                return HostMatch::Match {
                    source: entry.source.clone(),
                    line: entry.line,
                };
            }
            let slot = match spec {
                Specificity::Exact => &mut exact_mismatch,
                Specificity::Bare => &mut bare_mismatch,
            };
            slot.get_or_insert(entry);
        }
        match exact_mismatch.or(bare_mismatch) {
            Some(entry) => HostMatch::Mismatch {
                source: entry.source.clone(),
                line: entry.line,
                expected: entry.key.fingerprint(),
            },
            None => HostMatch::Unknown,
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Appends a mysh-format line `host:port mysh-x25519 b64` (IPv6 hosts are
    /// bracketed). Creates the file 0600 and its parent 0700.
    pub fn append(path: &Path, host: &str, port: u16, key: &PublicKey) -> std::io::Result<()> {
        let host = normalize_host(host);
        let host_field = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let line = format!("{host_field} {}", key.to_line(None));
        append_line_to(path, &line)
    }
}

/// Strips IPv6 brackets so `[::1]` and `::1` compare equal.
fn normalize_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

// ---------------------------------------------------------------------------
// pins

/// A `--pin` value: a fingerprint or a full public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    Fingerprint(Fingerprint),
    Key(PublicKey),
}

impl Pin {
    pub fn matches(&self, key: &PublicKey) -> bool {
        match self {
            Self::Fingerprint(fp) => key.fingerprint() == *fp,
            Self::Key(k) => k == key,
        }
    }
}

impl FromStr for Pin {
    type Err = KeyError;

    /// Accepts `SHA256:<b64>`, a bare base64 fingerprint, or a public key
    /// line (`mysh-x25519 b64 [c]` / `ssh-ed25519 b64 [c]`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(KeyError::Format("empty pin".into()));
        }
        let first = s.split_whitespace().next().unwrap_or_default();
        if is_key_type(first) {
            return parse_public_key(s).map(|(k, _)| Self::Key(k));
        }
        if looks_like_key_type(first) {
            return Err(KeyError::UnsupportedKeyType(first.to_owned()));
        }
        s.parse().map(Self::Fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;
    use crate::keys::tests::TempDir;

    fn key(n: u8) -> PublicKey {
        let mut b = [0u8; 32];
        b[0] = n | 0x40;
        b[1] = n;
        SecretKey::from_bytes(b).public()
    }

    fn ssh_line(seed: &[u8; 32], comment: &str) -> (String, PublicKey) {
        let kp = ssh_key::private::Ed25519Keypair::from_seed(seed);
        let ssh_pub =
            ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(kp.public), comment);
        let line = ssh_pub.to_openssh().expect("encode");
        let x = crate::keys::ed25519_pk_to_x25519(&kp.public.0).expect("point");
        (line, PublicKey::from_bytes(x))
    }

    fn b64(key: &PublicKey) -> String {
        key.to_line(None)
            .split_whitespace()
            .nth(1)
            .expect("b64")
            .to_owned()
    }

    #[test]
    fn tokenizer_respects_quotes() {
        let t = tokenize_quoted(r#"command="echo \"hi there\"",no-pty ssh-ed25519 AAAA c"#);
        assert_eq!(
            t,
            [
                r#"command="echo \"hi there\"",no-pty"#,
                "ssh-ed25519",
                "AAAA",
                "c"
            ]
        );
        assert_eq!(tokenize_quoted("  a   b "), ["a", "b"]);
        assert_eq!(tokenize_quoted("   "), [] as [&str; 0]);
    }

    #[test]
    fn authorized_keys_parse() {
        let k1 = key(1);
        let k2 = key(2);
        let (ssh, k3) = ssh_line(&[3u8; 32], "ssh user");
        let text = format!(
            "# comment line\n\n{}\
             {}\
             command=\"echo ssh-ed25519 no\",no-pty,from=\"*.example\" {}\n\
             ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC rsa@host\n\
             ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO ec\n\
             mysh-x25519 notbase64!!\n\
             garbage\n",
            k1.to_line(Some("alice laptop")),
            k2.to_line(None),
            ssh,
        );
        let ak = AuthorizedKeys::parse(&text, "test");
        assert_eq!(ak.len(), 3);
        assert!(!ak.is_empty());
        assert!(ak.contains(&k1));
        assert!(ak.contains(&k2));
        assert!(ak.contains(&k3));
        assert!(!ak.contains(&key(9)));
        let e1 = ak.find(&k1).expect("k1");
        assert_eq!(e1.comment.as_deref(), Some("alice laptop"));
        assert_eq!(e1.line, 3);
        assert_eq!(e1.source, "test");
        let e3 = ak.find(&k3).expect("k3");
        assert_eq!(e3.comment.as_deref(), Some("ssh user"));
        assert_eq!(e3.line, 5);
        assert_eq!(ak.iter().count(), 3);

        let mut all = AuthorizedKeys::new();
        assert!(all.is_empty());
        all.extend(ak);
        all.extend(AuthorizedKeys::parse(&key(4).to_line(None), "other"));
        assert_eq!(all.len(), 4);
        assert_eq!(all.find(&key(4)).expect("k4").source, "other");
    }

    #[test]
    fn authorized_keys_file_roundtrip_and_append() {
        let tmp = TempDir::new("authkeys");
        let path = tmp.path("dir").join("authorized_keys");
        assert!(AuthorizedKeys::append_line(&path, &key(1), Some("one")).expect("append"));
        assert!(!AuthorizedKeys::append_line(&path, &key(1), Some("dup")).expect("append"));
        // Missing trailing newline is repaired before appending.
        let mut raw = fs::read_to_string(&path).expect("read");
        raw.pop();
        fs::write(&path, &raw).expect("rewrite");
        assert!(AuthorizedKeys::append_line(&path, &key(2), None).expect("append"));
        let ak = AuthorizedKeys::load(&path).expect("load");
        assert_eq!(ak.len(), 2);
        assert_eq!(ak.find(&key(2)).expect("k2").line, 2);
        assert_eq!(
            ak.find(&key(1)).expect("k1").comment.as_deref(),
            Some("one")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(tmp.path("dir"))
                    .expect("meta")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert!(AuthorizedKeys::load(&tmp.path("nope")).is_err());
    }

    fn hashed(host_as_written: &str, salt: &[u8]) -> String {
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(salt).expect("hmac key");
        mac.update(host_as_written.as_bytes());
        let hash = mac.finalize().into_bytes();
        format!(
            "|1|{}|{}",
            base64::engine::general_purpose::STANDARD.encode(salt),
            base64::engine::general_purpose::STANDARD.encode(hash)
        )
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn known_hosts_plain_port_hashed() {
        let ka = key(10);
        let kb = key(11);
        let kc = key(12);
        let (ssh_line_d, kd) = ssh_line(&[13u8; 32], "");
        let (ssh_line_e, ke) = ssh_line(&[14u8; 32], "");
        let salt = [0x5a_u8; 20];
        let text = format!(
            "# mysh format\n\
             alpha.example:7722 mysh-x25519 {a}\n\
             alpha.example mysh-x25519 {b}\n\
             [2001:db8::1]:7722 mysh-x25519 {c} v6 comment\n\
             2001:db8::1 mysh-x25519 {a}\n\
             # openssh format\n\
             beta.example,10.0.0.5 {d}\n\
             [gamma.example]:2222 {e}\n\
             {hashed_bare} {d}\n\
             {hashed_port} {e}\n\
             @cert-authority *.example {d}\n\
             delta.example ssh-rsa AAAAB3NzaC1yc2E rsa\n\
             broken.example ssh-ed25519 !!!\n\
             *.wild.example mysh-x25519 {c}\n",
            a = b64(&ka),
            b = b64(&kb),
            c = b64(&kc),
            d = ssh_line_d,
            e = ssh_line_e,
            hashed_bare = hashed("hashed.example", &salt),
            hashed_port = hashed("[hashed-port.example]:7722", &salt),
        );
        let kh = KnownHosts::parse(&text, "kh");
        assert_eq!(kh.len(), 9);

        let m = |s: &str, l: usize| HostMatch::Match {
            source: s.into(),
            line: l,
        };

        // Exact port entry (line 2) and bare entry (line 3) both exist.
        assert_eq!(kh.check("alpha.example", 7722, &ka), m("kh", 2));
        assert_eq!(kh.check("ALPHA.example", 7722, &ka), m("kh", 2));
        // Bare entry matches any port.
        assert_eq!(kh.check("alpha.example", 9000, &kb), m("kh", 3));
        // On port 7722 kb also matches via the bare line (any match wins).
        assert_eq!(kh.check("alpha.example", 7722, &kb), m("kh", 3));
        // Unknown key: the exact-port entry decides the mismatch.
        assert_eq!(
            kh.check("alpha.example", 7722, &kc),
            HostMatch::Mismatch {
                source: "kh".into(),
                line: 2,
                expected: ka.fingerprint()
            }
        );
        // Other port: only the bare entry applies.
        assert_eq!(
            kh.check("alpha.example", 9000, &kc),
            HostMatch::Mismatch {
                source: "kh".into(),
                line: 3,
                expected: kb.fingerprint()
            }
        );
        // IPv6 with and without brackets.
        assert_eq!(kh.check("2001:db8::1", 7722, &kc), m("kh", 4));
        assert_eq!(kh.check("[2001:db8::1]", 7722, &kc), m("kh", 4));
        assert_eq!(kh.check("2001:db8::1", 1, &ka), m("kh", 5));
        // OpenSSH comma list, bare → any port.
        assert_eq!(kh.check("beta.example", 7722, &kd), m("kh", 7));
        assert_eq!(kh.check("10.0.0.5", 4444, &kd), m("kh", 7));
        assert_eq!(
            kh.check("beta.example", 7722, &ke),
            HostMatch::Mismatch {
                source: "kh".into(),
                line: 7,
                expected: kd.fingerprint()
            }
        );
        // OpenSSH [host]:port only that port.
        assert_eq!(kh.check("gamma.example", 2222, &ke), m("kh", 8));
        assert_eq!(kh.check("gamma.example", 7722, &ke), HostMatch::Unknown);
        // Hashed bare host, any port.
        assert_eq!(kh.check("hashed.example", 7722, &kd), m("kh", 9));
        assert_eq!(kh.check("hashed.example", 1234, &kd), m("kh", 9));
        assert!(matches!(
            kh.check("hashed.example", 7722, &ke),
            HostMatch::Mismatch { line: 9, .. }
        ));
        // Hashed [host]:port, only that port.
        assert_eq!(kh.check("hashed-port.example", 7722, &ke), m("kh", 10));
        assert_eq!(
            kh.check("hashed-port.example", 7723, &ke),
            HostMatch::Unknown
        );
        // Skipped lines do not match.
        assert_eq!(kh.check("delta.example", 7722, &kd), HostMatch::Unknown);
        assert_eq!(kh.check("broken.example", 7722, &kd), HostMatch::Unknown);
        assert_eq!(kh.check("nobody.example", 7722, &ka), HostMatch::Unknown);
        // Wildcards.
        assert_eq!(kh.check("x.wild.example", 1, &kc), m("kh", 14));
        assert_eq!(kh.check("wild.example", 1, &kc), HostMatch::Unknown);

        let mut merged = KnownHosts::new();
        assert!(merged.is_empty());
        merged.extend(kh);
        merged.extend(KnownHosts::parse("extra mysh-x25519 AAAA\n", "x"));
        assert_eq!(merged.len(), 9);
    }

    #[test]
    fn known_hosts_append_and_load() {
        let tmp = TempDir::new("knownhosts");
        let path = tmp.path("cfg").join("known_hosts");
        KnownHosts::append(&path, "srv.example", 7722, &key(20)).expect("append");
        KnownHosts::append(&path, "::1", 7723, &key(21)).expect("append");
        let text = fs::read_to_string(&path).expect("read");
        assert!(text.starts_with("srv.example:7722 mysh-x25519 "));
        assert!(text.contains("\n[::1]:7723 mysh-x25519 "));
        let kh = KnownHosts::load(&path).expect("load");
        assert_eq!(kh.len(), 2);
        assert!(matches!(
            kh.check("srv.example", 7722, &key(20)),
            HostMatch::Match { line: 1, .. }
        ));
        assert_eq!(kh.check("srv.example", 7723, &key(20)), HostMatch::Unknown);
        assert!(matches!(
            kh.check("[::1]", 7723, &key(21)),
            HostMatch::Match { line: 2, .. }
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn pin_parsing_and_matching() {
        let k = key(30);
        let fp = k.fingerprint();
        let p: Pin = fp.to_string().parse().expect("prefixed");
        assert_eq!(p, Pin::Fingerprint(fp.clone()));
        assert!(p.matches(&k));
        assert!(!p.matches(&key(31)));

        let bare = fp.to_string().trim_start_matches("SHA256:").to_owned();
        let p: Pin = bare.parse().expect("bare");
        assert!(p.matches(&k));

        let p: Pin = k.to_line(Some("c")).parse().expect("line");
        assert_eq!(p, Pin::Key(k));
        assert!(p.matches(&k));

        let (line, kx) = ssh_line(&[32u8; 32], "x");
        let p: Pin = line.parse().expect("ssh line");
        assert!(p.matches(&kx));
        assert!(!p.matches(&k));

        assert!(matches!("".parse::<Pin>(), Err(KeyError::Format(_))));
        assert!(matches!(
            "ssh-rsa AAAA".parse::<Pin>(),
            Err(KeyError::UnsupportedKeyType(_))
        ));
        assert!("SHA256:short".parse::<Pin>().is_err());
    }
}
