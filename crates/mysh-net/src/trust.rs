//! Trust stores: `authorized_keys` (server side), `known_hosts` (client
//! side), and `--pin` values. See `docs/02-security.md`, "Authorization" and
//! "Server trust".
//!
//! Both stores accept native `mysh-x25519` lines and OpenSSH `ssh-ed25519`
//! lines (converted to X25519). Other key types are skipped.

use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT;
use hmac::Mac as _;

use crate::keys::{
    Fingerprint, KeyError, PUBLIC_KEY_TYPE, PublicKey, SSH_ED25519_TYPE, decode_ssh_ed25519_blob,
    open_append_private, parse_public_key,
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

/// Per-key restrictions from the option prefix of an `authorized_keys`
/// line (`docs/02-security.md`, "Authorization").
///
/// Recognised: `command="…"`, `no-pty`, `no-files`, `no-forward` (alias
/// `no-port-forwarding`), `from="pat,…"`, `restrict` (= the three `no-*`
/// flags; a later `pty`, `files` or `port-forwarding` re-enables one, as in
/// OpenSSH). Anything else is ignored with a `debug` log. Option names are
/// case-insensitive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOptions {
    /// Forced command; the requested command is exposed to it by the server.
    pub command: Option<String>,
    pub no_pty: bool,
    pub no_files: bool,
    pub no_forward: bool,
    /// Source patterns (`from=`), negations kept with their leading `!`.
    /// Empty = any source.
    pub from: Vec<String>,
}

/// Why an option prefix was rejected (the whole line is then skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
enum OptionsError {
    UnterminatedQuote,
    MissingValue(String),
}

impl std::fmt::Display for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnterminatedQuote => f.write_str("unterminated quoted option value"),
            Self::MissingValue(name) => write!(f, "option `{name}` requires a value"),
        }
    }
}

impl KeyOptions {
    /// Whether a client connecting from `ip` passes the `from=` patterns:
    /// true when there are none; otherwise no negated pattern may match and
    /// at least one positive pattern must.
    pub fn allows_source(&self, ip: IpAddr) -> bool {
        if self.from.is_empty() {
            return true;
        }
        let text = ip.to_string();
        let mut positive = false;
        for pattern in &self.from {
            let (negated, pattern) = match pattern.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, pattern.as_str()),
            };
            if source_matches(pattern, ip, &text) {
                if negated {
                    return false;
                }
                positive = true;
            }
        }
        positive
    }

    /// Parses one comma-separated option list (the text before the key
    /// type). Values may be double-quoted with `\"` escapes.
    fn parse_list(&mut self, list: &str) -> Result<(), OptionsError> {
        let mut rest = list;
        loop {
            rest = rest.trim_start_matches([',', ' ', '\t']);
            if rest.is_empty() {
                return Ok(());
            }
            let name_len = rest.find([',', '=']).unwrap_or(rest.len());
            let name = &rest[..name_len];
            rest = &rest[name_len..];
            let value = if let Some(after_eq) = rest.strip_prefix('=') {
                let (value, tail) = take_option_value(after_eq)?;
                rest = tail;
                Some(value)
            } else {
                None
            };
            self.apply(name, value)?;
        }
    }

    fn apply(&mut self, name: &str, value: Option<String>) -> Result<(), OptionsError> {
        let lower = name.to_ascii_lowercase();
        let need_value =
            |value: Option<String>| value.ok_or_else(|| OptionsError::MissingValue(lower.clone()));
        match lower.as_str() {
            "command" => self.command = Some(need_value(value)?),
            "from" => {
                let value = need_value(value)?;
                for pattern in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    let bare = pattern.strip_prefix('!').unwrap_or(pattern);
                    if bare.contains('/') && parse_cidr(bare).is_none() {
                        tracing::warn!(pattern, "authorized_keys: malformed CIDR in from=");
                    }
                    self.from.push(pattern.to_owned());
                }
            }
            "no-pty" => self.no_pty = true,
            "no-files" => self.no_files = true,
            "no-forward" | "no-port-forwarding" => self.no_forward = true,
            "restrict" => {
                self.no_pty = true;
                self.no_files = true;
                self.no_forward = true;
            }
            "pty" => self.no_pty = false,
            "files" => self.no_files = false,
            "port-forwarding" => self.no_forward = false,
            _ => tracing::debug!(option = name, "authorized_keys: ignoring unknown option"),
        }
        Ok(())
    }
}

/// Reads an option value starting right after `=`: a double-quoted string
/// (only `\"` is unescaped, as in OpenSSH) or a bare run up to the next
/// comma. Returns the value and the remaining text.
fn take_option_value(s: &str) -> Result<(String, &str), OptionsError> {
    let Some(quoted) = s.strip_prefix('"') else {
        let end = s.find(',').unwrap_or(s.len());
        return Ok((s[..end].to_owned(), &s[end..]));
    };
    let mut value = String::new();
    let mut chars = quoted.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((value, &quoted[i + 1..])),
            '\\' => match chars.next() {
                Some((_, '"')) => value.push('"'),
                Some((_, other)) => {
                    value.push('\\');
                    value.push(other);
                }
                None => break,
            },
            other => value.push(other),
        }
    }
    Err(OptionsError::UnterminatedQuote)
}

/// Parses `addr/prefix` into the network address bits, the prefix length
/// and the address width.
fn parse_cidr(s: &str) -> Option<(u128, u32, u32)> {
    let (addr, bits) = s.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    let (value, width) = match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    (bits <= width).then_some((value, bits, width))
}

/// One `from=` pattern against a source address: an exact address, a CIDR
/// block (same family only) or a glob over the textual address.
fn source_matches(pattern: &str, ip: IpAddr, text: &str) -> bool {
    if let Ok(exact) = pattern.parse::<IpAddr>() {
        return exact == ip;
    }
    if pattern.contains('/') {
        let Some((net, bits, width)) = parse_cidr(pattern) else {
            return false;
        };
        let (value, ip_width) = match ip {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
            IpAddr::V6(v6) => (u128::from(v6), 128),
        };
        if width != ip_width {
            return false;
        }
        if bits == 0 {
            return true;
        }
        let shift = width - bits;
        return net >> shift == value >> shift;
    }
    glob_match(&pattern.to_ascii_lowercase(), text)
}

/// One trusted client key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: PublicKey,
    pub comment: Option<String>,
    /// File path or other origin label (`"baked"`, `"--authorized-key"`).
    pub source: String,
    /// 1-based line number within `source`.
    pub line: usize,
    /// Restrictions from the line's option prefix.
    pub options: KeyOptions,
    /// Raw Ed25519 public key when the line was `ssh-ed25519` (for
    /// signature authentication); `None` for native `mysh-x25519` lines.
    pub ed25519: Option<[u8; 32]>,
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
    /// OpenSSH option prefixes before the key type are parsed into
    /// [`KeyOptions`]; unknown key types, malformed options and malformed
    /// lines are skipped with a warning.
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
            let mut options = KeyOptions::default();
            if let Err(e) = tokens[..pos]
                .iter()
                .try_for_each(|list| options.parse_list(list))
            {
                tracing::warn!(source, line = line_no, error = %e, "authorized_keys: skipping entry with malformed options");
                continue;
            }
            let key_part = tokens[pos..].join(" ");
            match parse_public_key(&key_part) {
                Ok((key, comment)) => {
                    let ed25519 = (tokens[pos] == SSH_ED25519_TYPE)
                        .then(|| {
                            tokens
                                .get(pos + 1)
                                .and_then(|b64| decode_ssh_ed25519_blob(b64).ok())
                        })
                        .flatten();
                    entries.push(Entry {
                        key,
                        comment,
                        source: source.to_owned(),
                        line: line_no,
                        options,
                        ed25519,
                    });
                }
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

    /// The entry whose line carried this raw Ed25519 public key, if any.
    pub fn find_ed25519(&self, pk: &[u8; 32]) -> Option<&Entry> {
        self.entries.iter().find(|e| e.ed25519.as_ref() == Some(pk))
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

    /// Appends a complete public key line as given (`mysh-x25519 …` or
    /// `ssh-ed25519 …`, for pairing); no duplicate check. Creates the file
    /// 0600 and its parent 0700.
    pub fn append_raw_line(path: &Path, line: &str) -> std::io::Result<()> {
        append_line_to(path, line)
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
        assert_eq!(
            e3.options,
            KeyOptions {
                command: Some("echo ssh-ed25519 no".to_owned()),
                no_pty: true,
                from: vec!["*.example".to_owned()],
                ..KeyOptions::default()
            }
        );
        let ed = e3.ed25519.expect("ssh-ed25519 line keeps the raw key");
        assert_eq!(
            crate::keys::ed25519_pk_to_x25519(&ed).expect("point"),
            *k3.as_bytes()
        );
        assert!(std::ptr::eq(ak.find_ed25519(&ed).expect("by ed25519"), e3));
        assert!(ak.find_ed25519(&[0u8; 32]).is_none());
        assert_eq!(e1.ed25519, None);
        assert_eq!(e1.options, KeyOptions::default());
        assert_eq!(ak.iter().count(), 3);

        let mut all = AuthorizedKeys::new();
        assert!(all.is_empty());
        all.extend(ak);
        all.extend(AuthorizedKeys::parse(&key(4).to_line(None), "other"));
        assert_eq!(all.len(), 4);
        assert_eq!(all.find(&key(4)).expect("k4").source, "other");
    }

    fn options_of(prefix: &str) -> KeyOptions {
        let text = format!("{prefix} {}", key(7).to_line(None));
        let ak = AuthorizedKeys::parse(&text, "opts");
        ak.find(&key(7)).expect("entry parsed").options.clone()
    }

    #[test]
    fn key_options_each_option_parses() {
        assert_eq!(
            options_of("no-pty"),
            KeyOptions {
                no_pty: true,
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of("no-files"),
            KeyOptions {
                no_files: true,
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of("no-forward"),
            KeyOptions {
                no_forward: true,
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of("No-Port-Forwarding"),
            KeyOptions {
                no_forward: true,
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of(r#"command="uptime""#),
            KeyOptions {
                command: Some("uptime".to_owned()),
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of(r#"from="10.0.0.0/8,!10.1.2.3""#),
            KeyOptions {
                from: vec!["10.0.0.0/8".to_owned(), "!10.1.2.3".to_owned()],
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of("restrict"),
            KeyOptions {
                no_pty: true,
                no_files: true,
                no_forward: true,
                ..KeyOptions::default()
            }
        );
        assert_eq!(
            options_of("restrict,pty,port-forwarding"),
            KeyOptions {
                no_files: true,
                ..KeyOptions::default()
            }
        );
        // Combined, with spaces after commas and a trailing comma.
        assert_eq!(
            options_of(r#"no-pty,command="ls -l", no-files,"#),
            KeyOptions {
                command: Some("ls -l".to_owned()),
                no_pty: true,
                no_files: true,
                ..KeyOptions::default()
            }
        );
    }

    #[test]
    fn key_options_quoting() {
        assert_eq!(
            options_of(r#"command="echo \"hi, there\" a\\b",no-pty"#).command,
            Some(r#"echo "hi, there" a\\b"#.to_owned())
        );
        assert_eq!(
            options_of("command=bare,no-pty").command,
            Some("bare".to_owned())
        );
        // Unterminated quote: no key type is found, the line is skipped.
        let text = format!(r#"command="oops {}"#, key(7).to_line(None));
        assert!(AuthorizedKeys::parse(&text, "opts").is_empty());
        // Options needing a value without one skip the line.
        let text = format!("command,no-pty {}", key(7).to_line(None));
        assert!(AuthorizedKeys::parse(&text, "opts").is_empty());
        let text = format!("from {}", key(7).to_line(None));
        assert!(AuthorizedKeys::parse(&text, "opts").is_empty());
    }

    #[test]
    fn key_options_unknown_ignored() {
        assert_eq!(
            options_of(r#"environment="FOO=bar,baz",permitopen="host:80",agent-forwarding,no-pty"#),
            KeyOptions {
                no_pty: true,
                ..KeyOptions::default()
            }
        );
    }

    fn from(patterns: &[&str]) -> KeyOptions {
        KeyOptions {
            from: patterns.iter().map(|p| (*p).to_owned()).collect(),
            ..KeyOptions::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal")
    }

    #[test]
    fn key_options_from_empty_allows_all() {
        assert!(KeyOptions::default().allows_source(ip("203.0.113.9")));
        assert!(KeyOptions::default().allows_source(ip("::1")));
    }

    #[test]
    fn key_options_from_exact_and_cidr() {
        let o = from(&["192.0.2.7"]);
        assert!(o.allows_source(ip("192.0.2.7")));
        assert!(!o.allows_source(ip("192.0.2.8")));

        let o = from(&["10.0.0.0/8"]);
        assert!(o.allows_source(ip("10.255.1.2")));
        assert!(!o.allows_source(ip("11.0.0.1")));
        assert!(!o.allows_source(ip("::ffff:10.0.0.1")));

        let o = from(&["192.168.1.64/26"]);
        assert!(o.allows_source(ip("192.168.1.64")));
        assert!(o.allows_source(ip("192.168.1.127")));
        assert!(!o.allows_source(ip("192.168.1.128")));
        assert!(!o.allows_source(ip("192.168.1.63")));

        let o = from(&["0.0.0.0/0"]);
        assert!(o.allows_source(ip("8.8.8.8")));
        assert!(!o.allows_source(ip("2001:db8::1")));

        let o = from(&["fd00::/8"]);
        assert!(o.allows_source(ip("fd12:3456::1")));
        assert!(!o.allows_source(ip("fe80::1")));
        assert!(!o.allows_source(ip("10.0.0.1")));

        let o = from(&["2001:db8:abcd::/48"]);
        assert!(o.allows_source(ip("2001:db8:abcd:ffff::1")));
        assert!(!o.allows_source(ip("2001:db8:abce::1")));

        // Exact IPv6 compares numerically, not textually.
        let o = from(&["0:0:0:0:0:0:0:1"]);
        assert!(o.allows_source(ip("::1")));

        // Malformed CIDR never matches.
        assert!(!from(&["10.0.0.0/33"]).allows_source(ip("10.0.0.1")));
        assert!(!from(&["10.0.0/8"]).allows_source(ip("10.0.0.1")));
        assert!(!from(&["fd00::/129"]).allows_source(ip("fd00::1")));
    }

    #[test]
    fn key_options_from_glob_and_negation() {
        let o = from(&["192.168.1.*"]);
        assert!(o.allows_source(ip("192.168.1.200")));
        assert!(!o.allows_source(ip("192.168.2.1")));

        let o = from(&["2001:DB8:*"]);
        assert!(o.allows_source(ip("2001:db8::1")));
        assert!(!o.allows_source(ip("2001:db9::1")));

        let o = from(&["10.0.?.1"]);
        assert!(o.allows_source(ip("10.0.5.1")));
        assert!(!o.allows_source(ip("10.0.55.1")));

        // Hostname globs match the textual IP only (no reverse DNS).
        assert!(!from(&["*.lan"]).allows_source(ip("10.0.0.1")));

        // Negation denies even when a positive pattern matches.
        let o = from(&["10.0.0.0/8", "!10.0.0.0/24"]);
        assert!(o.allows_source(ip("10.0.1.1")));
        assert!(!o.allows_source(ip("10.0.0.1")));
        let o = from(&["!10.0.0.5", "10.0.0.*"]);
        assert!(!o.allows_source(ip("10.0.0.5")));
        assert!(o.allows_source(ip("10.0.0.6")));

        // Only negations: nothing positive ever matches, so everything is denied.
        let o = from(&["!192.0.2.1"]);
        assert!(!o.allows_source(ip("192.0.2.2")));
        assert!(!o.allows_source(ip("192.0.2.1")));
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
