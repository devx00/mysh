//! Minimal client for the OpenSSH agent protocol (`draft-miller-ssh-agent`).
//!
//! Only what a later authentication slice needs: list the ed25519 identities
//! an agent holds and ask it to sign a blob. No key material ever leaves the
//! agent; this module is wire I/O only and knows nothing about trust.
//!
//! Wire format: every message is `uint32 length ‖ byte type ‖ payload`;
//! strings are `uint32 len ‖ bytes`. Messages are capped at [`MAX_MESSAGE`]
//! and every round trip is bounded by [`REQUEST_TIMEOUT`].

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Largest agent message we are willing to read (256 KiB).
pub const MAX_MESSAGE: usize = 256 * 1024;
/// Per-request deadline (write + read of the reply).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const ED25519: &[u8] = b"ssh-ed25519";

/// An ed25519 identity held by the agent.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentKey {
    /// Raw 32-byte ed25519 public key.
    pub public: [u8; 32],
    /// Full SSH wire blob: `string "ssh-ed25519" ‖ string pk`.
    pub blob: Vec<u8>,
    /// Agent-side comment (usually the key file path or `-C` text).
    pub comment: String,
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKey")
            .field("public", &format_args!("{:02x?}", &self.public[..4]))
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

/// Connection to an `ssh-agent` Unix socket.
#[derive(Debug)]
pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    /// Connect to the agent socket at `path`.
    pub async fn connect(path: &Path) -> io::Result<Agent> {
        let stream = UnixStream::connect(path).await?;
        Ok(Agent { stream })
    }

    /// `$SSH_AUTH_SOCK` if set and non-empty.
    #[must_use]
    pub fn from_env() -> Option<PathBuf> {
        std::env::var_os("SSH_AUTH_SOCK")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    }

    /// List the ed25519 identities the agent holds; other key types are skipped.
    pub async fn list_ed25519(&mut self) -> io::Result<Vec<AgentKey>> {
        let reply = self.request(SSH_AGENTC_REQUEST_IDENTITIES, &[]).await?;
        let (ty, payload) = split_type(&reply)?;
        if ty != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(unexpected(ty));
        }
        let mut r = Reader(payload);
        let count = r.u32()?;
        let mut keys = Vec::new();
        for _ in 0..count {
            let blob = r.string()?;
            let comment = r.string()?;
            if let Some(public) = parse_ed25519_blob(blob) {
                keys.push(AgentKey {
                    public,
                    blob: blob.to_vec(),
                    comment: String::from_utf8_lossy(comment).into_owned(),
                });
            }
        }
        r.finish()?;
        Ok(keys)
    }

    /// Ask the agent to sign `data` with `key`.
    ///
    /// # Errors
    /// `PermissionDenied` if the agent refuses (key not held, user declined a
    /// confirmation prompt, …); `InvalidData` on a malformed reply; `TimedOut`
    /// after [`REQUEST_TIMEOUT`].
    pub async fn sign(&mut self, key: &AgentKey, data: &[u8]) -> io::Result<[u8; 64]> {
        let mut req = Vec::with_capacity(4 + key.blob.len() + 4 + data.len() + 4);
        put_string(&mut req, &key.blob);
        put_string(&mut req, data);
        req.extend_from_slice(&0u32.to_be_bytes()); // flags
        let reply = self.request(SSH_AGENTC_SIGN_REQUEST, &req).await?;
        let (ty, payload) = split_type(&reply)?;
        match ty {
            SSH_AGENT_SIGN_RESPONSE => {}
            SSH_AGENT_FAILURE => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "agent refused to sign",
                ));
            }
            other => return Err(unexpected(other)),
        }
        let mut r = Reader(payload);
        let sig_blob = r.string()?;
        r.finish()?;
        let mut s = Reader(sig_blob);
        if s.string()? != ED25519 {
            return Err(invalid("agent signature is not ssh-ed25519"));
        }
        let sig = s.string()?;
        s.finish()?;
        <[u8; 64]>::try_from(sig).map_err(|_| invalid("ed25519 signature is not 64 bytes"))
    }

    /// One round trip: send `ty ‖ payload`, return the reply (type byte first).
    async fn request(&mut self, ty: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
        let len = u32::try_from(payload.len() + 1).map_err(|_| invalid("request too large"))?;
        let mut msg = Vec::with_capacity(5 + payload.len());
        msg.extend_from_slice(&len.to_be_bytes());
        msg.push(ty);
        msg.extend_from_slice(payload);
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            self.stream.write_all(&msg).await?;
            let mut hdr = [0u8; 4];
            self.stream.read_exact(&mut hdr).await?;
            let len = u32::from_be_bytes(hdr) as usize;
            if len == 0 || len > MAX_MESSAGE {
                return Err(invalid("agent message length out of range"));
            }
            let mut body = vec![0u8; len];
            self.stream.read_exact(&mut body).await?;
            Ok(body)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ssh-agent request timed out"))?
    }
}

/// Build the SSH wire blob `string "ssh-ed25519" ‖ string pk` from a raw key.
#[must_use]
pub fn ed25519_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + ED25519.len() + 4 + 32);
    put_string(&mut blob, ED25519);
    put_string(&mut blob, public);
    blob
}

/// Parse an SSH wire blob; `None` unless it is exactly an ed25519 key.
#[must_use]
pub fn parse_ed25519_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader(blob);
    if r.string().ok()? != ED25519 {
        return None;
    }
    let pk = r.string().ok()?;
    r.finish().ok()?;
    pk.try_into().ok()
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    // Callers only pass blobs/data far below u32::MAX; saturate rather than panic.
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
}

fn split_type(reply: &[u8]) -> io::Result<(u8, &[u8])> {
    reply
        .split_first()
        .map(|(t, rest)| (*t, rest))
        .ok_or_else(|| invalid("empty agent message"))
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn unexpected(ty: u8) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected agent message type {ty}"),
    )
}

/// Cursor over an agent payload.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> io::Result<u32> {
        let (head, rest) = self
            .0
            .split_first_chunk::<4>()
            .ok_or_else(|| invalid("truncated agent message"))?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > self.0.len() {
            return Err(invalid("truncated agent string"));
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(s)
    }

    fn finish(self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing bytes in agent message"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn blob_round_trip() {
        let pk = [7u8; 32];
        let blob = ed25519_blob(&pk);
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(parse_ed25519_blob(&blob), Some(pk));
        assert_eq!(parse_ed25519_blob(&blob[..blob.len() - 1]), None);
        assert_eq!(parse_ed25519_blob(&[blob.clone(), vec![0]].concat()), None);
        let mut rsa = Vec::new();
        put_string(&mut rsa, b"ssh-rsa");
        put_string(&mut rsa, &pk);
        assert_eq!(parse_ed25519_blob(&rsa), None);
    }

    #[test]
    fn from_env_ignores_empty() {
        // Only observe; never mutate the process env (other tests run in parallel).
        let env = std::env::var_os("SSH_AUTH_SOCK");
        assert_eq!(
            Agent::from_env().is_some(),
            env.is_some_and(|s| !s.is_empty())
        );
    }

    fn on_path(tool: &str) -> bool {
        Command::new(tool)
            .arg("-V")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    /// Spawned `ssh-agent`, killed on drop.
    struct SpawnedAgent {
        pid: u32,
        sock: PathBuf,
    }

    impl SpawnedAgent {
        fn spawn(dir: &Path) -> Self {
            let sock = dir.join("sock");
            let out = Command::new("ssh-agent")
                .arg("-a")
                .arg(&sock)
                .output()
                .expect("ssh-agent spawn");
            assert!(
                out.status.success(),
                "ssh-agent: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            let pid = stdout
                .split("SSH_AGENT_PID=")
                .nth(1)
                .and_then(|s| s.split(';').next())
                .and_then(|s| s.trim().parse::<u32>().ok())
                .expect("SSH_AGENT_PID in ssh-agent output");
            SpawnedAgent { pid, sock }
        }
    }

    impl Drop for SpawnedAgent {
        fn drop(&mut self) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(self.pid.to_string())
                .status();
        }
    }

    /// Plain ed25519 verification via curve25519-dalek:
    /// `[s]B == R + H(R ‖ A ‖ M)·A`.
    fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest as _, Sha512};

        let Some(pk_point) = CompressedEdwardsY(*public).decompress() else {
            return false;
        };
        let (r_bytes, s_bytes) = sig.split_at(32);
        let Ok(r_bytes) = <[u8; 32]>::try_from(r_bytes) else {
            return false;
        };
        let Ok(s_bytes) = <[u8; 32]>::try_from(s_bytes) else {
            return false;
        };
        let scalar_s: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
        let Some(scalar_s) = scalar_s else {
            return false;
        };
        let hash = Sha512::new()
            .chain_update(r_bytes)
            .chain_update(public)
            .chain_update(msg)
            .finalize();
        let challenge = Scalar::from_bytes_mod_order_wide(&hash.into());
        // R' = [s]B - [k]A
        let r_point =
            EdwardsPoint::vartime_double_scalar_mul_basepoint(&challenge, &(-pk_point), &scalar_s);
        r_point.compress().0 == r_bytes
    }

    /// Removes the temp dir on drop.
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn agent_lists_and_signs() {
        for tool in ["ssh-agent", "ssh-add", "ssh-keygen"] {
            if !on_path(tool) {
                eprintln!("skipping agent_lists_and_signs: {tool} not on PATH");
                return;
            }
        }
        let dir = std::env::temp_dir().join(format!("mysh-agent-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let _cleanup = Cleanup(dir.clone());

        let agent = SpawnedAgent::spawn(&dir);
        let id = dir.join("id");
        let st = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", "testkey", "-f"])
            .arg(&id)
            .stdout(Stdio::null())
            .status()
            .expect("ssh-keygen");
        assert!(st.success());
        let out = Command::new("ssh-add")
            .arg(&id)
            .env("SSH_AUTH_SOCK", &agent.sock)
            .output()
            .expect("ssh-add");
        assert!(
            out.status.success(),
            "ssh-add: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let publine = std::fs::read_to_string(dir.join("id.pub")).expect("id.pub");
        let b64 = publine.split_whitespace().nth(1).expect("id.pub field");
        let blob = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .expect("base64")
        };
        let expected = parse_ed25519_blob(&blob).expect("ed25519 pub");

        let mut client = Agent::connect(&agent.sock).await.expect("connect");
        let keys = client.list_ed25519().await.expect("list");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].public, expected);
        assert_eq!(keys[0].blob, blob);
        assert_eq!(keys[0].comment, "testkey");

        let sig = client.sign(&keys[0], b"hello").await.expect("sign");
        assert!(
            verify(&expected, b"hello", &sig),
            "signature does not verify"
        );
        assert!(!verify(&expected, b"hellp", &sig));
        let sig2 = client.sign(&keys[0], b"hello").await.expect("sign again");
        assert_eq!(sig, sig2, "ed25519 is deterministic");
        let other = client.sign(&keys[0], b"world").await.expect("sign other");
        assert_ne!(sig, other);

        let unknown = AgentKey {
            public: [9u8; 32],
            blob: ed25519_blob(&[9u8; 32]),
            comment: String::new(),
        };
        let err = client
            .sign(&unknown, b"hello")
            .await
            .expect_err("unknown key");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
