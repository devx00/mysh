//! Pairing primitives for `mysh pair` (docs/02-security.md "Pairing"):
//! SPAKE2 over the Ed25519 group with explicit key confirmation.
//!
//! The password is the normalized one-time code; the identities are the two
//! Noise static public keys of the connection (client = A, server = B), so
//! the derived key is bound to this very channel. Confirmation is
//! client-first: `HMAC-SHA256(K, LABEL ‖ T)` with the labels from
//! [`mysh_proto::pair`] and `T = client_static ‖ server_static ‖ client_msg
//! ‖ server_msg`. Neither side treats the other as paired before its MAC
//! verified.

use std::fmt;

use hmac::{Hmac, Mac as _};
use mysh_proto::pair::{CLIENT_CONFIRM_LABEL, SERVER_CONFIRM_LABEL, normalize_code};
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::PublicKey;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum PairError {
    /// The peer's SPAKE2 message was malformed (wrong length or not a
    /// valid group element).
    #[error("malformed pairing message: {0}")]
    BadMessage(spake2::Error),
    /// A confirmation MAC did not verify: the codes differ, the transcript
    /// differs, or the message was tampered with.
    #[error("pairing confirmation failed")]
    BadMac,
}

/// A random code of `words` words from `list`, hyphen-joined; each word
/// carries `log2(list.len())` bits (11 for the BIP-39 list).
#[must_use]
pub fn generate_code(list: &[&str], words: usize) -> String {
    assert!(!list.is_empty(), "empty word list");
    let mut rng = OsRng;
    let mut picked = Vec::with_capacity(words);
    for _ in 0..words {
        // Rejection sampling keeps the choice uniform for any list length.
        let bound = u32::MAX - (u32::MAX % u32::try_from(list.len()).unwrap_or(u32::MAX));
        let r = loop {
            let r = rng.next_u32();
            if r < bound {
                break r;
            }
        };
        let idx = usize::try_from(r).unwrap_or(0) % list.len();
        picked.push(list[idx]);
    }
    picked.join("-")
}

/// One side of a SPAKE2 exchange, between `start_*` and [`Pake::finish`].
pub struct Pake {
    state: Spake2<Ed25519Group>,
}

impl fmt::Debug for Pake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pake { .. }")
    }
}

impl Pake {
    /// Client side (SPAKE2 "A"); returns the state and message A to send.
    #[must_use]
    pub fn start_client(
        code: &str,
        client_static: &PublicKey,
        server_static: &PublicKey,
    ) -> (Self, Vec<u8>) {
        let (state, msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(normalize_code(code)),
            &Identity::new(client_static.as_bytes()),
            &Identity::new(server_static.as_bytes()),
        );
        (Self { state }, msg)
    }

    /// Server side (SPAKE2 "B"); returns the state and message B to send.
    #[must_use]
    pub fn start_server(
        code: &str,
        client_static: &PublicKey,
        server_static: &PublicKey,
    ) -> (Self, Vec<u8>) {
        let (state, msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(normalize_code(code)),
            &Identity::new(client_static.as_bytes()),
            &Identity::new(server_static.as_bytes()),
        );
        (Self { state }, msg)
    }

    /// Derive the shared key from the peer's message. Succeeds for any
    /// well-formed message; only the confirmation MACs reveal whether the
    /// codes matched.
    pub fn finish(self, peer_msg: &[u8]) -> Result<SharedKey, PairError> {
        let key = self.state.finish(peer_msg).map_err(PairError::BadMessage)?;
        let mut bytes = [0u8; 32];
        if key.len() != bytes.len() {
            return Err(PairError::BadMessage(spake2::Error::WrongLength));
        }
        bytes.copy_from_slice(&key);
        Ok(SharedKey(bytes))
    }
}

/// What both sides hash the confirmation MACs over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    pub client_static: PublicKey,
    pub server_static: PublicKey,
    pub client_msg: Vec<u8>,
    pub server_msg: Vec<u8>,
}

impl Transcript {
    /// `T = client_static ‖ server_static ‖ client_msg ‖ server_msg`.
    fn bytes(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(64 + self.client_msg.len() + self.server_msg.len());
        t.extend_from_slice(self.client_static.as_bytes());
        t.extend_from_slice(self.server_static.as_bytes());
        t.extend_from_slice(&self.client_msg);
        t.extend_from_slice(&self.server_msg);
        t
    }
}

/// The SPAKE2 output key `K`; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedKey([u8; 32]);

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedKey(..)")
    }
}

impl SharedKey {
    fn mac(&self, label: &[u8], t: &Transcript) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(label);
        mac.update(&t.bytes());
        mac
    }

    fn tag(&self, label: &[u8], t: &Transcript) -> [u8; 32] {
        self.mac(label, t).finalize().into_bytes().into()
    }

    fn verify(&self, label: &[u8], t: &Transcript, mac: &[u8; 32]) -> Result<(), PairError> {
        self.mac(label, t)
            .verify_slice(mac)
            .map_err(|_| PairError::BadMac)
    }

    /// `HMAC-SHA256(K, CLIENT_CONFIRM_LABEL ‖ T)`.
    #[must_use]
    pub fn confirm_client(&self, t: &Transcript) -> [u8; 32] {
        self.tag(CLIENT_CONFIRM_LABEL, t)
    }

    /// `HMAC-SHA256(K, SERVER_CONFIRM_LABEL ‖ T)`.
    #[must_use]
    pub fn confirm_server(&self, t: &Transcript) -> [u8; 32] {
        self.tag(SERVER_CONFIRM_LABEL, t)
    }

    /// Constant-time check of the client's confirmation MAC.
    pub fn verify_client(&self, t: &Transcript, mac: &[u8; 32]) -> Result<(), PairError> {
        self.verify(CLIENT_CONFIRM_LABEL, t, mac)
    }

    /// Constant-time check of the server's confirmation MAC.
    pub fn verify_server(&self, t: &Transcript, mac: &[u8; 32]) -> Result<(), PairError> {
        self.verify(SERVER_CONFIRM_LABEL, t, mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;

    const LIST: &[&str] = &["alpha", "bravo", "charlie", "delta", "echo"];

    fn exchange(
        client_code: &str,
        server_code: &str,
        server_static_for_client: &PublicKey,
        client_static: &PublicKey,
        server_static: &PublicKey,
    ) -> (SharedKey, SharedKey, Transcript, Transcript) {
        let (c, msg_a) = Pake::start_client(client_code, client_static, server_static_for_client);
        let (s, msg_b) = Pake::start_server(server_code, client_static, server_static);
        let ck = c.finish(&msg_b).unwrap();
        let sk = s.finish(&msg_a).unwrap();
        let ct = Transcript {
            client_static: *client_static,
            server_static: *server_static_for_client,
            client_msg: msg_a.clone(),
            server_msg: msg_b.clone(),
        };
        let st = Transcript {
            client_static: *client_static,
            server_static: *server_static,
            client_msg: msg_a,
            server_msg: msg_b,
        };
        (ck, sk, ct, st)
    }

    #[test]
    fn round_trip_confirms_both_ways() {
        let cs = SecretKey::generate().public();
        let ss = SecretKey::generate().public();
        let (ck, sk, ct, st) = exchange("Apple bread-cat", "apple-bread-cat", &ss, &cs, &ss);
        assert_eq!(ck.0, sk.0);
        sk.verify_client(&st, &ck.confirm_client(&ct)).unwrap();
        ck.verify_server(&ct, &sk.confirm_server(&st)).unwrap();
        // The two labels never collide.
        assert_ne!(ck.confirm_client(&ct), ck.confirm_server(&ct));
    }

    #[test]
    fn wrong_code_gives_different_keys_and_mac_mismatch() {
        let cs = SecretKey::generate().public();
        let ss = SecretKey::generate().public();
        let (ck, sk, ct, st) = exchange("apple-bread-cat", "apple-bread-dog", &ss, &cs, &ss);
        assert_ne!(ck.0, sk.0);
        assert!(matches!(
            sk.verify_client(&st, &ck.confirm_client(&ct)),
            Err(PairError::BadMac)
        ));
        assert!(matches!(
            ck.verify_server(&ct, &sk.confirm_server(&st)),
            Err(PairError::BadMac)
        ));
    }

    #[test]
    fn transcript_binds_the_server_static() {
        let cs = SecretKey::generate().public();
        let ss = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        // Same code, but the client believes it talks to `other`: the
        // identities differ, so SPAKE2 keys differ and the MACs mismatch.
        let (ck, sk, ct, st) = exchange("apple-bread-cat", "apple-bread-cat", &other, &cs, &ss);
        assert_ne!(ck.0, sk.0);
        assert!(sk.verify_client(&st, &ck.confirm_client(&ct)).is_err());
        // Even with an equal key, swapping the static in the transcript
        // changes the MAC.
        let (ck, _, ct, _) = exchange("apple-bread-cat", "apple-bread-cat", &ss, &cs, &ss);
        let mut swapped = ct.clone();
        swapped.server_static = other;
        assert_ne!(ck.confirm_client(&ct), ck.confirm_client(&swapped));
        assert!(ck.verify_client(&swapped, &ck.confirm_client(&ct)).is_err());
    }

    #[test]
    fn malformed_peer_message_is_rejected() {
        let cs = SecretKey::generate().public();
        let ss = SecretKey::generate().public();
        let (c, _) = Pake::start_client("a-b", &cs, &ss);
        assert!(matches!(c.finish(b"short"), Err(PairError::BadMessage(_))));
    }

    #[test]
    fn generate_code_draws_from_the_list() {
        let code = generate_code(LIST, 6);
        let words: Vec<&str> = code.split('-').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|w| LIST.contains(w)));
        assert_eq!(normalize_code(&code), code);
        assert_ne!(generate_code(LIST, 8), generate_code(LIST, 8));
    }
}
