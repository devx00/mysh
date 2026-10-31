//! `Msg<T>` framing: `u32-LE len ‖ postcard(T)`, `len ≤ MAX_CONTROL_MESSAGE`.
//!
//! Used inside every message-mode stream after the prologue. Pure functions
//! only; `mysh-net` supplies the async read/write wrappers.

use serde::{Serialize, de::DeserializeOwned};

use crate::MAX_CONTROL_MESSAGE;

/// Size of the length prefix.
pub const HEADER_LEN: usize = 4;

/// Framing and codec failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("message of {0} bytes exceeds the {MAX_CONTROL_MESSAGE}-byte limit")]
    TooLarge(usize),
    #[error("postcard: {0}")]
    Codec(#[from] postcard::Error),
}

/// Encode `msg` as a complete frame (header + body).
pub fn encode<T: Serialize + ?Sized>(msg: &T) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; HEADER_LEN];
    postcard::to_io(msg, &mut out)?;
    let len = out.len() - HEADER_LEN;
    if len > MAX_CONTROL_MESSAGE {
        return Err(Error::TooLarge(len));
    }
    #[allow(clippy::cast_possible_truncation)] // bounded by MAX_CONTROL_MESSAGE
    out[..HEADER_LEN].copy_from_slice(&(len as u32).to_le_bytes());
    Ok(out)
}

/// Decode a frame body (without the header).
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    Ok(postcard::from_bytes(body)?)
}

/// Parse a header; returns the body length or `TooLarge`.
pub fn body_len(header: [u8; HEADER_LEN]) -> Result<usize, Error> {
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_CONTROL_MESSAGE {
        return Err(Error::TooLarge(len));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let frame = encode(&(7u32, String::from("x"))).unwrap();
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&frame[..HEADER_LEN]);
        let len = body_len(header).unwrap();
        assert_eq!(len, frame.len() - HEADER_LEN);
        let back: (u32, String) = decode(&frame[HEADER_LEN..]).unwrap();
        assert_eq!(back, (7, "x".into()));
    }

    #[test]
    fn rejects_oversize() {
        let big = vec![0u8; MAX_CONTROL_MESSAGE + 1];
        assert!(matches!(encode(&big), Err(Error::TooLarge(_))));
        let header = u32::try_from(MAX_CONTROL_MESSAGE + 1)
            .unwrap()
            .to_le_bytes();
        assert!(matches!(body_len(header), Err(Error::TooLarge(_))));
    }
}
