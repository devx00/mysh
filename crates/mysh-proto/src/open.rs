//! Stream prologue: every yamux stream starts with an [`Open`] from the
//! opener and an [`OpenReply`] from the acceptor (docs/03-protocol.md §5).
//!
//! `Open` is framed as `Msg<[kind: u8 ‖ postcard(body)]>` so an acceptor can
//! reply `Unsupported` to a kind it does not know without decoding the body.

use serde::{Deserialize, Serialize};

use crate::{file::FileOp, frame, session::SessionRequest};

/// Stream kinds. Numeric tags are wire-stable; append only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Open {
    /// Exactly one per connection, opened by the client first.
    Control,
    /// Client → server.
    Session(SessionRequest),
    /// Client → server; raw bytes after `Ok`.
    DirectTcp { host: String, port: u16 },
    /// Client → server; message mode, lives as long as the listener.
    ForwardListen { host: String, port: u16 },
    /// Server → client, one per accepted connection; raw bytes after `Ok`.
    ForwardedTcp { listener: u32, peer: String },
    /// Client → server; see [`crate::file`].
    File { op: FileOp, cwd: Option<String> },
    /// Client → server; one `Msg<Option<String>>` then close.
    Cwd { session: u32 },
    /// Client → server; reattach to a detached PTY session. On `Ok` the
    /// stream becomes that session's stream: `SessionOut::Attached`, the
    /// buffered output, then live traffic.
    Attach { session: u32 },
    /// Client → server; one `Msg<Vec<DetachedSession>>` then close.
    ListSessions,
}

/// Kind tags for [`Open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpenKind {
    Control = 0,
    Session = 1,
    DirectTcp = 2,
    ForwardListen = 3,
    ForwardedTcp = 4,
    File = 5,
    Cwd = 6,
    Attach = 7,
    ListSessions = 8,
}

impl OpenKind {
    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::Control,
            1 => Self::Session,
            2 => Self::DirectTcp,
            3 => Self::ForwardListen,
            4 => Self::ForwardedTcp,
            5 => Self::File,
            6 => Self::Cwd,
            7 => Self::Attach,
            8 => Self::ListSessions,
            _ => return None,
        })
    }
}

/// Decoding an [`Open`] body.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("empty Open message")]
    Empty,
    #[error("unknown Open kind {0}")]
    UnknownKind(u8),
    #[error(transparent)]
    Frame(#[from] frame::Error),
}

impl Open {
    pub fn kind(&self) -> OpenKind {
        match self {
            Self::Control => OpenKind::Control,
            Self::Session(_) => OpenKind::Session,
            Self::DirectTcp { .. } => OpenKind::DirectTcp,
            Self::ForwardListen { .. } => OpenKind::ForwardListen,
            Self::ForwardedTcp { .. } => OpenKind::ForwardedTcp,
            Self::File { .. } => OpenKind::File,
            Self::Cwd { .. } => OpenKind::Cwd,
            Self::Attach { .. } => OpenKind::Attach,
            Self::ListSessions => OpenKind::ListSessions,
        }
    }

    /// `kind ‖ postcard(body)`; wrap with [`frame::encode`]-style header via
    /// [`Open::encode_frame`] for the wire.
    pub fn encode_body(&self) -> Result<Vec<u8>, frame::Error> {
        let mut out = vec![self.kind() as u8];
        match self {
            Self::Control | Self::ListSessions => {}
            Self::Session(req) => {
                postcard::to_io(req, &mut out)?;
            }
            Self::DirectTcp { host, port } | Self::ForwardListen { host, port } => {
                postcard::to_io(&(host, port), &mut out)?;
            }
            Self::ForwardedTcp { listener, peer } => {
                postcard::to_io(&(listener, peer), &mut out)?;
            }
            Self::File { op, cwd } => {
                postcard::to_io(&(op, cwd), &mut out)?;
            }
            Self::Cwd { session } | Self::Attach { session } => {
                postcard::to_io(session, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Complete frame: `u32-LE len ‖ kind ‖ body`.
    pub fn encode_frame(&self) -> Result<Vec<u8>, frame::Error> {
        let body = self.encode_body()?;
        if body.len() > crate::MAX_CONTROL_MESSAGE {
            return Err(frame::Error::TooLarge(body.len()));
        }
        let mut out = Vec::with_capacity(frame::HEADER_LEN + body.len());
        #[allow(clippy::cast_possible_truncation)] // bounded above
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a frame body (after the length header).
    pub fn decode_body(body: &[u8]) -> Result<Self, OpenError> {
        let (&tag, rest) = body.split_first().ok_or(OpenError::Empty)?;
        let kind = OpenKind::from_tag(tag).ok_or(OpenError::UnknownKind(tag))?;
        Ok(match kind {
            OpenKind::Control => Self::Control,
            OpenKind::Session => Self::Session(frame::decode(rest)?),
            OpenKind::DirectTcp => {
                let (host, port) = frame::decode(rest)?;
                Self::DirectTcp { host, port }
            }
            OpenKind::ForwardListen => {
                let (host, port) = frame::decode(rest)?;
                Self::ForwardListen { host, port }
            }
            OpenKind::ForwardedTcp => {
                let (listener, peer) = frame::decode(rest)?;
                Self::ForwardedTcp { listener, peer }
            }
            OpenKind::File => {
                let (op, cwd) = frame::decode(rest)?;
                Self::File { op, cwd }
            }
            OpenKind::Cwd => Self::Cwd {
                session: frame::decode(rest)?,
            },
            OpenKind::Attach => Self::Attach {
                session: frame::decode(rest)?,
            },
            OpenKind::ListSessions => Self::ListSessions,
        })
    }
}

/// Acceptor's answer to an [`Open`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenReply {
    Ok,
    Err { code: ErrorCode, message: String },
}

/// Failure classes shared by `OpenReply` and the handshake verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Peer static key is not trusted.
    Unauthorized,
    /// Policy refusal (`--deny …`).
    Denied,
    NotFound,
    /// Unknown or unimplemented `Open` kind.
    Unsupported,
    Io,
    /// Quota exceeded (streams, sessions, listeners).
    Limit,
    /// Malformed message or sequencing violation.
    Protocol,
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "unauthorized",
            Self::Denied => "denied by server policy",
            Self::NotFound => "not found",
            Self::Unsupported => "unsupported",
            Self::Io => "i/o error",
            Self::Limit => "limit exceeded",
            Self::Protocol => "protocol error",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{PtyRequest, SessionKind, WinSize};

    #[test]
    fn open_round_trips_every_kind() {
        let cases = vec![
            Open::Control,
            Open::Session(SessionRequest {
                kind: SessionKind::Exec {
                    argv: vec!["ls".into(), "-l".into()],
                },
                env: vec![("TERM".into(), "xterm".into())],
                pty: Some(PtyRequest {
                    term: "xterm".into(),
                    size: WinSize {
                        cols: 80,
                        rows: 24,
                        xpixel: 0,
                        ypixel: 0,
                    },
                }),
                cwd: Some("~/src".into()),
            }),
            Open::DirectTcp {
                host: "localhost".into(),
                port: 80,
            },
            Open::ForwardListen {
                host: "0.0.0.0".into(),
                port: 0,
            },
            Open::ForwardedTcp {
                listener: 3,
                peer: "10.0.0.1:5555".into(),
            },
            Open::File {
                op: FileOp::Stat {
                    path: "/etc".into(),
                },
                cwd: None,
            },
            Open::Cwd { session: 9 },
            Open::Attach { session: 4 },
            Open::ListSessions,
        ];
        for open in cases {
            let frame = open.encode_frame().unwrap();
            let body = &frame[frame::HEADER_LEN..];
            assert_eq!(body[0], open.kind() as u8);
            assert_eq!(Open::decode_body(body).unwrap(), open);
        }
    }

    #[test]
    fn unknown_kind_is_reported_without_decoding_body() {
        assert!(matches!(
            Open::decode_body(&[200, 1, 2, 3]),
            Err(OpenError::UnknownKind(200))
        ));
        assert!(matches!(Open::decode_body(&[]), Err(OpenError::Empty)));
    }
}
