//! Async wrappers over `mysh_proto::frame` (`Msg<T>`) and the stream
//! prologue (`Open` / `OpenReply`).
//!
//! All helpers are cancellation-unsafe in the usual sense: a cancelled
//! `read_msg` may have consumed part of a frame. Callers own the stream and
//! only ever run one read at a time, so this is acceptable.

use std::io;

use mysh_proto::frame::{self, HEADER_LEN};
use mysh_proto::open::{Open, OpenError, OpenReply};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn invalid(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Write one `Msg<T>` frame (`frame::encode`) and flush.
pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize + ?Sized>(
    w: &mut W,
    msg: &T,
) -> io::Result<()> {
    let bytes = frame::encode(msg).map_err(invalid)?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Read one frame body (header already validated against the size cap).
///
/// Clean EOF before the header → `UnexpectedEof`; oversize → `InvalidData`.
async fn read_body<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header).await?;
    let len = frame::body_len(header).map_err(invalid)?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Read one `Msg<T>` frame.
///
/// Clean EOF before the header → `ErrorKind::UnexpectedEof`; oversize or
/// codec failure → `ErrorKind::InvalidData`.
pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let body = read_body(r).await?;
    frame::decode(&body).map_err(invalid)
}

/// Write the stream prologue request (`Open::encode_frame`) and flush.
pub async fn write_open<W: AsyncWrite + Unpin>(w: &mut W, open: &Open) -> io::Result<()> {
    let bytes = open.encode_frame().map_err(invalid)?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Read the stream prologue request.
///
/// `Ok(Err(tag))` is returned for an unknown `OpenKind` tag so the acceptor
/// can reply `Unsupported` without failing the stream.
pub async fn read_open<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Result<Open, u8>> {
    let body = read_body(r).await?;
    match Open::decode_body(&body) {
        Ok(open) => Ok(Ok(open)),
        Err(OpenError::UnknownKind(tag)) => Ok(Err(tag)),
        Err(err) => Err(invalid(err)),
    }
}

/// Write the stream prologue reply and flush.
pub async fn write_reply<W: AsyncWrite + Unpin>(w: &mut W, reply: &OpenReply) -> io::Result<()> {
    write_msg(w, reply).await
}

/// Read the stream prologue reply.
pub async fn read_reply<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<OpenReply> {
    read_msg(r).await
}

#[cfg(test)]
mod tests {
    use mysh_proto::open::ErrorCode;

    use super::*;

    #[tokio::test]
    async fn msg_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_msg(&mut a, &(1u32, String::from("hi")))
            .await
            .unwrap();
        let got: (u32, String) = read_msg(&mut b).await.unwrap();
        assert_eq!(got, (1, "hi".into()));
    }

    #[tokio::test]
    async fn eof_before_header_is_unexpected_eof() {
        let (a, mut b) = tokio::io::duplex(16);
        drop(a);
        let err = read_msg::<_, u32>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn oversize_header_is_invalid_data() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        let err = read_msg::<_, u32>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn open_and_reply_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let open = Open::DirectTcp {
            host: "localhost".into(),
            port: 80,
        };
        write_open(&mut a, &open).await.unwrap();
        assert_eq!(read_open(&mut b).await.unwrap(), Ok(open));

        let reply = OpenReply::Err {
            code: ErrorCode::Denied,
            message: "no".into(),
        };
        write_reply(&mut b, &reply).await.unwrap();
        assert_eq!(read_reply(&mut a).await.unwrap(), reply);
    }

    #[tokio::test]
    async fn unknown_open_kind_yields_tag() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let body = [200u8, 1, 2, 3];
        a.write_all(&u32::try_from(body.len()).unwrap().to_le_bytes())
            .await
            .unwrap();
        a.write_all(&body).await.unwrap();
        assert_eq!(read_open(&mut b).await.unwrap(), Err(200));
    }
}
