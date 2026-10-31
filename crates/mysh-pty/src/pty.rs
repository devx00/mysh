//! Pseudo-terminal pair: open, resize, foreground process group, and a
//! tokio-driven master.
//!
//! The pair is opened with `posix_openpt`/`grantpt`/`unlockpt`/`ptsname`
//! rather than `openpty(3)` (absent on old bionic) or `forkpty(3)` (forks a
//! multi-threaded runtime); see `docs/04-sessions.md` "PTY session (server)".

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use mysh_proto::session::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::io::{Errno, FdFlags};
use rustix::pty::OpenptFlags;
use rustix::termios::Winsize;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Master side of a pty. `O_NONBLOCK | CLOEXEC`.
#[derive(Debug)]
pub struct PtyMaster(OwnedFd);

/// Slave side of a pty. `CLOEXEC`; consumed by [`crate::spawn::spawn_with_pty`].
#[derive(Debug)]
pub struct PtySlave(pub(crate) OwnedFd);

impl AsFd for PtyMaster {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for PtySlave {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for PtySlave {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

fn to_winsize(size: WinSize) -> Winsize {
    Winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.xpixel,
        ws_ypixel: size.ypixel,
    }
}

pub(crate) fn from_winsize(ws: Winsize) -> WinSize {
    WinSize {
        cols: ws.ws_col,
        rows: ws.ws_row,
        xpixel: ws.ws_xpixel,
        ypixel: ws.ws_ypixel,
    }
}

/// Open a pty pair and set its initial window size (`TIOCSWINSZ`) so the
/// child never observes 0×0.
pub fn open_pty(size: WinSize) -> io::Result<(PtyMaster, PtySlave)> {
    let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
    rustix::pty::grantpt(&master)?;
    rustix::pty::unlockpt(&master)?;
    let name = rustix::pty::ptsname(&master, Vec::new())?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;

    // `posix_openpt` has no CLOEXEC flag on macOS (rustix only honours it on
    // Linux), so set it explicitly along with non-blocking mode.
    rustix::io::fcntl_setfd(&master, FdFlags::CLOEXEC)?;
    let flags = rustix::fs::fcntl_getfl(&master)?;
    rustix::fs::fcntl_setfl(&master, flags | OFlags::NONBLOCK)?;

    let master = PtyMaster(master);
    master.resize(size)?;
    Ok((master, PtySlave(slave)))
}

/// `tcgetpgrp` errors (ENOTTY, no foreground group) are not actionable for
/// callers; they all mean "no probe target".
fn foreground_pgrp_of(fd: BorrowedFd<'_>) -> Option<u32> {
    rustix::termios::tcgetpgrp(fd)
        .ok()
        .and_then(|pid| u32::try_from(pid.as_raw_nonzero().get()).ok())
}

impl PtyMaster {
    /// `TIOCSWINSZ`. The kernel delivers `SIGWINCH` to the foreground process
    /// group of the slave.
    pub fn resize(&self, size: WinSize) -> io::Result<()> {
        rustix::termios::tcsetwinsize(&self.0, to_winsize(size))?;
        Ok(())
    }

    /// `tcgetpgrp` on the master: the foreground process group of the
    /// session, used as the cwd-probe target. `None` when the tty has no
    /// foreground group any more (or on any other error, e.g. `ENOTTY`).
    pub fn foreground_pgrp(&self) -> io::Result<Option<u32>> {
        Ok(foreground_pgrp_of(self.0.as_fd()))
    }

    /// Register the master with the tokio reactor.
    pub fn into_async(self) -> io::Result<AsyncPtyMaster> {
        // SAFETY: `PtyMaster` owns its `OwnedFd`; `as_raw_fd` always returns
        // that descriptor and it stays open until the `AsyncFd` is dropped.
        let fd = unsafe { AsyncFd::register(self) }.map_err(|e| e.into_parts().1)?;
        Ok(AsyncPtyMaster(fd))
    }
}

/// Non-blocking pty master driven by the tokio reactor.
///
/// Reads report EOF (`Ok(0)`) once the last slave descriptor is closed: Linux
/// signals that with `EIO`, macOS with a plain zero-length read.
#[derive(Debug)]
pub struct AsyncPtyMaster(AsyncFd<PtyMaster>);

impl AsyncPtyMaster {
    /// See [`PtyMaster::resize`].
    pub fn resize(&self, size: WinSize) -> io::Result<()> {
        self.0.get_ref().resize(size)
    }

    /// See [`PtyMaster::foreground_pgrp`].
    pub fn foreground_pgrp(&self) -> io::Result<Option<u32>> {
        self.0.get_ref().foreground_pgrp()
    }
}

impl AsFd for AsyncPtyMaster {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.get_ref().as_fd()
    }
}

impl AsRawFd for AsyncPtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.0.get_ref().as_raw_fd()
    }
}

fn read_master(master: &PtyMaster, buf: &mut [u8]) -> io::Result<usize> {
    match rustix::io::read(master, buf) {
        Ok(n) => Ok(n),
        // Linux: EIO once every slave fd is closed. ENXIO shows up on some
        // BSD-derived ptys in the same situation. Both mean "hung up" = EOF.
        Err(Errno::IO | Errno::NXIO) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

impl AsyncRead for AsyncPtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| read_master(inner.get_ref(), unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                // Spurious wakeup: readiness was cleared by `try_io`; poll again.
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for AsyncPtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard
                .try_io(|inner| rustix::io::write(inner.get_ref(), data).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A pty has no half-close; the session closes the master by dropping it.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_sets_size_and_flags() {
        let size = WinSize {
            cols: 100,
            rows: 40,
            xpixel: 0,
            ypixel: 0,
        };
        let (master, slave) = open_pty(size).expect("open pty");
        let ws = rustix::termios::tcgetwinsize(&slave).expect("winsize");
        assert_eq!((ws.ws_row, ws.ws_col), (40, 100));

        let fl = rustix::fs::fcntl_getfl(&master).expect("getfl");
        assert!(fl.contains(OFlags::NONBLOCK));
        let fd = rustix::io::fcntl_getfd(&master).expect("getfd");
        assert!(fd.contains(FdFlags::CLOEXEC));
        let fd = rustix::io::fcntl_getfd(&slave).expect("getfd");
        assert!(fd.contains(FdFlags::CLOEXEC));

        master
            .resize(WinSize {
                cols: 120,
                rows: 50,
                xpixel: 0,
                ypixel: 0,
            })
            .expect("resize");
        let ws = rustix::termios::tcgetwinsize(&slave).expect("winsize");
        assert_eq!((ws.ws_row, ws.ws_col), (50, 120));
    }

    #[tokio::test]
    async fn master_hits_eof_when_slave_closes() {
        use tokio::io::AsyncReadExt;

        let (master, slave) = open_pty(WinSize::default()).expect("open pty");
        let mut master = master.into_async().expect("async");
        // Nothing holds the slave: the first read must report EOF, not hang
        // or fail with EIO.
        drop(slave);
        let mut out = Vec::new();
        let n = master.read_to_end(&mut out).await.expect("read_to_end");
        assert_eq!(n, 0);
    }
}
