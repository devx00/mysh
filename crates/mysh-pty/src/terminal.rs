//! Client-side terminal plumbing: tty detection, window size, the raw-mode
//! guard, suspend/resume, and the signal streams the client driver needs
//! (`docs/04-sessions.md` "Client terminal driver").

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};

use mysh_proto::session::WinSize;
use rustix::process::Signal;
use rustix::termios::{OptionalActions, SpecialCodeIndex, Termios};
use tokio::signal::unix::SignalKind;

use crate::pty::from_winsize;

/// `isatty(fd)`.
pub fn is_terminal(fd: impl AsFd) -> bool {
    rustix::termios::isatty(fd)
}

/// `TIOCGWINSZ`; fails with `ENOTTY` on anything that is not a terminal.
pub fn window_size(fd: impl AsFd) -> io::Result<WinSize> {
    Ok(from_winsize(rustix::termios::tcgetwinsize(fd)?))
}

/// Raw-mode guard. Holds a private dup of the terminal fd and the termios
/// it had on entry; dropping the guard restores it (errors ignored — the
/// terminal may already be gone).
#[derive(Debug)]
pub struct RawMode {
    fd: OwnedFd,
    original: Termios,
    raw: Termios,
}

/// Put the terminal behind `fd` (usually stdin) into raw mode: `cfmakeraw`
/// on input and output flags like ssh, `VMIN = 1`, `VTIME = 0`, applied with
/// `TCSANOW`. `fd` is dup'd internally; the caller keeps ownership.
pub fn enter_raw_mode(fd: RawFd) -> io::Result<RawMode> {
    // SAFETY: the caller passes a descriptor they hold open (stdin in
    // practice); we only borrow it for the duration of the dup below.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let fd = borrowed.try_clone_to_owned()?;
    let original = rustix::termios::tcgetattr(&fd)?;
    let mut raw = original.clone();
    raw.make_raw();
    raw.special_codes[SpecialCodeIndex::VMIN] = 1;
    raw.special_codes[SpecialCodeIndex::VTIME] = 0;
    rustix::termios::tcsetattr(&fd, OptionalActions::Now, &raw)?;
    Ok(RawMode { fd, original, raw })
}

impl RawMode {
    /// Temporarily restore the original termios (before `SIGTSTP`, or to run
    /// a cooked-mode helper).
    pub fn suspend(&self) -> io::Result<()> {
        rustix::termios::tcsetattr(&self.fd, OptionalActions::Now, &self.original)?;
        Ok(())
    }

    /// Re-apply raw mode after [`RawMode::suspend`] (on `SIGCONT`).
    pub fn resume(&self) -> io::Result<()> {
        rustix::termios::tcsetattr(&self.fd, OptionalActions::Now, &self.raw)?;
        Ok(())
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(&self.fd, OptionalActions::Now, &self.original);
    }
}

/// `kill(0, SIGTSTP)`: stop our whole process group, as a shell's `Ctrl-Z`
/// would. The caller restores the terminal first ([`RawMode::suspend`]).
pub fn suspend_self() -> io::Result<()> {
    rustix::process::kill_current_process_group(Signal::TSTP)?;
    Ok(())
}

/// Stream of `SIGWINCH` deliveries.
pub fn sigwinch() -> io::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(SignalKind::window_change())
}

/// Stream of `SIGCONT` deliveries (resume after [`suspend_self`]).
pub fn sigcont() -> io::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(SignalKind::from_raw(Signal::CONT.as_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn non_tty_is_detected_and_has_no_window_size() {
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        assert!(!is_terminal(&null));
        assert!(window_size(&null).is_err());
        assert!(enter_raw_mode(null.as_raw_fd()).is_err());
    }

    #[test]
    fn pty_slave_is_a_terminal_with_the_requested_size() {
        let size = WinSize {
            cols: 132,
            rows: 43,
            xpixel: 0,
            ypixel: 0,
        };
        let (_master, slave) = crate::pty::open_pty(size).expect("open pty");
        assert!(is_terminal(&slave));
        assert_eq!(window_size(&slave).expect("winsize"), size);
    }

    #[test]
    fn raw_mode_guard_restores_termios_on_drop() {
        use rustix::termios::LocalModes;

        let (_master, slave) = crate::pty::open_pty(WinSize::default()).expect("open pty");
        let before = rustix::termios::tcgetattr(&slave).expect("tcgetattr");
        assert!(
            before
                .local_modes
                .contains(LocalModes::ECHO | LocalModes::ICANON)
        );
        {
            let guard = enter_raw_mode(slave.as_raw_fd()).expect("enter raw mode");
            let now = rustix::termios::tcgetattr(&slave).expect("tcgetattr");
            assert!(!now.local_modes.contains(LocalModes::ECHO));
            assert!(!now.local_modes.contains(LocalModes::ICANON));
            assert_eq!(now.special_codes[SpecialCodeIndex::VMIN], 1);
            assert_eq!(now.special_codes[SpecialCodeIndex::VTIME], 0);

            guard.suspend().expect("suspend");
            let suspended = rustix::termios::tcgetattr(&slave).expect("tcgetattr");
            assert!(
                suspended
                    .local_modes
                    .contains(LocalModes::ECHO | LocalModes::ICANON)
            );
            guard.resume().expect("resume");
            let resumed = rustix::termios::tcgetattr(&slave).expect("tcgetattr");
            assert!(!resumed.local_modes.contains(LocalModes::ECHO));
        }
        let after = rustix::termios::tcgetattr(&slave).expect("tcgetattr");
        assert!(
            after
                .local_modes
                .contains(LocalModes::ECHO | LocalModes::ICANON)
        );
        // The guard's dup must not have closed the caller's fd.
        assert!(is_terminal(&slave));
    }

    /// Needs the test process to have a real controlling terminal on stdin.
    #[test]
    #[ignore = "requires a real tty on stdin"]
    fn stdin_raw_mode_round_trip() {
        let stdin = std::io::stdin();
        assert!(is_terminal(&stdin));
        let size = window_size(&stdin).expect("winsize");
        assert!(size.cols > 0 && size.rows > 0);
        let guard = enter_raw_mode(stdin.as_raw_fd()).expect("raw mode");
        drop(guard);
    }
}
