//! Local terminal: raw-mode guard, the single stdin reader task, meta-key
//! interception, `SIGWINCH`/`SIGCONT` (docs/04-sessions.md "Client terminal
//! driver", docs/05-meta-shell.md "Meta key").
//!
//! Exactly one [`Terminal`] exists per client run; it owns stdin for the
//! whole run and hands bytes to whichever consumer is current (a foreground
//! session or the prompt's line editor). The meta key is split out of the
//! byte stream wherever it appears, so a chunk `b"ab\x1dcd"` yields
//! `Bytes(ab)`, `MetaKey`, `Bytes(cd)` in that order.
//!
//! `tokio::io::stdin` reads on a blocking thread; a read that is pending at
//! exit keeps that thread alive, which is why the process ends with
//! `std::process::exit` rather than by returning from `main`.

use std::{collections::VecDeque, io, os::fd::AsRawFd as _};

use mysh_proto::session::WinSize;
use mysh_pty::terminal::{
    RawMode, enter_raw_mode, is_terminal, sigcont, sigwinch, suspend_self, window_size,
};
use tokio::{io::AsyncReadExt as _, signal::unix::Signal, sync::mpsc};
use tracing::debug;

use crate::client::console::Console;

/// Stdin read chunk.
const CHUNK: usize = 4096;

/// One event from the local terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Raw stdin bytes (never containing the meta key).
    Bytes(Vec<u8>),
    /// The meta key was pressed.
    MetaKey,
    /// The window size changed (also emitted after `SIGCONT`).
    Winch,
    /// Stdin reached end of file.
    Eof,
}

/// The local terminal and stdin reader. See the module docs.
pub struct Terminal {
    console: Console,
    raw: Option<RawMode>,
    interactive: bool,
    meta_key: Option<u8>,
    rx: mpsc::Receiver<Vec<u8>>,
    pending: VecDeque<Input>,
    winch: Option<Signal>,
    cont: Option<Signal>,
    eof: bool,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Terminal")
            .field("interactive", &self.interactive)
            .field("raw", &self.raw.is_some())
            .field("meta_key", &self.meta_key)
            .field("eof", &self.eof)
            .finish_non_exhaustive()
    }
}

impl Terminal {
    /// Start the stdin reader; enter raw mode when both stdin and stdout are
    /// terminals (and tell `console` so it translates newlines).
    pub fn new(console: &Console, meta_key: Option<u8>) -> io::Result<Terminal> {
        let interactive = is_terminal(io::stdin()) && console.is_tty();
        let raw = if interactive {
            let guard = enter_raw_mode(io::stdin().as_raw_fd())?;
            console.set_raw(true);
            Some(guard)
        } else {
            None
        };
        Self::build(console, raw, interactive, meta_key)
    }

    /// Stdin pump only: no raw mode, no meta key, no signal streams. Used for
    /// `mysh HOST CMD` without `-t`, which leaves the local terminal alone.
    pub fn cooked(console: &Console) -> io::Result<Terminal> {
        Self::build(console, None, false, None)
    }

    fn build(
        console: &Console,
        raw: Option<RawMode>,
        interactive: bool,
        meta_key: Option<u8>,
    ) -> io::Result<Terminal> {
        let (winch, cont) = if interactive {
            (Some(sigwinch()?), Some(sigcont()?))
        } else {
            (None, None)
        };
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(stdin_reader(tx));
        Ok(Terminal {
            console: console.clone(),
            raw,
            interactive,
            meta_key,
            rx,
            pending: VecDeque::new(),
            winch,
            cont,
            eof: false,
        })
    }

    /// Whether stdin and stdout are both terminals (raw mode is active).
    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Current window size; `80x24` when it cannot be determined.
    pub fn winsize(&self) -> WinSize {
        window_size(io::stdin())
            .or_else(|_| window_size(io::stdout()))
            .unwrap_or(WinSize {
                cols: 80,
                rows: 24,
                xpixel: 0,
                ypixel: 0,
            })
    }

    /// Next terminal event. After `Eof` only signal events are delivered
    /// (never `None` while the signal streams exist), so a driver loop can
    /// keep waiting on other sources without spinning.
    pub async fn next(&mut self) -> Option<Input> {
        if let Some(ev) = self.pending.pop_front() {
            return Some(ev);
        }
        loop {
            tokio::select! {
                chunk = self.rx.recv(), if !self.eof => {
                    if let Some(bytes) = chunk {
                        match self.meta_key {
                            Some(key) => self.pending.extend(split_meta(&bytes, key)),
                            None => self.pending.push_back(Input::Bytes(bytes)),
                        }
                        if let Some(ev) = self.pending.pop_front() {
                            return Some(ev);
                        }
                    } else {
                        self.eof = true;
                        return Some(Input::Eof);
                    }
                }
                Some(()) = recv_signal(self.winch.as_mut()) => return Some(Input::Winch),
                Some(()) = recv_signal(self.cont.as_mut()) => {
                    self.resume_raw();
                    return Some(Input::Winch);
                }
                else => return None,
            }
        }
    }

    /// Restore the terminal, stop our process group (`SIGTSTP`), and re-enter
    /// raw mode when we are continued.
    pub fn suspend(&self) {
        if let Some(raw) = &self.raw {
            let _ = raw.suspend();
        }
        if let Err(e) = suspend_self() {
            debug!(error = %e, "suspend failed");
        }
        self.resume_raw();
    }

    fn resume_raw(&self) {
        if let Some(raw) = &self.raw {
            let _ = raw.resume();
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.raw.take().is_some() {
            self.console.set_raw(false);
        }
    }
}

async fn recv_signal(signal: Option<&mut Signal>) -> Option<()> {
    if let Some(s) = signal {
        s.recv().await
    } else {
        std::future::pending().await
    }
}

async fn stdin_reader(tx: mpsc::Sender<Vec<u8>>) {
    let mut stdin = crate::client::ctl::stdin();
    let mut buf = vec![0u8; CHUNK];
    loop {
        match stdin.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!(error = %e, "stdin read failed");
                break;
            }
        }
    }
}

/// Split `buf` around every occurrence of `key`: bytes before a key are
/// delivered first, then `MetaKey`, then the bytes after it. Empty segments
/// are not emitted.
pub fn split_meta(buf: &[u8], key: u8) -> Vec<Input> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &b) in buf.iter().enumerate() {
        if b == key {
            if i > start {
                out.push(Input::Bytes(buf[start..i].to_vec()));
            }
            out.push(Input::MetaKey);
            start = i + 1;
        }
    }
    if start < buf.len() {
        out.push(Input::Bytes(buf[start..].to_vec()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: u8 = 0x1d;

    fn bytes(s: &[u8]) -> Input {
        Input::Bytes(s.to_vec())
    }

    #[test]
    fn key_alone() {
        assert_eq!(split_meta(&[K], K), vec![Input::MetaKey]);
    }

    #[test]
    fn key_at_start() {
        assert_eq!(
            split_meta(b"\x1dabc", K),
            vec![Input::MetaKey, bytes(b"abc")]
        );
    }

    #[test]
    fn key_in_middle() {
        assert_eq!(
            split_meta(b"ab\x1dcd", K),
            vec![bytes(b"ab"), Input::MetaKey, bytes(b"cd")]
        );
    }

    #[test]
    fn key_at_end() {
        assert_eq!(
            split_meta(b"abc\x1d", K),
            vec![bytes(b"abc"), Input::MetaKey]
        );
    }

    #[test]
    fn two_keys() {
        assert_eq!(
            split_meta(b"a\x1d\x1db", K),
            vec![bytes(b"a"), Input::MetaKey, Input::MetaKey, bytes(b"b")]
        );
    }

    #[test]
    fn no_key() {
        assert_eq!(split_meta(b"hello", K), vec![bytes(b"hello")]);
        assert_eq!(split_meta(b"", K).len(), 0);
    }
}
