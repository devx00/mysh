//! How the library talks back to its caller: a [`Reporter`] receives
//! everything the `mysh` binary would have printed, a [`TrustPrompt`]
//! decides about unknown server keys and supplies key passphrases.
//!
//! The `mysh` binary implements both on its terminal console; embedding
//! programs usually keep the silent defaults and consume the typed results
//! of [`crate::Client`] instead.

use std::{future::Future, io, pin::Pin};

use mysh_net::keys::Fingerprint;
use serde::Serialize;

use crate::types::{Bytes, ErrorOut, Event, Mode, codes};

/// Receives what the library wants to surface. Every method has a default
/// so a reporter only has to implement [`Reporter::event`]; the extra
/// hooks exist for the binary's console, which renders text modes.
pub trait Reporter: Send + Sync {
    /// Progress, notices, session output, errors and results — everything
    /// the library surfaces, as the `--json-stream` events of the CLI.
    fn event(&self, ev: &Event);

    /// Whether a human is watching (the binary's console returns `true`
    /// for a terminal); the library may then print banners and prompts.
    fn is_interactive(&self) -> bool {
        false
    }

    /// The output mode the caller renders in. A program that only wants
    /// events keeps the default; the binary answers with its `--json` /
    /// `--json-stream` / `--plain` choice.
    fn mode(&self) -> Mode {
        Mode::Plain
    }

    /// Text for a human (prompts, tables); dropped by default.
    fn print(&self, _text: &str) {}

    /// [`Reporter::print`] plus a newline; dropped by default.
    fn println(&self, _text: &str) {}

    /// A command's result document and its text rendering. The default
    /// forwards the document as an [`Event::Result`].
    fn result(&self, value: serde_json::Value, human: &mut dyn FnMut() -> String) {
        let _ = human;
        self.event(&Event::Result { value });
    }

    /// One JSON document (what `--json` prints, also in `--json-stream`
    /// mode); forwarded as an [`Event::Result`] by default.
    fn emit(&self, value: serde_json::Value) {
        self.event(&Event::Result { value });
    }

    /// Bytes already in their final form (a control-socket relay);
    /// forwarded as [`Event::Stdout`] by default.
    fn write_raw(&self, bytes: &[u8]) {
        self.event(&Event::Stdout {
            data: Bytes::from(bytes),
        });
    }

    /// [`Reporter::write_raw`] for stderr.
    fn write_raw_err(&self, bytes: &[u8]) {
        self.event(&Event::Stderr {
            data: Bytes::from(bytes),
        });
    }

    /// The progress line started by [`Reporter::progress`] is complete.
    fn progress_done(&self) {}

    /// Session bytes collected since the last call, `(stdout, stderr)`;
    /// only the binary's `--json` console collects.
    fn take_exec_capture(&self) -> (Vec<u8>, Vec<u8>) {
        (Vec::new(), Vec::new())
    }

    /// Resolves once everything queued so far has been delivered.
    fn flush(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    /// `[mysh] text`.
    fn notice(&self, text: &str) {
        self.event(&Event::Notice {
            text: text.to_owned(),
        });
    }

    /// Raw session output.
    fn write_bytes(&self, bytes: &[u8]) {
        self.event(&Event::Stdout {
            data: Bytes::from(bytes),
        });
    }

    /// Raw session stderr (exec sessions without a pty).
    fn write_stderr(&self, bytes: &[u8]) {
        self.event(&Event::Stderr {
            data: Bytes::from(bytes),
        });
    }

    /// One update of a progress line; finish with [`Reporter::progress_done`].
    fn progress(&self, label: &str, done: u64, total: Option<u64>) {
        self.event(&Event::Progress {
            label: label.to_owned(),
            done,
            total,
        });
    }

    /// A failed command: its stable code and rendered chain.
    fn error(&self, err: &anyhow::Error) {
        let out = ErrorOut::from_error(err);
        self.event(&Event::Error {
            code: out.error.code,
            message: out.error.message,
        });
    }
}

impl dyn Reporter + '_ {
    /// A command's result: `value` as a document plus its text rendering
    /// (see [`Reporter::result`]). A value that does not serialize is
    /// reported as an `internal` error.
    pub fn report<T: Serialize>(&self, value: &T, human: impl FnOnce() -> String) {
        match serde_json::to_value(value) {
            Ok(value) => {
                let mut human = Some(human);
                self.result(value, &mut || human.take().map(|f| f()).unwrap_or_default());
            }
            Err(e) => self.event(&Event::Error {
                code: codes::INTERNAL.to_owned(),
                message: format!("serializing result: {e}"),
            }),
        }
    }

    /// [`Reporter::emit`] for any serializable value; a value that does
    /// not serialize is reported as an `internal` error.
    pub fn emit_value<T: Serialize>(&self, value: &T) {
        match serde_json::to_value(value) {
            Ok(value) => self.emit(value),
            Err(e) => self.event(&Event::Error {
                code: codes::INTERNAL.to_owned(),
                message: format!("serializing output: {e}"),
            }),
        }
    }
}

/// Drops everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullReporter;

impl Reporter for NullReporter {
    fn event(&self, _ev: &Event) {}
}

/// Decides about an unknown server key (TOFU) and supplies passphrases of
/// encrypted key files. The default refuses both, so a program that does
/// not implement it only connects to known hosts with unencrypted keys.
pub trait TrustPrompt: Send + Sync {
    /// Whether to trust `fp` for `host:port` and record it in
    /// `known_hosts`. Called only when the key is unknown and the target
    /// neither has `accept_new` nor `strict` set.
    fn confirm_unknown(&self, host: &str, port: u16, fp: &Fingerprint) -> bool;

    /// The passphrase of the encrypted key file `source`; an error leaves
    /// the key unusable (and the connection fails with that error).
    fn passphrase(&self, source: &str) -> io::Result<String> {
        Err(io::Error::other(format!(
            "{source}: key is passphrase-protected and no prompt is available"
        )))
    }
}

/// Refuses unknown keys and passphrase prompts.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseUnknown;

impl TrustPrompt for RefuseUnknown {
    fn confirm_unknown(&self, _host: &str, _port: u16, _fp: &Fingerprint) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct Collect(Mutex<Vec<Event>>);

    impl Reporter for Collect {
        fn event(&self, ev: &Event) {
            self.0.lock().expect("lock").push(ev.clone());
        }
    }

    #[test]
    fn defaults_route_through_event() {
        let r = Collect(Mutex::new(Vec::new()));
        let dynr: &dyn Reporter = &r;
        dynr.notice("hi");
        dynr.progress("x", 1, Some(2));
        dynr.report(&serde_json::json!({"ok": true}), || "ok\n".to_owned());
        dynr.error(&anyhow::anyhow!("boom"));
        let evs = r.0.lock().expect("lock");
        assert_eq!(evs.len(), 4);
        assert!(matches!(&evs[0], Event::Notice { text } if text == "hi"));
        assert!(matches!(&evs[2], Event::Result { value } if value["ok"] == true));
        assert!(matches!(&evs[3], Event::Error { code, .. } if code == codes::INTERNAL));
        assert!(!dynr.is_interactive());
        assert_eq!(dynr.mode(), Mode::Plain);
    }

    #[test]
    fn refuse_unknown_refuses() {
        let p = RefuseUnknown;
        assert!(!p.confirm_unknown("h", 1, &Fingerprint::of_ssh_ed25519(&[0u8; 32])));
        assert!(p.passphrase("k").is_err());
    }
}
