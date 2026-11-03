//! The error of [`crate::Client`]: an anyhow chain tagged with one of the
//! stable codes of [`crate::types::codes`] (docs/05-meta-shell.md "Error
//! codes"), the same classification the CLI prints as `{"error": …}`.

use std::fmt;

use crate::types::code_for;

/// A failed client operation.
#[derive(Debug)]
pub struct Error {
    /// Stable code: one of the constants in [`crate::types::codes`].
    pub code: &'static str,
    source: anyhow::Error,
}

impl Error {
    /// Tag `source` with an explicit code.
    #[must_use]
    pub fn new(code: &'static str, source: anyhow::Error) -> Self {
        Self { code, source }
    }

    /// The full chain (`{err:#}`), what `Display` prints.
    #[must_use]
    pub fn message(&self) -> String {
        format!("{:#}", self.source)
    }

    /// The underlying chain.
    #[must_use]
    pub fn inner(&self) -> &anyhow::Error {
        &self.source
    }

    /// Unwrap the underlying chain.
    #[must_use]
    pub fn into_inner(self) -> anyhow::Error {
        self.source
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

/// The source is the head of the inner chain, so a `CodedError` inside it
/// is still found by [`code_for`] after the error is wrapped again.
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Classify with [`code_for`]: the first coded cause in the chain, else
/// `internal`.
impl From<anyhow::Error> for Error {
    fn from(source: anyhow::Error) -> Self {
        Self {
            code: code_for(&source),
            source,
        }
    }
}

/// `Result` with the client [`Error`] by default.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;
    use crate::types::{coded, codes};

    #[test]
    fn classifies_from_chain() {
        let e = Error::from(coded(codes::NOT_FOUND, anyhow!("nope")).context("stat"));
        assert_eq!(e.code, codes::NOT_FOUND);
        assert_eq!(e.to_string(), "stat: nope");
        let plain = Error::from(anyhow!("x"));
        assert_eq!(plain.code, codes::INTERNAL);
        // Wrapped again, the code is still found through `source()`.
        let rewrapped = anyhow::Error::new(e).context("outer");
        assert_eq!(code_for(&rewrapped), codes::NOT_FOUND);
    }
}
