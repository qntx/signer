//! Error types for the Sui signer.

use std::fmt;

/// Errors from Sui signing operations.
#[derive(Debug)]
pub enum Error {
    /// Private key is invalid.
    InvalidKey(String),
    /// Signature verification failed.
    VerifyFailed(ed25519_dalek::SignatureError),
    /// Hex decoding failed.
    Hex(hex::FromHexError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::VerifyFailed(e) => write!(f, "verification failed: {e}"),
            Self::Hex(e) => write!(f, "hex error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::VerifyFailed(e)
    }
}
