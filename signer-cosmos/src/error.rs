//! Error types for the Cosmos signer.

use std::fmt;

/// Errors from Cosmos signing operations.
#[derive(Debug)]
pub enum Error {
    /// Private key is invalid.
    InvalidKey(String),
    /// Message format is wrong.
    InvalidMessage(String),
    /// Signing primitive failed.
    SigningFailed(String),
    /// Hex decoding failed.
    Hex(hex::FromHexError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::InvalidMessage(m) => write!(f, "invalid message: {m}"),
            Self::SigningFailed(m) => write!(f, "signing failed: {m}"),
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
