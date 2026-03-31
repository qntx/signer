//! Error types for the EVM signer.

use std::fmt;

/// Errors from EVM signing operations.
#[derive(Debug)]
pub enum Error {
    /// Private key is invalid.
    InvalidKey(String),
    /// Message format is wrong.
    InvalidMessage(String),
    /// Signing primitive failed.
    SigningFailed(String),
    /// Signature bytes are malformed.
    InvalidSignature(String),
    /// Transaction bytes are malformed.
    InvalidTransaction(String),
    /// Hex decoding failed.
    Hex(hex::FromHexError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::InvalidMessage(m) => write!(f, "invalid message: {m}"),
            Self::SigningFailed(m) => write!(f, "signing failed: {m}"),
            Self::InvalidSignature(m) => write!(f, "invalid signature: {m}"),
            Self::InvalidTransaction(m) => write!(f, "invalid transaction: {m}"),
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

impl From<signer_core::Error> for Error {
    fn from(e: signer_core::Error) -> Self {
        match e {
            signer_core::Error::InvalidKey(m) => Self::InvalidKey(m),
            signer_core::Error::InvalidMessage(m) => Self::InvalidMessage(m),
            signer_core::Error::SigningFailed(m) => Self::SigningFailed(m),
            signer_core::Error::InvalidSignature(m) => Self::InvalidSignature(m),
            signer_core::Error::InvalidTransaction(m) => Self::InvalidTransaction(m),
        }
    }
}
