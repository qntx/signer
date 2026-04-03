//! Error types for the Bitcoin signer.

use alloc::string::String;

/// Errors from Bitcoin signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Private key is invalid.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// Message format is wrong.
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    /// Signing primitive failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// Signature bytes are malformed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// Transaction bytes are malformed.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    /// Hex decoding failed.
    #[error("hex error: {0}")]
    Hex(hex::FromHexError),
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

impl From<signer_primitives::Error> for Error {
    fn from(e: signer_primitives::Error) -> Self {
        match e {
            signer_primitives::Error::InvalidKey(m) => Self::InvalidKey(m),
            signer_primitives::Error::InvalidMessage(m) => Self::InvalidMessage(m),
            signer_primitives::Error::SigningFailed(m) => Self::SigningFailed(m),
            signer_primitives::Error::InvalidSignature(m) => Self::InvalidSignature(m),
            signer_primitives::Error::InvalidTransaction(m) => Self::InvalidTransaction(m),
        }
    }
}
