//! Error types for the Bitcoin signer.

use alloc::string::String;

/// Errors from Bitcoin signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
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
}

impl From<signer_primitives::SignError> for SignError {
    fn from(e: signer_primitives::SignError) -> Self {
        use signer_primitives::SignError as Core;
        match e {
            Core::InvalidKey(m) => Self::InvalidKey(m),
            Core::InvalidMessage(m) => Self::InvalidMessage(m),
            Core::SigningFailed(m) => Self::SigningFailed(m),
            Core::InvalidSignature(m) => Self::InvalidSignature(m),
            Core::InvalidTransaction(m) => Self::InvalidTransaction(m),
        }
    }
}
