//! Error types for the Sui signer.

use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

/// Errors from Sui signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Private key is invalid.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerifyFailed(ed25519_dalek::SignatureError),
    /// Hex decoding failed.
    #[error("hex error: {0}")]
    Hex(hex::FromHexError),
}

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

impl From<signer_core::Error> for Error {
    fn from(e: signer_core::Error) -> Self {
        Self::InvalidKey(e.to_string())
    }
}
