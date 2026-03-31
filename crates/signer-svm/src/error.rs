//! Error types for the Solana signer.

use std::fmt;

/// Errors from Solana signing operations.
#[derive(Debug)]
pub enum Error {
    /// Private key is invalid.
    InvalidKey(String),
    /// Keypair bytes are malformed.
    InvalidKeypair(String),
    /// Transaction bytes are malformed.
    InvalidTransaction(String),
    /// Signature verification failed.
    VerifyFailed(ed25519_dalek::SignatureError),
    /// Hex decoding failed.
    Hex(hex::FromHexError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::InvalidKeypair(m) => write!(f, "invalid keypair: {m}"),
            Self::InvalidTransaction(m) => write!(f, "invalid transaction: {m}"),
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

impl From<signer_core::Error> for Error {
    fn from(e: signer_core::Error) -> Self {
        Self::InvalidKey(e.to_string())
    }
}
