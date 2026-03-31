//! Core error type shared across all signer crates.

/// Errors from signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Private key is invalid or out of range.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// Message has wrong length or format.
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    /// The cryptographic signing primitive failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// Signature bytes are malformed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// Transaction bytes are malformed.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
}
