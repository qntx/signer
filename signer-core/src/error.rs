//! Core error type shared across all signer crates.

use std::fmt;

/// Errors from signing operations.
#[derive(Debug)]
pub enum Error {
    /// Private key is invalid or out of range.
    InvalidKey(String),
    /// Message has wrong length or format.
    InvalidMessage(String),
    /// The cryptographic signing primitive failed.
    SigningFailed(String),
    /// Signature bytes are malformed.
    InvalidSignature(String),
    /// Transaction bytes are malformed.
    InvalidTransaction(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::InvalidMessage(m) => write!(f, "invalid message: {m}"),
            Self::SigningFailed(m) => write!(f, "signing failed: {m}"),
            Self::InvalidSignature(m) => write!(f, "invalid signature: {m}"),
            Self::InvalidTransaction(m) => write!(f, "invalid transaction: {m}"),
        }
    }
}

impl std::error::Error for Error {}
