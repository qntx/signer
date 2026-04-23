//! Error types for the Solana signer.
//!
//! Follows the same pattern as `kobe` chain crates: a transparent
//! [`Core`](SignError::Core) wrapper around [`signer_primitives::SignError`]
//! plus Solana-specific variants (currently only [`InvalidKeypair`](SignError::InvalidKeypair)).

use alloc::string::String;

/// Errors from Solana signing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// Core signer error (key / message / signature / transaction).
    #[error(transparent)]
    Core(#[from] signer_primitives::SignError),

    /// Keypair bytes are malformed (e.g. not a valid 64-byte Base58 keypair).
    #[error("invalid keypair: {0}")]
    InvalidKeypair(String),
}

impl SignError {
    /// Construct an [`InvalidTransaction`](signer_primitives::SignError::InvalidTransaction)
    /// variant.
    #[must_use]
    pub fn invalid_transaction(msg: impl Into<String>) -> Self {
        Self::Core(signer_primitives::SignError::InvalidTransaction(msg.into()))
    }

    /// Construct an [`InvalidSignature`](signer_primitives::SignError::InvalidSignature)
    /// variant.
    #[must_use]
    pub fn invalid_signature(msg: impl Into<String>) -> Self {
        Self::Core(signer_primitives::SignError::InvalidSignature(msg.into()))
    }
}
