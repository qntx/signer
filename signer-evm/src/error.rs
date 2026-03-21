//! Error types for EVM signer operations.

/// Errors that can occur during EVM signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidKey(String),

    /// Signing error from alloy.
    #[error("signing: {0}")]
    Signing(#[from] alloy_signer::Error),
}
