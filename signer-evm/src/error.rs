//! Error types for EVM signer operations.

/// Errors that can occur during EVM signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string.
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Signing error from alloy.
    #[error("signing error: {0}")]
    Signing(#[from] alloy_signer::Error),

    /// Kobe bridge error.
    #[cfg(feature = "kobe")]
    #[error("kobe error: {0}")]
    Kobe(String),
}
