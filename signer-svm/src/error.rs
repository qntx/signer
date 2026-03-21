//! Error types for Solana signer operations.

/// Errors that can occur during Solana signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidKey(String),

    /// Invalid keypair base58.
    #[error("invalid keypair base58: {0}")]
    InvalidKeypair(String),

    /// Ed25519 signature error.
    #[error("ed25519: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
}
