//! Error types for Solana signer operations.

/// Errors that can occur during Solana signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string.
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid keypair base58.
    #[error("invalid keypair base58: {0}")]
    InvalidKeypairBase58(String),

    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(#[from] ed25519_dalek::SignatureError),

    /// Kobe bridge error.
    #[cfg(feature = "kobe")]
    #[error("kobe error: {0}")]
    Kobe(String),
}
