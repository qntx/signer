//! Error types for Bitcoin signer operations.

/// Errors that can occur during Bitcoin signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidKey(String),

    /// Invalid WIF key.
    #[error("invalid WIF: {0}")]
    Wif(#[from] bitcoin::key::FromWifError),

    /// Invalid signature or verification failure.
    #[error("invalid signature: {0}")]
    Signature(String),

    /// PSBT signing error.
    #[error("PSBT signing failed: {0}")]
    Psbt(String),

    /// secp256k1 error.
    #[error("secp256k1: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
}
