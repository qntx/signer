//! Error types for Bitcoin signer operations.

/// Errors that can occur during Bitcoin signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string.
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid WIF (Wallet Import Format) string.
    #[error("invalid WIF: {0}")]
    InvalidWif(String),

    /// PSBT signing error.
    #[error("PSBT signing error: {0}")]
    PsbtSign(String),

    /// secp256k1 error.
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    /// Bitcoin key error.
    #[error("key error: {0}")]
    Key(#[from] bitcoin::key::FromWifError),

    /// Kobe bridge error.
    #[cfg(feature = "kobe")]
    #[error("kobe error: {0}")]
    Kobe(String),
}
