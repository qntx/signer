//! Crate-level error types.

use alloc::string::String;
use core::fmt;

/// Errors from signing operations.
#[derive(Debug)]
pub enum SignerError {
    /// Private key is malformed or out of range.
    InvalidKey(String),
    /// Message or hash has wrong length / format.
    InvalidMessage(String),
    /// The cryptographic signing primitive failed.
    SigningFailed(String),
    /// Could not derive an on-chain address from the key.
    AddressFailed(String),
    /// Transaction bytes are malformed.
    InvalidTransaction(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::InvalidMessage(m) => write!(f, "invalid message: {m}"),
            Self::SigningFailed(m) => write!(f, "signing failed: {m}"),
            Self::AddressFailed(m) => write!(f, "address derivation failed: {m}"),
            Self::InvalidTransaction(m) => write!(f, "invalid transaction: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignerError {}

/// Errors from HD key derivation.
#[derive(Debug)]
pub enum HdError {
    /// Derivation path syntax is wrong.
    InvalidPath(String),
    /// Key derivation computation failed.
    DerivationFailed(String),
    /// Ed25519 SLIP-10 only supports hardened indices.
    Ed25519NonHardened,
}

impl fmt::Display for HdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(m) => write!(f, "invalid derivation path: {m}"),
            Self::DerivationFailed(m) => write!(f, "derivation failed: {m}"),
            Self::Ed25519NonHardened => f.write_str("ed25519 requires hardened-only derivation"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HdError {}

/// Errors from mnemonic operations.
#[derive(Debug)]
pub enum MnemonicError {
    /// Phrase contains invalid words or bad checksum.
    InvalidPhrase(String),
    /// Random generation failed.
    GenerationFailed(String),
}

impl fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPhrase(m) => write!(f, "invalid mnemonic: {m}"),
            Self::GenerationFailed(m) => write!(f, "mnemonic generation failed: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MnemonicError {}

/// Errors from envelope encryption / decryption.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum CryptoError {
    /// Encryption failed.
    EncryptionFailed(String),
    /// Decryption failed (wrong passphrase or corrupted data).
    DecryptionFailed(String),
    /// KDF or cipher parameters are invalid.
    InvalidParams(String),
}

#[cfg(feature = "std")]
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed(m) => write!(f, "encryption failed: {m}"),
            Self::DecryptionFailed(m) => write!(f, "decryption failed: {m}"),
            Self::InvalidParams(m) => write!(f, "invalid params: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
