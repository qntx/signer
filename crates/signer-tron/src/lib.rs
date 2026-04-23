//! TRON transaction signer built on secp256k1 ECDSA and Keccak-256.
//!
//! Derives `T…` `Base58Check` addresses from the uncompressed public key
//! (`0x41` prefix + `Keccak256(pk)[12..]`) and signs messages with the
//! EVM-style `\x19TRON Signed Message:\n` prefix.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

mod error;

pub use error::SignError;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use signer_primitives::Secp256k1Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// TRON transaction signer.
///
/// Wraps a [`Secp256k1Signer`]. The inner key is zeroized on drop.
pub struct Signer {
    inner: Secp256k1Signer,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Signer {
    /// Create from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Ok(Self {
            inner: Secp256k1Signer::from_bytes(bytes)?,
        })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or the key is out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        Ok(Self {
            inner: Secp256k1Signer::from_hex(hex_str)?,
        })
    }

    /// Generate a random signer.
    ///
    /// # Panics
    ///
    /// Panics if the OS random number generator fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn random() -> Self {
        Self {
            inner: Secp256k1Signer::random(),
        }
    }

    /// TRON address (`Base58Check` with `0x41` prefix, starts with `T`).
    ///
    /// Computed as `Base58Check(0x41 || Keccak256(uncompressed_pubkey[1..])[12..])`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "crypto outputs have fixed sizes: uncompressed pubkey=65B, Keccak256=32B, SHA-256=32B"
    )]
    pub fn address(&self) -> String {
        let uncompressed = self.inner.uncompressed_public_key();
        let hash = Keccak256::digest(&uncompressed[1..]);
        let mut payload = Vec::with_capacity(25);
        payload.push(0x41);
        payload.extend_from_slice(&hash[12..]);
        let checksum = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(&payload).into_string()
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.compressed_public_key()
    }

    /// Sign a 32-byte digest. Returns a [`SignOutput::Ecdsa`] with a
    /// `0 | 1` recovery id.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_prehash_recoverable(hash)?)
    }

    /// Sign a TRON transaction (SHA-256 of the raw transaction bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(tx_bytes).into();
        self.sign_hash(&digest)
    }

    /// Sign a message with TRON's message-signing convention.
    ///
    /// `digest = keccak256("\x19TRON Signed Message:\n" || len || message)`.
    /// The returned `v` byte follows EVM convention (`27 | 28`).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let digest: [u8; 32] = Keccak256::digest(&data).into();
        let out = self.sign_hash(&digest)?;
        Ok(bump_v_by_27(out))
    }
}

/// Bump the `v` byte of an [`SignOutput::Ecdsa`] by 27 (TRON message encoding).
fn bump_v_by_27(out: SignOutput) -> SignOutput {
    match out {
        SignOutput::Ecdsa { signature, v } => SignOutput::Ecdsa {
            signature,
            v: v.wrapping_add(27),
        },
        other => other,
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, Self::Error> {
        Self::sign_hash(self, hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error> {
        Self::sign_message(self, message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Self::Error> {
        Self::sign_transaction(self, tx_bytes)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_tron::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_tron::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

#[cfg(test)]
mod tests;
