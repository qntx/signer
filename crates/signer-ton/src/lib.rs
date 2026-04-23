//! TON transaction signer built on Ed25519.
//!
//! TON wallet addresses depend on the deployed contract code and workchain
//! ID, so [`Signer::address`] returns the hex-encoded public key instead.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

mod error;

pub use ed25519_dalek::{self, Signature};
pub use error::SignError;
use signer_primitives::Ed25519Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// TON transaction signer.
///
/// Wraps an [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
pub struct Signer {
    inner: Ed25519Signer,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Signer {
    /// Create from raw 32-byte secret key bytes.
    ///
    /// # Errors
    ///
    /// Reserved for future compatibility; currently never fails.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Ok(Self {
            inner: Ed25519Signer::from_bytes(bytes)?,
        })
    }

    /// Create from a hex-encoded 32-byte private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or not 32 bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        Ok(Self {
            inner: Ed25519Signer::from_hex(hex_str)?,
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
            inner: Ed25519Signer::random(),
        }
    }

    /// TON signer identity (hex-encoded Ed25519 public key).
    ///
    /// TON wallet addresses depend on the deployed contract code and
    /// workchain ID, so a full address cannot be derived from the key alone.
    /// This returns the 64-character hex public key used to identify the signer.
    #[must_use]
    pub fn address(&self) -> String {
        self.public_key_hex()
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes()
    }

    /// Public key in hex (64 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no hashing or prefixing).
    ///
    /// Returns the native [`ed25519_dalek::Signature`]. For the unified
    /// [`SignOutput::Ed25519`] wire form, use [`Self::sign_message`].
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.inner.sign_raw(message)
    }

    /// Sign a 32-byte digest with Ed25519.
    ///
    /// # Errors
    ///
    /// Never fails; the [`Result`] is kept for trait symmetry.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_output(hash))
    }

    /// Sign an arbitrary message with raw Ed25519 (TON's native convention).
    ///
    /// # Errors
    ///
    /// Never fails; the [`Result`] is kept for trait symmetry.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_output(message))
    }

    /// Sign transaction bytes with raw Ed25519.
    ///
    /// # Errors
    ///
    /// Never fails; the [`Result`] is kept for trait symmetry.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_output(tx_bytes))
    }

    /// Verify a 64-byte Ed25519 signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on verification failure.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignError> {
        Ok(self.inner.verify(message, signature)?)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Self::sign_hash(self, hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Self::sign_message(self, message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        Self::sign_transaction(self, tx_bytes)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_ton::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_ton::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

#[cfg(test)]
mod tests;
