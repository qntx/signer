//! TON transaction signer built on Ed25519.
//!
//! TON wallet addresses depend on the deployed contract code and workchain
//! ID, so [`Signer::address`] returns the hex-encoded public key instead.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

pub use ed25519_dalek::Signature;
pub use signer_primitives::{
    self, Sign, SignError, SignExt, SignMessage, SignMessageExt, SignOutput,
};
use signer_primitives::{Ed25519Signer, delegate_ed25519_ctors};

/// TON transaction signer.
///
/// Newtype over [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
#[derive(Debug)]
pub struct Signer(Ed25519Signer);

impl Signer {
    delegate_ed25519_ctors!();

    /// TON signer identity (hex-encoded Ed25519 public key).
    ///
    /// TON wallet addresses depend on the deployed contract code and
    /// workchain ID, so a full address cannot be derived from the key alone.
    /// This returns the 64-character hex public key used to identify the
    /// signer.
    #[must_use]
    pub fn address(&self) -> String {
        self.public_key_hex()
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key_bytes()
    }

    /// Public key in hex (64 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.0.public_key_hex()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no hashing or prefixing).
    ///
    /// Returns the native [`Signature`]. For the unified
    /// [`SignOutput::Ed25519`] wire form, use [`Sign::sign_message`].
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.0.sign_raw(message)
    }

    /// Verify a 64-byte Ed25519 signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on verification failure.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignError> {
        self.0.verify(message, signature)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(hash))
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(tx_bytes))
    }
}

impl SignMessage for Signer {
    /// Raw Ed25519 signature over the message bytes (no prefix or hashing).
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(message))
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
