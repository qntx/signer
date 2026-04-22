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
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: Ed25519Signer::from_bytes(bytes),
        }
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
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.inner.sign_raw(message)
    }

    /// Verify an Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignError> {
        self.inner.verify(message, signature)?;
        Ok(())
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        let sig = self.inner.sign_raw(hash);
        Ok(SignOutput::ed25519(sig.to_bytes().to_vec()))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(tx_bytes)
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
        Self::from_hex(&account.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 Test Vector 1
    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_PUBKEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn test_signer() -> Signer {
        Signer::from_hex(TEST_KEY).unwrap()
    }

    #[test]
    fn rfc8032_pubkey() {
        assert_eq!(test_signer().public_key_hex(), TEST_PUBKEY);
    }

    #[test]
    fn from_bytes_matches_from_hex() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes);
        assert_eq!(s.public_key_bytes(), test_signer().public_key_bytes());
    }

    #[test]
    fn sign_and_verify() {
        let s = test_signer();
        let msg = b"hello TON";
        let sig = s.sign_raw(msg);
        s.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn sign_wrong_message_fails() {
        let s = test_signer();
        let sig = s.sign_raw(b"correct");
        assert!(s.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn sign_trait_verify() {
        let s = test_signer();
        let out = Sign::sign_message(&s, b"test").unwrap();
        assert_eq!(out.signature.len(), 64);
        assert!(out.recovery_id.is_none());
        let sig = Signature::from_slice(&out.signature).unwrap();
        s.verify(b"test", &sig)
            .expect("trait signature must verify");
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let s1 = s.sign_raw(b"deterministic");
        let s2 = s.sign_raw(b"deterministic");
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9d61b1"));
    }
}
