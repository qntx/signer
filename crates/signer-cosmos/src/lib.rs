//! Cosmos transaction signer built on secp256k1 ECDSA.
//!
//! Provides signing for Cosmos SDK transactions (SHA-256 + ECDSA)
//! and bech32 `cosmos1…` address derivation.
//!
//! # Examples
//!
//! ```
//! use signer_cosmos::Signer;
//!
//! let signer = Signer::random();
//! let addr = signer.address();
//! assert!(addr.starts_with("cosmos1"));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

mod error;

use bech32::{Bech32, Hrp};
pub use error::SignError;
use ripemd::{Digest as _, Ripemd160};
use sha2::{Digest, Sha256};
use signer_primitives::Secp256k1Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// Cosmos transaction signer.
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

    /// Cosmos address with `cosmos1` prefix.
    ///
    /// Computed as `bech32(hrp="cosmos", RIPEMD160(SHA256(compressed_pubkey)))`.
    ///
    /// # Panics
    ///
    /// Panics if bech32 encoding fails (should never happen with valid input).
    #[must_use]
    pub fn address(&self) -> String {
        let pubkey = self.inner.compressed_public_key();
        let sha = Sha256::digest(&pubkey);
        let hash160 = Ripemd160::digest(sha);
        let hrp = Hrp::parse_unchecked("cosmos");
        #[allow(
            clippy::expect_used,
            reason = "HRP and hash160 are always valid bech32 inputs"
        )]
        bech32::encode::<Bech32>(hrp, &hash160).expect("valid bech32")
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.compressed_public_key())
    }

    /// Verify an ECDSA signature against a 32-byte pre-hashed digest.
    ///
    /// Accepts 64-byte (`r || s`) or 65-byte (`r || s || v`) input;
    /// the `v` byte is ignored for verification.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on malformed input or
    /// failed verification.
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8]) -> Result<(), SignError> {
        Ok(self.inner.verify_prehash(hash, signature)?)
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

    /// Sign a Cosmos transaction (SHA-256 hash then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(tx_bytes).into();
        self.sign_hash(&digest)
    }

    /// Sign an arbitrary message (SHA-256 hash then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.sign_hash(&digest)
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
    /// Create from a [`kobe_cosmos::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_cosmos::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

#[cfg(test)]
mod tests;
