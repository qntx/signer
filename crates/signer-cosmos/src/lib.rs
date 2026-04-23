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

use bech32::{Bech32, Hrp};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
pub use signer_primitives::{self, Sign, SignError, SignExt, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// Cosmos transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Cosmos address with `cosmos1` prefix.
    ///
    /// Computed as `bech32(hrp="cosmos", RIPEMD160(SHA256(compressed_pubkey)))`.
    ///
    /// # Panics
    ///
    /// Panics if bech32 encoding fails (should never happen with valid input).
    #[must_use]
    pub fn address(&self) -> String {
        let pubkey = self.0.compressed_public_key();
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
        self.0.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.compressed_public_key())
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
        self.0.verify_prehash(hash, signature)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.0.sign_prehash_recoverable(&digest)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(tx_bytes).into();
        self.0.sign_prehash_recoverable(&digest)
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
