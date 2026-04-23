//! TRON transaction signer built on secp256k1 ECDSA and Keccak-256.
//!
//! Derives `T…` `Base58Check` addresses from the uncompressed public key
//! (`0x41` prefix + `Keccak256(pk)[12..]`) and signs messages with the
//! EVM-style `\x19TRON Signed Message:\n` prefix.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use sha2::Sha256;
use sha3::{Digest, Keccak256};
pub use signer_primitives::{self, Sign, SignError, SignExt, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// TRON transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// TRON address (`Base58Check` with `0x41` prefix, starts with `T`).
    ///
    /// Computed as `Base58Check(0x41 || Keccak256(uncompressed_pubkey[1..])[12..])`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "crypto outputs have fixed sizes: uncompressed pubkey=65B, Keccak256=32B, SHA-256=32B"
    )]
    pub fn address(&self) -> String {
        let uncompressed = self.0.uncompressed_public_key();
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

    /// Sign a message with TRON's message-signing convention.
    ///
    /// `digest = keccak256("\x19TRON Signed Message:\n" || len || message)`.
    /// The returned `v` byte follows EVM convention (`27 | 28`).
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let digest: [u8; 32] = Keccak256::digest(&data).into();
        let out = self.0.sign_prehash_recoverable(&digest)?;
        Ok(bump_v_by_27(out))
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(tx_bytes).into();
        self.0.sign_prehash_recoverable(&digest)
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

#[cfg(test)]
mod tests;
