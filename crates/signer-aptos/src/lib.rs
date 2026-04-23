//! Aptos transaction signer built on [`ed25519_dalek`] and [`sha3`].
//!
//! Aptos uses **Ed25519** (`PureEdDSA`, RFC 8032) for signing and **SHA3-256**
//! for address derivation and transaction signing message domain separation.
//!
//! - **Address**: `SHA3-256(pubkey || 0x00)`, displayed as `0x` + hex (64 chars).
//! - **Transaction signing**: `Ed25519::sign(SHA3-256("APTOS::RawTransaction") || bcs_bytes)`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

pub use ed25519_dalek::Signature;
use sha3::Digest as _;
pub use signer_primitives::{self, Sign, SignError, SignExt, SignOutput};
use signer_primitives::{Ed25519Signer, delegate_ed25519_ctors};

/// Ed25519 single-key authentication scheme byte used by Aptos.
const ED25519_SCHEME: u8 = 0x00;

/// Domain separator for `RawTransaction` signing messages.
const RAW_TX_DOMAIN: &[u8] = b"APTOS::RawTransaction";

/// Aptos transaction signer.
///
/// Newtype over [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
#[derive(Debug)]
pub struct Signer(Ed25519Signer);

impl Signer {
    delegate_ed25519_ctors!();

    /// Aptos account address: `0x` + hex(`SHA3-256(pubkey || 0x00)`).
    #[must_use]
    pub fn address(&self) -> String {
        let mut buf = self.0.public_key_bytes();
        buf.push(ED25519_SCHEME);
        let hash = sha3_256(&buf);
        format!("0x{}", hex::encode(hash))
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key_bytes()
    }

    /// Public key in hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.0.public_key_hex()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no domain prefix).
    ///
    /// Returns the native [`Signature`]. For the unified
    /// [`SignOutput::Ed25519WithPubkey`] wire form, use [`Sign::sign_message`].
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.0.sign_raw(message)
    }

    /// Verify a 64-byte Ed25519 signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] if the bytes are not a valid
    /// 64-byte signature or fail verification.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignError> {
        self.0.verify(message, signature)
    }
}

impl Sign for Signer {
    type Error = SignError;

    /// Sign a 32-byte digest with Ed25519 (no Aptos domain prefix).
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output_with_pubkey(hash))
    }

    /// Sign an arbitrary message with raw Ed25519 (no Aptos domain prefix).
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output_with_pubkey(message))
    }

    /// Sign a BCS-serialized `RawTransaction`.
    ///
    /// Computes `SHA3-256("APTOS::RawTransaction")` as the 32-byte prefix,
    /// then signs `prefix || bcs_raw_tx` with Ed25519.
    fn sign_transaction(&self, bcs_raw_tx: &[u8]) -> Result<SignOutput, SignError> {
        let signing_msg = tx_signing_message(bcs_raw_tx);
        Ok(self.0.sign_output_with_pubkey(&signing_msg))
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_aptos::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the derived bytes are malformed.
    pub fn from_derived(account: &kobe_aptos::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// Compute SHA3-256.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    sha3::Sha3_256::digest(data).into()
}

/// Build the Aptos transaction signing message.
///
/// Returns `SHA3-256("APTOS::RawTransaction") || bcs_raw_tx`.
fn tx_signing_message(bcs_raw_tx: &[u8]) -> Vec<u8> {
    let prefix = sha3_256(RAW_TX_DOMAIN);
    let mut msg = Vec::with_capacity(32 + bcs_raw_tx.len());
    msg.extend_from_slice(&prefix);
    msg.extend_from_slice(bcs_raw_tx);
    msg
}

#[cfg(test)]
mod tests;
