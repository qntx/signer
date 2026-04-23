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

use sha3::Digest as _;

mod error;

pub use ed25519_dalek::{self, Signature};
pub use error::SignError;
use signer_primitives::Ed25519Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// Ed25519 single-key authentication scheme byte used by Aptos.
const ED25519_SCHEME: u8 = 0x00;

/// Domain separator for `RawTransaction` signing messages.
const RAW_TX_DOMAIN: &[u8] = b"APTOS::RawTransaction";

/// Aptos transaction signer.
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

    /// Aptos account address: `0x` + hex(`SHA3-256(pubkey || 0x00)`).
    #[must_use]
    pub fn address(&self) -> String {
        let mut buf = self.inner.public_key_bytes();
        buf.push(ED25519_SCHEME);
        let hash = sha3_256(&buf);
        format!("0x{}", hex::encode(hash))
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes()
    }

    /// Public key in hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no domain prefix).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.inner.sign_raw(message)
    }

    /// Sign a BCS-serialized `RawTransaction`.
    ///
    /// Computes `SHA3-256("APTOS::RawTransaction")` as the 32-byte prefix,
    /// then signs `prefix || bcs_raw_tx` with Ed25519.
    #[must_use]
    pub fn sign_transaction_bcs(&self, bcs_raw_tx: &[u8]) -> Signature {
        let signing_msg = tx_signing_message(bcs_raw_tx);
        self.inner.sign_raw(&signing_msg)
    }

    /// Verify a 64-byte Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] if the bytes are not a valid
    /// 64-byte signature or fail verification.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignError> {
        Ok(self.inner.verify(message, signature)?)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_output_with_pubkey(hash))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_output_with_pubkey(message))
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let signing_msg = tx_signing_message(tx_bytes);
        Ok(self.inner.sign_output_with_pubkey(&signing_msg))
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
