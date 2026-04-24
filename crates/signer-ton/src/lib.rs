//! TON transaction signer built on Ed25519.
//!
//! TON wallet addresses depend on the deployed contract code and workchain
//! ID, so this crate exposes [`Signer::identity`] (hex-encoded Ed25519
//! public key) instead of a full address. Full wallet-address derivation
//! with contract configuration is handled by `kobe-ton`.
//!
//! # Off-chain message framing
//!
//! TON has no single canonical "personal signed message" envelope.
//! Different use cases pick different preimages:
//!
//! - **TON Connect `ton_proof`**: `Ed25519(SHA-256(0xffff ||
//!   utf8("ton-connect") || SHA-256(domain_msg)))`.
//! - **`ton-proof-item-v2/`**: domain-tagged preimage for authenticated
//!   sessions.
//! - **Wallet contract messages**: `Ed25519(cell_hash)` where
//!   `cell_hash` is the BOC hash of the outgoing message.
//!
//! Because none of these is universal, [`SignMessage::sign_message`] and
//! [`Signer::sign_transaction`] on this crate perform **raw Ed25519** over
//! the input bytes verbatim (no hashing, no prefixing). Callers are
//! expected to construct the appropriate preimage for their scenario
//! and hand it to the signer as-is. This is analogous to Nostr's
//! `sign_message` — the primitive is intentionally exposed at the
//! lowest level.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

pub use ed25519_dalek::Signature;
pub use signer_primitives::{self, Sign, SignError, SignMessage, SignOutput};
use signer_primitives::{Ed25519Signer, delegate_ed25519_ctors};

/// TON transaction signer.
///
/// Newtype over [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
#[derive(Debug)]
pub struct Signer(Ed25519Signer);

impl Signer {
    delegate_ed25519_ctors!();

    /// TON signer identity (hex-encoded Ed25519 public key, 64 chars).
    ///
    /// TON wallet addresses depend on the deployed contract code and
    /// workchain ID, so a receivable address cannot be derived from the key
    /// alone. This returns the signer's **identity** (public key hex) used
    /// to uniquely name the signing entity. For full wallet-address
    /// derivation (V3R2 / V4R2 / V5R1 contract types) use `kobe-ton`.
    #[must_use]
    pub fn identity(&self) -> String {
        self.0.public_key_hex()
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
    /// [`SignOutput::Ed25519`] wire form, use [`SignMessage::sign_message`].
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

    /// Sign arbitrary TON transaction preimage bytes with raw Ed25519.
    ///
    /// TON has no single canonical transaction format; callers construct
    /// the preimage (e.g. `cell_hash` of an outgoing BOC message, or the
    /// TON Connect `ton_proof` domain-tagged bytes) and hand it to this
    /// method verbatim. Returns [`SignOutput::Ed25519`].
    ///
    /// # Errors
    ///
    /// Infallible in practice; the [`Result`] is reserved for future
    /// compatibility.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(tx_bytes))
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(hash))
    }
}

impl SignMessage for Signer {
    /// **Framing**: raw Ed25519 over the message bytes — no prefix, no
    /// hashing. TON has no single canonical personal-message envelope (TON
    /// Connect `ton_proof` and wallet-contract messages all pick different
    /// preimages), so the primitive is intentionally exposed at the lowest
    /// level.
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
