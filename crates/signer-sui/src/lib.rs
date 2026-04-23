//! Sui transaction signer built on [`ed25519_dalek`] and [`blake2`].
//!
//! Sui uses **BLAKE2b-256** for address derivation and intent-based
//! transaction/message signing. The wire signature format is
//! `flag(0x00) || sig(64) || pubkey(32)` (97 bytes).
//!
//! Address derivation is handled by `kobe-sui`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
pub use ed25519_dalek::Signature;
pub use signer_primitives::{self, Sign, SignError, SignExt, SignOutput};
use signer_primitives::{Ed25519Signer, delegate_ed25519_ctors};

/// Ed25519 signature scheme flag used by Sui.
const ED25519_FLAG: u8 = 0x00;

/// Sui transaction intent prefix: `[scope=0, version=0, app_id=0]`.
const TX_INTENT: [u8; 3] = [0x00, 0x00, 0x00];

/// Sui personal message intent prefix: `[scope=3, version=0, app_id=0]`.
const MSG_INTENT: [u8; 3] = [0x03, 0x00, 0x00];

/// Sui transaction signer.
///
/// Newtype over [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
#[derive(Debug)]
pub struct Signer(Ed25519Signer);

impl Signer {
    delegate_ed25519_ctors!();

    /// Sui address: `0x` + hex(BLAKE2b-256(`0x00` || pubkey)).
    #[must_use]
    pub fn address(&self) -> String {
        let mut buf = Vec::with_capacity(33);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(&self.0.public_key_bytes());
        let hash = blake2b_256(&buf);
        format!("0x{}", hex::encode(hash))
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

    /// Sign arbitrary bytes with Ed25519 (raw, no intent prefix).
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
    /// Returns [`SignError::InvalidSignature`] on verification failure.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignError> {
        self.0.verify(message, signature)
    }

    /// Encode a Sui wire signature: `flag(0x00) || sig(64) || pubkey(32)`.
    #[must_use]
    pub fn encode_signature(&self, signature: &Signature) -> Vec<u8> {
        let mut out = Vec::with_capacity(97);
        out.push(ED25519_FLAG);
        out.extend_from_slice(&signature.to_bytes());
        out.extend_from_slice(&self.0.public_key_bytes());
        out
    }
}

impl Sign for Signer {
    type Error = SignError;

    /// Sign a 32-byte digest with Ed25519 (no intent prefix).
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output_with_pubkey(hash))
    }

    /// Sign a personal message with Sui's intent-based BLAKE2b-256 hashing.
    ///
    /// The message is first BCS-serialized (ULEB128 length prefix), then
    /// `BLAKE2b-256(intent[3, 0, 0] || bcs_bytes)` is signed with Ed25519.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let bcs = bcs_serialize_bytes(message);
        let digest = intent_hash(MSG_INTENT, &bcs);
        Ok(self.0.sign_output_with_pubkey(&digest))
    }

    /// Sign a Sui transaction with intent-based BLAKE2b-256 hashing.
    ///
    /// Computes `BLAKE2b-256(intent[0, 0, 0] || tx_bytes)` then signs the
    /// digest with Ed25519.
    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest = intent_hash(TX_INTENT, tx_bytes);
        Ok(self.0.sign_output_with_pubkey(&digest))
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_sui::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_sui::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// BLAKE2b-256 hash.
#[allow(
    clippy::expect_used,
    reason = "32 is always a valid BLAKE2b output size"
)]
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct length");
    out
}

/// Compute intent message hash: `BLAKE2b-256(intent_prefix || data)`.
#[allow(
    clippy::expect_used,
    reason = "32 is always a valid BLAKE2b output size"
)]
fn intent_hash(intent: [u8; 3], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(&intent);
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct length");
    out
}

/// BCS-serialize a byte slice: ULEB128 length prefix followed by the bytes.
fn bcs_serialize_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + data.len());
    let mut len = data.len();
    loop {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "masked with 0x7F, always fits u8"
        )]
        let mut byte = (len & 0x7F) as u8;
        len >>= 7;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests;
