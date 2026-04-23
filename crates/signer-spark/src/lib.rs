//! Spark (Bitcoin L2) transaction signer built on secp256k1 ECDSA.
//!
//! Shares Bitcoin's cryptographic primitives (double-SHA256, P2PKH address
//! derivation) and [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)
//! message signing, but is a distinct chain. Address derivation is handled
//! by `kobe-spark`.
//!
//! # Message signing
//!
//! [`SignMessage::sign_message`] signs with the BIP-137 header byte for a
//! **compressed P2PKH** address (`v = 31 | 32`), matching Bitcoin Core's
//! `signmessage` on-wire format so the resulting signature round-trips
//! through any BIP-137 verifier.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
pub use signer_primitives::{
    self, Sign, SignError, SignExt, SignMessage, SignMessageExt, SignOutput,
};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// BIP-137 header offset for a compressed P2PKH address (`27 + 4`).
const BIP137_COMPRESSED_P2PKH_OFFSET: u8 = 31;

/// Spark transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Spark P2PKH address (legacy, starts with `1`).
    ///
    /// Same derivation as Bitcoin: `Base58Check(0x00 || RIPEMD160(SHA256(compressed_pubkey)))`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "SHA-256 output is always 32 bytes, slicing first 4 is safe"
    )]
    pub fn address(&self) -> String {
        let pubkey = self.0.compressed_public_key();
        let sha = Sha256::digest(&pubkey);
        let hash160 = Ripemd160::digest(sha);
        let mut payload = Vec::with_capacity(25);
        payload.push(0x00);
        payload.extend_from_slice(&hash160);
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
        self.0.verify_prehash_any(hash, signature)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(hash)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(Sha256::digest(tx_bytes)).into();
        self.0.sign_prehash_recoverable(&digest)
    }
}

impl SignMessage for Signer {
    /// BIP-137 message signing for a compressed P2PKH address.
    ///
    /// Digest: `double_SHA256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message)`.
    /// Returns a 65-byte [`SignOutput::Ecdsa`] with `v = 31 | 32`, directly
    /// consumable by any BIP-137 verifier.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let digest = bitcoin_message_digest(message);
        let out = self.0.sign_prehash_recoverable(&digest)?;
        Ok(match out {
            SignOutput::Ecdsa { signature, v } => SignOutput::Ecdsa {
                signature,
                v: BIP137_COMPRESSED_P2PKH_OFFSET.wrapping_add(v),
            },
            other => other,
        })
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_spark::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_spark::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// Compute `double_SHA256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message)`.
fn bitcoin_message_digest(message: &[u8]) -> [u8; 32] {
    const PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";
    let mut data = Vec::with_capacity(PREFIX.len() + 9 + message.len());
    data.extend_from_slice(PREFIX);
    encode_compact_size(&mut data, message.len());
    data.extend_from_slice(message);
    Sha256::digest(Sha256::digest(&data)).into()
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are range-checked before each cast"
)]
fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

#[cfg(test)]
mod tests;
