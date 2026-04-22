//! Bitcoin transaction signer built on secp256k1 ECDSA.
//!
//! Provides sighash signing, legacy Bitcoin message signing with the
//! `\x18Bitcoin Signed Message:\n` prefix and `CompactSize` length encoding,
//! and `P2PKH` address derivation.
//!
//! **Address derivation is handled by `kobe-btc` — this crate is signing only.**
//!
//! # Examples
//!
//! ```
//! use signer_btc::Signer;
//!
//! let signer = Signer::random();
//! let hash = [0u8; 32];
//! let out = signer.sign_hash(&hash).unwrap();
//! assert_eq!(out.signature.len(), 65); // r(32) + s(32) + recovery_id(1)
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

mod error;

pub use error::SignError;
use ripemd::{Digest as _, Ripemd160};
use sha2::{Digest, Sha256};
use signer_primitives::Secp256k1Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// Bitcoin transaction signer.
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

    /// Bitcoin P2PKH address (legacy, starts with `1`).
    ///
    /// Computed as `Base58Check(0x00 || RIPEMD160(SHA256(compressed_pubkey)))`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "SHA-256 output is always 32 bytes, slicing first 4 is safe"
    )]
    pub fn address(&self) -> String {
        let pubkey = self.inner.compressed_public_key();
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
        self.inner.compressed_public_key()
    }

    /// Sign a 32-byte sighash. Returns 65 bytes: `r(32) || s(32) || recovery_id(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not 32 bytes or the signing primitive fails.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_prehash_recoverable(hash)?)
    }

    /// Sign a Bitcoin transaction sighash preimage (double-SHA256 then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_transaction(&self, sighash_preimage: &[u8]) -> Result<SignOutput, SignError> {
        let hash = Sha256::digest(Sha256::digest(sighash_preimage));
        self.sign_hash(&hash)
    }

    /// Sign a message using Bitcoin message signing convention.
    ///
    /// `hash = SHA256(SHA256(prefix || varint(len) || message))`
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let mut data = Vec::with_capacity(prefix.len() + 9 + message.len());
        data.extend_from_slice(prefix);
        encode_compact_size(&mut data, message.len());
        data.extend_from_slice(message);
        let hash = Sha256::digest(Sha256::digest(&data));
        self.sign_hash(&hash)
    }
}

signer_primitives::impl_sign_delegate!();

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_btc::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(addr: &kobe_btc::DerivedAddress) -> Result<Self, SignError> {
        Self::from_hex(&addr.private_key_hex)
    }
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
