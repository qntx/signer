//! Filecoin transaction signer built on secp256k1 ECDSA and `BLAKE2b`.
//!
//! Uses the `f1` (protocol-1) address scheme derived from the uncompressed
//! public key, and signs transactions with `BLAKE2b-256` + ECDSA.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

mod error;

use blake2::digest::consts::{U4, U20, U32};
use blake2::{Blake2b, Digest};
pub use error::SignError;
use signer_primitives::Secp256k1Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

type Blake2b256 = Blake2b<U32>;
type Blake2b160 = Blake2b<U20>;
type Blake2b4 = Blake2b<U4>;

/// Filecoin transaction signer.
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

    /// Filecoin protocol-1 (secp256k1) address (`f1…`).
    ///
    /// Computed as `"f1" + base32_lower(BLAKE2b-160(uncompressed_pubkey) || BLAKE2b-4(0x01 || payload))`.
    #[must_use]
    pub fn address(&self) -> String {
        let uncompressed = self.inner.uncompressed_public_key();
        let payload = Blake2b160::digest(&uncompressed);
        let mut checksum_input = Vec::with_capacity(1 + payload.len());
        checksum_input.push(0x01); // protocol 1
        checksum_input.extend_from_slice(&payload);
        let checksum = Blake2b4::digest(&checksum_input);
        let mut addr_bytes = Vec::with_capacity(payload.len() + checksum.len());
        addr_bytes.extend_from_slice(&payload);
        addr_bytes.extend_from_slice(&checksum);
        let encoded = base32_lower_encode(&addr_bytes);
        format!("f1{encoded}")
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.compressed_public_key()
    }

    /// Sign a 32-byte hash. Returns 65 bytes: `r(32) || s(32) || recovery_id(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not 32 bytes or signing fails.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_prehash_recoverable(hash)?)
    }

    /// Sign a Filecoin transaction (Blake2b-256 hash then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let hash = Blake2b256::digest(tx_bytes);
        self.sign_hash(&hash)
    }

    /// Sign a message (Blake2b-256 hash then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let hash = Blake2b256::digest(message);
        self.sign_hash(&hash)
    }
}

signer_primitives::impl_sign_delegate!();

/// RFC 4648 base32 lowercase encoding without padding.
#[allow(
    clippy::indexing_slicing,
    reason = "idx is masked with 0x1F, always < 32 = ALPHABET.len()"
)]
fn base32_lower_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "masked with 0x1F, always <= 31"
            )]
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "masked with 0x1F, always <= 31"
        )]
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_fil::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_fil::DerivedAccount) -> Result<Self, SignError> {
        let bytes = account
            .private_key_bytes()
            .map_err(|e| SignError::InvalidKey(alloc::format!("{e}")))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests;
