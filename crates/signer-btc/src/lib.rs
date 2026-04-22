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
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use indexing for clarity"
)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    use super::*;

    const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn test_signer() -> Signer {
        Signer::from_hex(TEST_KEY).unwrap()
    }

    fn verify_secp256k1(s: &Signer, hash: &[u8], out: &SignOutput) {
        let r: [u8; 32] = out.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = out.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s_bytes).unwrap();
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&s.public_key_bytes()).unwrap();
        vk.verify_prehash(hash, &sig)
            .expect("signature must verify");
    }

    #[test]
    fn sign_hash_verify() {
        let s = test_signer();
        let hash = Sha256::digest(b"test message");
        let out = s.sign_hash(&hash).unwrap();
        assert_eq!(out.signature.len(), 65);
        assert!(out.recovery_id.is_some());
        verify_secp256k1(&s, &hash, &out);
    }

    #[test]
    fn sign_transaction_double_sha256_verify() {
        let s = test_signer();
        let tx = b"bitcoin tx bytes";
        let out = s.sign_transaction(tx).unwrap();
        let expected = Sha256::digest(Sha256::digest(tx));
        verify_secp256k1(&s, &expected, &out);
    }

    #[test]
    fn compressed_public_key_33_bytes() {
        let pk = test_signer().public_key_bytes();
        assert_eq!(pk.len(), 33);
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes).unwrap();
        assert_eq!(s.public_key_bytes(), test_signer().public_key_bytes());
    }

    #[test]
    fn sign_message_short_verify() {
        let s = test_signer();
        let msg = b"Hello Bitcoin!";
        let out = s.sign_message(msg).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "test message is short, len fits in u8"
        )]
        data.push(msg.len() as u8);
        data.extend_from_slice(msg);
        let expected = Sha256::digest(Sha256::digest(&data));
        verify_secp256k1(&s, &expected, &out);
    }

    #[test]
    fn sign_message_long_varint_verify() {
        let s = test_signer();
        let msg = vec![0x42u8; 300];
        let out = s.sign_message(&msg).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        data.push(0xFD);
        data.extend_from_slice(&300u16.to_le_bytes());
        data.extend_from_slice(&msg);
        let expected = Sha256::digest(Sha256::digest(&data));
        verify_secp256k1(&s, &expected, &out);
    }

    #[test]
    fn sign_message_varint_boundary_253() {
        let s = test_signer();
        let msg = vec![0xAA; 253];
        let out = s.sign_message(&msg).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
        data.push(0xFD);
        data.extend_from_slice(&253u16.to_le_bytes());
        data.extend_from_slice(&msg);
        let expected = Sha256::digest(Sha256::digest(&data));
        verify_secp256k1(&s, &expected, &out);
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let out1 = s.sign_transaction(b"same data").unwrap();
        let out2 = s.sign_transaction(b"same data").unwrap();
        assert_eq!(out1.signature, out2.signature);
    }

    #[test]
    fn rejects_non_32_byte_hash() {
        assert!(test_signer().sign_hash(b"short").is_err());
        assert!(test_signer().sign_hash(&[0u8; 33]).is_err());
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(Signer::from_hex("not-hex").is_err());
        assert!(Signer::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("4c0883"));
    }
}
