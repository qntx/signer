//! Filecoin transaction signer built on [`k256`] and [`blake2`].
//!
//! Provides secp256k1 ECDSA signing with Blake2b-256 hashing for Filecoin.
//! Address derivation is handled by [`kobe-fil`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};

mod error;

use blake2::digest::consts::{U4, U20, U32};
use blake2::{Blake2b, Digest};
pub use error::SignError;
use k256::ecdsa::SigningKey;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};
use zeroize::ZeroizeOnDrop;

type Blake2b256 = Blake2b<U32>;
type Blake2b160 = Blake2b<U20>;
type Blake2b4 = Blake2b<U4>;

/// Filecoin transaction signer.
///
/// Wraps a secp256k1 signing key. The inner key is zeroized on drop.
pub struct Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ZeroizeOnDrop for Signer {}

impl Signer {
    /// Create from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        let key =
            SigningKey::from_slice(bytes).map_err(|e| SignError::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or the key is out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            SignError::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Self::from_bytes(&bytes)
    }

    /// Generate a random signer.
    ///
    /// # Panics
    ///
    /// Panics if the OS random number generator fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "getrandom failure is unrecoverable; secp256k1 rejection has p ≈ 2⁻¹²⁸"
    )]
    pub fn random() -> Self {
        use zeroize::Zeroize as _;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let key = SigningKey::from_slice(&bytes).expect("invalid random key");
        bytes.zeroize();
        Self { key }
    }

    /// Filecoin protocol-1 (secp256k1) address (`f1...`).
    ///
    /// Computed as `"f1" + base32_lower(BLAKE2b-160(pubkey) || BLAKE2b-4(0x01 || payload))`.
    #[must_use]
    pub fn address(&self) -> String {
        let vk = self.key.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let payload = Blake2b160::digest(uncompressed.as_bytes());
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
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Expose the inner [`SigningKey`].
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Sign a 32-byte hash. Returns 65 bytes: `r(32) || s(32) || recovery_id(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not 32 bytes or signing fails.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        if hash.len() != 32 {
            return Err(SignError::InvalidMessage(format!(
                "expected 32-byte hash, got {}",
                hash.len()
            )));
        }
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(hash)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(rid.to_byte());
        Ok(SignOutput::secp256k1(out, rid.to_byte()))
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

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        Self::sign_hash(self, hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Self::sign_message(self, message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        Self::sign_transaction(self, tx_bytes)
    }
}

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
        Self::from_hex(&account.private_key)
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
        s.signing_key()
            .verifying_key()
            .verify_prehash(hash, &sig)
            .expect("signature must verify");
    }

    #[test]
    fn sign_hash_verify() {
        let s = test_signer();
        let hash = Blake2b256::digest(b"filecoin test");
        let out = s.sign_hash(&hash).unwrap();
        assert_eq!(out.signature.len(), 65);
        assert!(out.recovery_id.is_some());
        verify_secp256k1(&s, &hash, &out);
    }

    #[test]
    fn sign_transaction_blake2b_verify() {
        let s = test_signer();
        let tx = b"fil tx bytes";
        let out = s.sign_transaction(tx).unwrap();
        let expected = Blake2b256::digest(tx);
        verify_secp256k1(&s, &expected, &out);
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let out1 = s.sign_message(b"same").unwrap();
        let out2 = s.sign_message(b"same").unwrap();
        assert_eq!(out1.signature, out2.signature);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes).unwrap();
        assert_eq!(
            s.signing_key().verifying_key(),
            test_signer().signing_key().verifying_key()
        );
    }

    #[test]
    fn rejects_non_32_byte_hash() {
        assert!(test_signer().sign_hash(b"short").is_err());
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
