//! Spark (Bitcoin L2) transaction signer built on [`k256`] and [`sha2`].
//!
//! Provides secp256k1 ECDSA signing for Spark transactions.
//! Address derivation is handled by [`kobe-spark`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};

mod error;

pub use error::SignError;
use k256::ecdsa::SigningKey;
use ripemd::{Digest as _, Ripemd160};
use sha2::{Digest, Sha256};
pub use signer_primitives::{self, Sign, SignExt, SignOutput};
use zeroize::ZeroizeOnDrop;

/// Spark transaction signer.
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
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        let key = SigningKey::from_slice(&bytes).expect("invalid random key");
        bytes.zeroize();
        Self { key }
    }

    /// Spark P2PKH address (legacy, starts with `1`).
    ///
    /// Same derivation as Bitcoin: `Base58Check(0x00 || RIPEMD160(SHA256(compressed_pubkey)))`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "SHA-256 output is always 32 bytes, slicing first 4 is safe"
    )]
    pub fn address(&self) -> String {
        let pubkey = self.public_key_bytes();
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

    /// Sign a Spark transaction (double-SHA256 then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let hash = Sha256::digest(Sha256::digest(tx_bytes));
        self.sign_hash(&hash)
    }

    /// Sign a message (double-SHA256 then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let hash = Sha256::digest(Sha256::digest(message));
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

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_spark::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_spark::DerivedAccount) -> Result<Self, SignError> {
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
        let out = s.sign_hash(&[0u8; 32]).unwrap();
        assert_eq!(out.signature.len(), 65);
        assert!(out.recovery_id.is_some());
        verify_secp256k1(&s, &[0u8; 32], &out);
    }

    #[test]
    fn sign_transaction_double_sha256_verify() {
        let s = test_signer();
        let tx = b"spark tx data";
        let out = s.sign_transaction(tx).unwrap();
        let expected = Sha256::digest(Sha256::digest(tx));
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
