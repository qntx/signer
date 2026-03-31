//! TRON transaction signer built on [`k256`] and [`sha3`].
//!
//! Provides secp256k1 ECDSA signing for TRON transactions and messages.
//! Address derivation is handled by [`kobe-tron`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, vec::Vec};

mod error;

pub use error::Error;
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
pub use signer_core::{self, Sign, SignExt, SignOutput};
use zeroize::ZeroizeOnDrop;

/// TRON transaction signer.
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
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or the key is out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Self::from_bytes(&bytes)
    }

    /// Generate a random signer.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn random() -> Self {
        Self {
            key: SigningKey::random(&mut rand_core::OsRng),
        }
    }

    /// Sign a 32-byte hash. Returns 65 bytes: `r(32) || s(32) || recovery_id(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not 32 bytes or signing fails.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidMessage(format!(
                "expected 32-byte hash, got {}",
                hash.len()
            )));
        }
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(hash)
            .map_err(|e| Error::SigningFailed(e.to_string()))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(rid.to_byte());
        Ok(SignOutput::secp256k1(out, rid.to_byte()))
    }

    /// Sign a TRON transaction (SHA-256 of the raw transaction bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Error> {
        let hash = Sha256::digest(tx_bytes);
        self.sign_hash(&hash)
    }

    /// Sign a message with TRON message signing convention.
    ///
    /// `hash = keccak256("\x19TRON Signed Message:\n" || len || message)`
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Error> {
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let hash = Keccak256::digest(&data);
        let mut out = self.sign_hash(&hash)?;
        // TRON follows EVM convention: v = 27 + recovery_id
        out.signature[64] += 27;
        out.recovery_id = out.recovery_id.map(|r| r + 27);
        Ok(out)
    }

    /// Expose the inner [`SigningKey`].
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

impl Sign for Signer {
    type Error = Error;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, Error> {
        Self::sign_hash(self, hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Error> {
        Self::sign_message(self, message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Error> {
        Self::sign_transaction(self, tx_bytes)
    }
}
#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_tron::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_tron::DerivedAccount) -> Result<Self, Error> {
        Self::from_hex(&account.private_key)
    }
}

#[cfg(test)]
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
        let hash = Sha256::digest(b"tron test");
        let out = s.sign_hash(&hash).unwrap();
        assert_eq!(out.signature.len(), 65);
        assert!(out.recovery_id.is_some());
        verify_secp256k1(&s, &hash, &out);
    }

    #[test]
    fn sign_transaction_sha256_verify() {
        let s = test_signer();
        let tx = b"tron tx bytes";
        let out = s.sign_transaction(tx).unwrap();
        let expected = Sha256::digest(tx);
        verify_secp256k1(&s, &expected, &out);
    }

    #[test]
    fn sign_message_tron_prefix_verify() {
        let s = test_signer();
        let msg = b"Hello TRON";
        let out = s.sign_message(msg).unwrap();

        let v = out.signature[64];
        assert!(v == 27 || v == 28, "TRON v must be 27 or 28, got {v}");

        let prefix = format!("\x19TRON Signed Message:\n{}", msg.len());
        let mut data = Vec::new();
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(msg);
        let hash = Keccak256::digest(&data);
        verify_secp256k1(&s, &hash, &out);
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let out1 = s.sign_hash(&[0u8; 32]).unwrap();
        let out2 = s.sign_hash(&[0u8; 32]).unwrap();
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
