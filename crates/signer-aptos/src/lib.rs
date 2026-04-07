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
use zeroize as _;

mod error;

pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey, Verifier};
pub use error::SignError;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// Ed25519 single-key authentication scheme byte used by Aptos.
const ED25519_SCHEME: u8 = 0x00;

/// Domain separator for `RawTransaction` signing messages.
const RAW_TX_DOMAIN: &[u8] = b"APTOS::RawTransaction";

/// Aptos transaction signer.
///
/// Wraps an Ed25519 signing key. The inner key is zeroized on drop.
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

impl Signer {
    /// Create from raw 32-byte secret key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }

    /// Create from a hex-encoded 32-byte private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or not 32 bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            SignError::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Generate a random signer.
    ///
    /// # Panics
    ///
    /// Panics if the OS random number generator fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    #[allow(clippy::expect_used, reason = "getrandom failure is unrecoverable")]
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let signer = Self::from_bytes(&bytes);
        bytes.fill(0);
        signer
    }

    /// Aptos account address: `0x` + hex(`SHA3-256(pubkey || 0x00)`).
    #[must_use]
    pub fn address(&self) -> String {
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(self.key.verifying_key().as_bytes());
        buf.push(ED25519_SCHEME);
        let hash = sha3_256(&buf);
        format!("0x{}", hex::encode(hash))
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }

    /// Public key in hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Sign arbitrary bytes with raw Ed25519 (no domain prefix).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.key.sign(message)
    }

    /// Sign a BCS-serialized `RawTransaction`.
    ///
    /// Computes `SHA3-256("APTOS::RawTransaction")` as the 32-byte prefix,
    /// then signs `prefix || bcs_raw_tx` with Ed25519.
    #[must_use]
    pub fn sign_transaction_bcs(&self, bcs_raw_tx: &[u8]) -> Signature {
        let signing_msg = tx_signing_message(bcs_raw_tx);
        self.key.sign(&signing_msg)
    }

    /// Verify an Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignError> {
        self.key.verifying_key().verify(message, signature)?;
        Ok(())
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        let sig = self.key.sign(hash);
        let pubkey = self.key.verifying_key().as_bytes().to_vec();
        Ok(SignOutput::ed25519_with_pubkey(
            sig.to_bytes().to_vec(),
            pubkey,
        ))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let sig = self.sign_transaction_bcs(tx_bytes);
        let pubkey = self.key.verifying_key().as_bytes().to_vec();
        Ok(SignOutput::ed25519_with_pubkey(
            sig.to_bytes().to_vec(),
            pubkey,
        ))
    }
}

/// Compute SHA3-256.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
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
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use indexing for clarity"
)]
mod tests {
    use super::*;

    // RFC 8032 Test Vector 1
    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_PUBKEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn test_signer() -> Signer {
        Signer::from_hex(TEST_KEY).unwrap()
    }

    #[test]
    fn rfc8032_pubkey() {
        assert_eq!(test_signer().public_key_hex(), TEST_PUBKEY);
    }

    #[test]
    fn address_is_sha3_of_pubkey_with_scheme() {
        let s = test_signer();
        let addr = s.address();
        assert!(addr.starts_with("0x"), "address must start with 0x");
        assert_eq!(addr.len(), 66, "address must be 66 chars (0x + 64 hex)");

        // Manually verify: SHA3-256(pubkey || 0x00)
        let mut buf = s.public_key_bytes();
        buf.push(ED25519_SCHEME);
        let expected = sha3_256(&buf);
        assert_eq!(addr, format!("0x{}", hex::encode(expected)));
    }

    #[test]
    fn from_bytes_matches_from_hex() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes);
        assert_eq!(s.address(), test_signer().address());
    }

    #[test]
    fn sign_and_verify() {
        let s = test_signer();
        let msg = b"hello aptos";
        let sig = s.sign_raw(msg);
        s.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn sign_wrong_message_fails() {
        let s = test_signer();
        let sig = s.sign_raw(b"correct");
        assert!(s.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn sign_transaction_bcs_verify() {
        let s = test_signer();
        let bcs_tx = b"fake bcs raw transaction";
        let sig = s.sign_transaction_bcs(bcs_tx);
        let signing_msg = tx_signing_message(bcs_tx);
        s.verify(&signing_msg, &sig)
            .expect("transaction signature must verify against signing message");
    }

    #[test]
    fn tx_signing_message_prefix_is_correct() {
        let prefix = sha3_256(b"APTOS::RawTransaction");
        let bcs = b"test";
        let msg = tx_signing_message(bcs);
        assert_eq!(msg.len(), 32 + bcs.len());
        assert_eq!(&msg[..32], &prefix);
        assert_eq!(&msg[32..], bcs.as_slice());
    }

    #[test]
    fn sign_trait_includes_pubkey() {
        let s = test_signer();
        let out = Sign::sign_transaction(&s, b"tx").unwrap();
        assert_eq!(out.signature.len(), 64);
        let pk = out.public_key.as_ref().expect("must include pubkey");
        assert_eq!(pk.len(), 32);
        assert_eq!(hex::encode(pk), TEST_PUBKEY);
    }

    #[test]
    fn deterministic_signing() {
        let s = test_signer();
        let s1 = s.sign_transaction_bcs(b"same input");
        let s2 = s.sign_transaction_bcs(b"same input");
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9d61b1"));
    }
}
