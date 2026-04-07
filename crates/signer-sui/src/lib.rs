//! Sui transaction signer built on [`ed25519_dalek`] and [`blake2`].
//!
//! Sui uses **BLAKE2b-256** for address derivation and intent-based
//! transaction/message signing. The wire signature format is
//! `flag(0x00) || sig(64) || pubkey(32)` (97 bytes).
//!
//! Address derivation is handled by [`kobe-sui`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use zeroize as _;

mod error;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey, Verifier};
pub use error::SignError;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// Ed25519 signature scheme flag used by Sui.
const ED25519_FLAG: u8 = 0x00;

/// Sui transaction intent prefix: `[scope=0, version=0, app_id=0]`.
const TX_INTENT: [u8; 3] = [0x00, 0x00, 0x00];

/// Sui personal message intent prefix: `[scope=3, version=0, app_id=0]`.
const MSG_INTENT: [u8; 3] = [0x03, 0x00, 0x00];

/// Sui transaction signer.
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
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        let signer = Self::from_bytes(&bytes);
        bytes.fill(0);
        signer
    }

    /// Sui address: `0x` + hex(BLAKE2b-256(`0x00` || pubkey)).
    #[must_use]
    pub fn address(&self) -> String {
        let mut buf = Vec::with_capacity(33);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(self.key.verifying_key().as_bytes());
        let hash = blake2b_256(&buf);
        format!("0x{}", hex::encode(hash))
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }

    /// Sign arbitrary bytes with Ed25519 (raw, no intent prefix).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.key.sign(message)
    }

    /// Sign a Sui transaction with intent-based BLAKE2b-256 hashing.
    ///
    /// Computes `BLAKE2b-256(intent[0,0,0] || tx_bytes)` then signs the digest.
    /// Returns the raw Ed25519 [`Signature`].
    #[must_use]
    pub fn sign_transaction_intent(&self, tx_bytes: &[u8]) -> Signature {
        let digest = intent_hash(TX_INTENT, tx_bytes);
        self.key.sign(&digest)
    }

    /// Sign a personal message with intent-based BLAKE2b-256 hashing.
    ///
    /// The message is first BCS-serialized (ULEB128 length prefix), then
    /// `BLAKE2b-256(intent[3,0,0] || bcs_bytes)` is signed.
    /// Returns the raw Ed25519 [`Signature`].
    #[must_use]
    pub fn sign_message_intent(&self, message: &[u8]) -> Signature {
        let bcs = bcs_serialize_bytes(message);
        let digest = intent_hash(MSG_INTENT, &bcs);
        self.key.sign(&digest)
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

    /// Encode a Sui wire signature: `flag(0x00) || sig(64) || pubkey(32)`.
    #[must_use]
    pub fn encode_signature(&self, signature: &Signature) -> Vec<u8> {
        let mut out = Vec::with_capacity(97);
        out.push(ED25519_FLAG);
        out.extend_from_slice(&signature.to_bytes());
        out.extend_from_slice(self.key.verifying_key().as_bytes());
        out
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
        let sig = self.sign_message_intent(message);
        let pubkey = self.key.verifying_key().as_bytes().to_vec();
        Ok(SignOutput::ed25519_with_pubkey(
            sig.to_bytes().to_vec(),
            pubkey,
        ))
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let sig = self.sign_transaction_intent(tx_bytes);
        let pubkey = self.key.verifying_key().as_bytes().to_vec();
        Ok(SignOutput::ed25519_with_pubkey(
            sig.to_bytes().to_vec(),
            pubkey,
        ))
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
        Self::from_hex(&account.private_key)
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
        assert_eq!(hex::encode(test_signer().public_key_bytes()), TEST_PUBKEY);
    }

    #[test]
    fn address_is_blake2b_of_flagged_pubkey() {
        let s = test_signer();
        let addr = s.address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66);

        let mut buf = vec![ED25519_FLAG];
        buf.extend_from_slice(&s.public_key_bytes());
        let expected = blake2b_256(&buf);
        assert_eq!(addr, format!("0x{}", hex::encode(expected)));
    }

    #[test]
    fn from_bytes_matches_from_hex() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes);
        assert_eq!(s.address(), test_signer().address());
    }

    #[test]
    fn sign_transaction_intent_verify() {
        let s = test_signer();
        let tx = b"bcs transaction data";
        let sig = s.sign_transaction_intent(tx);
        let digest = intent_hash(TX_INTENT, tx);
        s.verify(&digest, &sig).expect("intent digest must verify");
    }

    #[test]
    fn sign_message_bcs_intent_verify() {
        let s = test_signer();
        let msg = b"hello sui";
        let sig = s.sign_message_intent(msg);
        let bcs = bcs_serialize_bytes(msg);
        let digest = intent_hash(MSG_INTENT, &bcs);
        s.verify(&digest, &sig)
            .expect("personal msg digest must verify");
    }

    #[test]
    fn encode_signature_wire_format() {
        let s = test_signer();
        let sig = s.sign_raw(b"data");
        let encoded = s.encode_signature(&sig);

        assert_eq!(encoded.len(), 97);
        assert_eq!(encoded[0], ED25519_FLAG);
        assert_eq!(&encoded[1..65], &sig.to_bytes());
        assert_eq!(&encoded[65..], s.public_key_bytes());
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
        let s1 = s.sign_transaction_intent(b"same input");
        let s2 = s.sign_transaction_intent(b"same input");
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn bcs_uleb128_encoding() {
        let bcs_short = bcs_serialize_bytes(b"hi");
        assert_eq!(bcs_short[0], 2);
        assert_eq!(&bcs_short[1..], b"hi");

        let data = vec![0xAA; 200];
        let bcs_long = bcs_serialize_bytes(&data);
        assert_eq!(bcs_long[0], 0xC8);
        assert_eq!(bcs_long[1], 0x01);
        assert_eq!(&bcs_long[2..], data.as_slice());

        let bcs_empty = bcs_serialize_bytes(b"");
        assert_eq!(bcs_empty, vec![0]);
    }

    #[test]
    fn bcs_128_byte_boundary() {
        let data = vec![0xBB; 128];
        let bcs = bcs_serialize_bytes(&data);
        assert_eq!(bcs[0], 0x80);
        assert_eq!(bcs[1], 0x01);
        assert_eq!(&bcs[2..], data.as_slice());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9d61b1"));
    }
}
