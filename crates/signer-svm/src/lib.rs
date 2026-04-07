//! Solana transaction signer built on [`ed25519_dalek`].
//!
//! Provides Ed25519 signing, Solana compact-u16 transaction envelope
//! parsing, and signed transaction encoding.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};

mod error;

pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey, Verifier};
pub use error::SignError;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};
use zeroize::Zeroizing;

/// Solana transaction signer.
///
/// Wraps an [`ed25519_dalek::SigningKey`]. The inner key is zeroized on drop.
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

    /// Create from a Base58-encoded keypair (64 bytes: secret || public).
    ///
    /// Standard format used by Phantom, Backpack, and Solflare.
    ///
    /// # Errors
    ///
    /// Returns an error if the Base58 is invalid or not 64 bytes.
    #[allow(
        clippy::indexing_slicing,
        reason = "length is checked to be exactly 64 before slicing"
    )]
    pub fn from_keypair_base58(b58: &str) -> Result<Self, SignError> {
        let decoded = bs58::decode(b58)
            .into_vec()
            .map_err(|e| SignError::InvalidKeypair(e.to_string()))?;
        if decoded.len() != 64 {
            return Err(SignError::InvalidKeypair(format!(
                "expected 64 bytes, got {}",
                decoded.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decoded[..32]);
        let signer = Self::from_bytes(&secret);
        secret.fill(0);
        Ok(signer)
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

    /// Solana address (Base58-encoded 32-byte public key).
    #[must_use]
    pub fn address(&self) -> String {
        bs58::encode(self.key.verifying_key().as_bytes()).into_string()
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }

    /// Public key in hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    /// Sign arbitrary bytes with raw Ed25519 (no hashing or prefixing).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.key.sign(message)
    }

    /// Sign serialized Solana transaction message bytes.
    #[must_use]
    pub fn sign_transaction_message(&self, message_bytes: &[u8]) -> Signature {
        self.sign_raw(message_bytes)
    }

    /// Verify an Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignError> {
        self.key.verifying_key().verify(msg, signature)?;
        Ok(())
    }

    /// Export keypair as Base58 (64 bytes: secret || public).
    #[must_use]
    pub fn keypair_base58(&self) -> Zeroizing<String> {
        let vk = self.key.verifying_key();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.key.as_bytes());
        buf[32..].copy_from_slice(vk.as_bytes());
        let encoded = bs58::encode(&buf).into_string();
        buf.fill(0);
        Zeroizing::new(encoded)
    }

    /// Extract the signable message portion from a full serialized Solana transaction.
    ///
    /// Strips the compact-u16 header and signature slot placeholders.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is empty or malformed.
    #[allow(clippy::indexing_slicing, reason = "bounds are checked before slicing")]
    pub fn extract_signable_bytes(tx_bytes: &[u8]) -> Result<&[u8], SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::InvalidTransaction("empty transaction".into()));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        let msg_start = header_len + num_sigs * 64;
        if tx_bytes.len() <= msg_start {
            return Err(SignError::InvalidTransaction(
                "transaction too short".into(),
            ));
        }
        Ok(&tx_bytes[msg_start..])
    }

    /// Encode a signed transaction by splicing the signature into the first slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is empty or has no signature slots.
    #[allow(clippy::indexing_slicing, reason = "bounds are checked before slicing")]
    pub fn encode_signed_transaction(
        tx_bytes: &[u8],
        signature: &Signature,
    ) -> Result<Vec<u8>, SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::InvalidTransaction("empty transaction".into()));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        if num_sigs == 0 {
            return Err(SignError::InvalidTransaction("no signature slots".into()));
        }
        if tx_bytes.len() < header_len + num_sigs * 64 {
            return Err(SignError::InvalidTransaction(
                "transaction too short".into(),
            ));
        }
        let mut signed = tx_bytes.to_vec();
        signed[header_len..header_len + 64].copy_from_slice(&signature.to_bytes());
        Ok(signed)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        let sig = self.key.sign(hash);
        Ok(SignOutput::ed25519(sig.to_bytes().to_vec()))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(tx_bytes)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignError> {
        Self::extract_signable_bytes(tx_bytes)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        let sig = Signature::from_slice(&signature.signature)
            .map_err(|e| SignError::InvalidTransaction(e.to_string()))?;
        Self::encode_signed_transaction(tx_bytes, &sig)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_svm::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(derived: &kobe_svm::DerivedAddress) -> Result<Self, SignError> {
        Self::from_hex(&derived.private_key_hex)
    }
}

fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), SignError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 3 {
            return Err(SignError::InvalidTransaction(
                "compact-u16 exceeds 3 bytes".into(),
            ));
        }
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(SignError::InvalidTransaction(
        "truncated compact-u16".into(),
    ))
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
    fn rfc8032_vector1_pubkey() {
        assert_eq!(test_signer().public_key_hex(), TEST_PUBKEY);
    }

    #[test]
    fn address_is_base58_pubkey() {
        let s = test_signer();
        let decoded = bs58::decode(&s.address()).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(hex::encode(&decoded), TEST_PUBKEY);
    }

    #[test]
    fn from_bytes_matches_from_hex() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s1 = Signer::from_bytes(&bytes);
        assert_eq!(s1.address(), test_signer().address());
    }

    #[test]
    fn keypair_base58_roundtrip() {
        let s = test_signer();
        let b58 = s.keypair_base58();
        let restored = Signer::from_keypair_base58(&b58).unwrap();
        assert_eq!(s.address(), restored.address());
        assert_eq!(s.public_key_hex(), restored.public_key_hex());
    }

    #[test]
    fn sign_and_verify() {
        let s = test_signer();
        let msg = b"test message for solana";
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
    fn sign_trait_verify() {
        let s = test_signer();
        let out = Sign::sign_message(&s, b"hello").unwrap();
        assert_eq!(out.signature.len(), 64);
        assert!(out.recovery_id.is_none());
        let sig = Signature::from_slice(&out.signature).unwrap();
        s.verify(b"hello", &sig)
            .expect("trait signature must verify");
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let out1 = Sign::sign_hash(&s, b"deterministic").unwrap();
        let out2 = Sign::sign_hash(&s, b"deterministic").unwrap();
        assert_eq!(out1.signature, out2.signature);
    }

    #[test]
    fn extract_signable_bytes_strips_header() {
        // Minimal Solana tx: compact-u16(1) + 64-byte sig slot + message
        let mut tx = vec![1u8];
        tx.extend_from_slice(&[0u8; 64]);
        tx.extend_from_slice(b"message_body");
        let signable = Signer::extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, b"message_body");
    }

    #[test]
    fn extract_signable_bytes_rejects_empty() {
        assert!(Signer::extract_signable_bytes(&[]).is_err());
    }

    #[test]
    fn encode_signed_transaction_splices_sig() {
        let s = test_signer();
        let msg = b"message_body";
        let mut tx = vec![1u8];
        tx.extend_from_slice(&[0u8; 64]);
        tx.extend_from_slice(msg);

        let sig = s.sign_raw(msg);
        let signed = Signer::encode_signed_transaction(&tx, &sig).unwrap();

        assert_eq!(&signed[1..65], &sig.to_bytes());
        assert_eq!(&signed[65..], msg);
    }

    #[test]
    fn rejects_invalid_keypair_base58() {
        assert!(Signer::from_keypair_base58("invalid!!!").is_err());
        assert!(Signer::from_keypair_base58("3J98t1").is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9d61b1"));
    }
}
