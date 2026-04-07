//! EVM transaction signer built on [`k256`] and [`sha3`].
//!
//! Provides EIP-191 personal signing, EIP-712 typed data signing,
//! and typed transaction signing with RLP encoding.
//!
//! **No alloy dependency.** Pure cryptographic primitives only.
//!
//! # Examples
//!
//! ```
//! use signer_evm::Signer;
//!
//! let signer = Signer::random();
//! let out = signer.sign_message(b"hello").unwrap();
//! assert_eq!(out.signature.len(), 65); // r(32) + s(32) + v(1)
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};

mod eip712;
mod error;
mod rlp;

pub use error::SignError;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
pub use signer_primitives::{self, Sign, SignExt, SignOutput};
use zeroize::ZeroizeOnDrop;

/// EVM transaction signer.
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
    /// Create a signer from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        let key =
            SigningKey::from_slice(bytes).map_err(|e| SignError::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create a signer from a hex-encoded private key (with or without `0x`).
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

    /// Ethereum address derived from this signing key (EIP-55 checksummed).
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "uncompressed pubkey is always 65B, Keccak256 is always 32B"
    )]
    pub fn address(&self) -> String {
        let vk = self.key.verifying_key();
        let pk = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&pk.as_bytes()[1..]);
        eip55_checksum(&hex::encode(&hash[12..]))
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

    /// Expose the inner [`SigningKey`] reference.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Sign a 32-byte hash. Returns 65 bytes: `r(32) || s(32) || v(1)`.
    ///
    /// `v` is the raw recovery ID (0 or 1).
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not exactly 32 bytes.
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

        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.r().to_bytes());
        out.extend_from_slice(&sig.s().to_bytes());
        out.push(rid.to_byte());
        Ok(SignOutput::secp256k1(out, rid.to_byte()))
    }

    /// EIP-191 `personal_sign`. Returns 65 bytes with `v = 27 | 28`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    #[allow(
        clippy::indexing_slicing,
        reason = "signature is always 65 bytes from sign_hash"
    )]
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let hash = Keccak256::digest(&data);

        let mut out = self.sign_hash(&hash)?;
        out.signature[64] += 27; // v = 27 + recovery_id
        out.recovery_id = out.recovery_id.map(|r| r + 27);
        Ok(out)
    }

    /// Sign EIP-712 typed structured data (JSON input).
    /// Returns 65 bytes with `v = 27 | 28`.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or signing fails.
    #[allow(
        clippy::indexing_slicing,
        reason = "signature is always 65 bytes from sign_hash"
    )]
    pub fn sign_typed_data(&self, typed_data_json: &str) -> Result<SignOutput, SignError> {
        let hash = eip712::hash_typed_data_json(typed_data_json)?;
        let mut out = self.sign_hash(&hash)?;
        out.signature[64] += 27;
        out.recovery_id = out.recovery_id.map(|r| r + 27);
        Ok(out)
    }

    /// Sign an unsigned typed transaction (EIP-1559 / EIP-2930).
    /// Returns 65 bytes: `r(32) || s(32) || v(1)` where `v` is raw recovery ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction bytes are malformed.
    pub fn sign_transaction(&self, unsigned_tx: &[u8]) -> Result<SignOutput, SignError> {
        let hash = Keccak256::digest(unsigned_tx);
        self.sign_hash(&hash)
    }

    /// Encode a signed typed transaction: `type || RLP([…fields, v, r, s])`.
    ///
    /// # Errors
    ///
    /// Returns an error if the unsigned tx or signature is malformed.
    #[allow(
        clippy::indexing_slicing,
        reason = "signature length is checked to be exactly 65 before slicing"
    )]
    pub fn encode_signed_transaction(
        unsigned_tx: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        if signature.len() != 65 {
            return Err(SignError::InvalidSignature(
                "expected 65-byte signature".into(),
            ));
        }
        let v = signature[64];
        let r: [u8; 32] = signature[..32]
            .try_into()
            .map_err(|_| SignError::InvalidSignature("bad r component".into()))?;
        let s: [u8; 32] = signature[32..64]
            .try_into()
            .map_err(|_| SignError::InvalidSignature("bad s component".into()))?;
        rlp::encode_signed_typed_tx(unsigned_tx, v, &r, &s)
            .map_err(|e| SignError::InvalidTransaction(String::from(e)))
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

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        Self::encode_signed_transaction(tx_bytes, &signature.signature)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_evm::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_evm::DerivedAccount) -> Result<Self, SignError> {
        Self::from_hex(&account.private_key)
    }
}

fn eip55_checksum(addr_hex: &str) -> String {
    let lower = addr_hex.to_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());
    let hash_hex = hex::encode(hash);

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = u8::from_str_radix(&hash_hex[i..=i], 16).unwrap_or(0);
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
    }
    out
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
    const TEST_ADDR: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";

    fn test_signer() -> Signer {
        Signer::from_hex(TEST_KEY).unwrap()
    }

    #[test]
    fn known_address_from_hex() {
        assert_eq!(test_signer().address(), TEST_ADDR);
    }

    #[test]
    fn known_address_0x_prefix() {
        let s = Signer::from_hex(&format!("0x{TEST_KEY}")).unwrap();
        assert_eq!(s.address(), TEST_ADDR);
    }

    #[test]
    fn known_address_from_bytes() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes).unwrap();
        assert_eq!(s.address(), TEST_ADDR);
    }

    #[test]
    fn sign_hash_verify() {
        let s = test_signer();
        let hash = Keccak256::digest(b"test message");
        let out = s.sign_hash(&hash).unwrap();

        assert_eq!(out.signature.len(), 65);
        assert!(out.recovery_id.is_some());
        let v = out.recovery_id.unwrap();
        assert!(v == 0 || v == 1, "raw recovery_id must be 0 or 1, got {v}");

        let r: [u8; 32] = out.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = out.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s_bytes).unwrap();
        s.signing_key()
            .verifying_key()
            .verify_prehash(&hash, &sig)
            .expect("signature must verify");
    }

    #[test]
    fn sign_message_eip191_verify() {
        let s = test_signer();
        let msg = b"Hello World";
        let out = s.sign_message(msg).unwrap();

        assert_eq!(out.signature.len(), 65);
        let v = out.signature[64];
        assert!(v == 27 || v == 28, "EIP-191 v must be 27 or 28, got {v}");

        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(msg);
        let hash = Keccak256::digest(&prefixed);

        let r: [u8; 32] = out.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = out.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s_bytes).unwrap();
        s.signing_key()
            .verifying_key()
            .verify_prehash(&hash, &sig)
            .expect("EIP-191 signature must verify");
    }

    #[test]
    fn sign_message_recovery_id_matches_v() {
        let s = test_signer();
        let out = s.sign_message(b"recovery test").unwrap();
        let v = out.signature[64];
        let rid = out.recovery_id.unwrap();
        assert_eq!(v, rid, "v byte must equal recovery_id");
        assert!(rid == 27 || rid == 28);
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let hash = Keccak256::digest(b"deterministic");
        let out1 = s.sign_hash(&hash).unwrap();
        let out2 = s.sign_hash(&hash).unwrap();
        assert_eq!(out1.signature, out2.signature);
    }

    #[test]
    fn rejects_non_32_byte_hash() {
        let s = test_signer();
        assert!(s.sign_hash(b"short").is_err());
        assert!(s.sign_hash(&[0u8; 33]).is_err());
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(Signer::from_hex("not-hex").is_err());
        assert!(Signer::from_hex("abcd").is_err());
        assert!(Signer::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("4c0883"));
        assert!(!debug.contains("362318"));
    }
}
