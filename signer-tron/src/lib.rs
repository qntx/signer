//! Tron transaction signer using secp256k1.
//!
//! Tron uses the same curve as Ethereum but with a different address format
//! (base58check with 0x41 prefix) and message prefix (`\x19TRON Signed Message`).

mod error;

use k256::ecdsa::SigningKey;
use sha2::{Digest as _, Sha256};
use sha3::{Digest, Keccak256};

pub use error::Error;

/// Tron signer.
#[derive(Debug, Clone)]
pub struct Signer {
    /// The secp256k1 signing key.
    signing_key: SigningKey,
}

/// Signature output from a Tron signing operation.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Raw signature bytes (65 bytes: r || s || v).
    pub bytes: Vec<u8>,
    /// ECDSA recovery ID.
    pub recovery_id: u8,
}

impl Signer {
    /// Create a signer from raw 32-byte private key.
    pub fn from_bytes(private_key: &[u8; 32]) -> Result<Self, Error> {
        let signing_key =
            SigningKey::from_slice(private_key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// Create a signer from a hex-encoded private key.
    pub fn from_hex(hex_key: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Self::from_bytes(&key)
    }

    /// Create a signer from a kobe-tron derived address.
    #[cfg(feature = "kobe")]
    pub fn from_derived(derived: &kobe_tron::DerivedAddress) -> Result<Self, Error> {
        let bytes =
            hex::decode(&*derived.private_key_hex).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Self::from_bytes(&key)
    }

    /// Get the base58check-encoded Tron address.
    #[must_use]
    pub fn address(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        let hash = Keccak256::digest(&pubkey.as_bytes()[1..]);
        let mut prefixed = vec![0x41u8];
        prefixed.extend_from_slice(&hash[12..]);
        bs58::encode(&prefixed).with_check().into_string()
    }

    /// Sign a pre-hashed 32-byte message digest.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature, Error> {
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| Error::Signing(e.to_string()))?;
        let r = sig.r().to_bytes();
        let s = sig.s().to_bytes();
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&r);
        bytes.extend_from_slice(&s);
        bytes.push(recid.to_byte());
        Ok(Signature {
            bytes,
            recovery_id: recid.to_byte(),
        })
    }

    /// Sign an arbitrary message with Tron's personal message prefix.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, Error> {
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(message);
        let hash: [u8; 32] = Keccak256::digest(&prefixed).into();
        self.sign_prehash(&hash)
    }

    /// Sign a transaction (SHA-256 of raw bytes, then ECDSA signed).
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<Signature, Error> {
        let hash: [u8; 32] = Sha256::digest(tx_bytes).into();
        self.sign_prehash(&hash)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    #[test]
    fn address_starts_with_t() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let addr = signer.address();
        assert!(addr.starts_with('T'), "got: {addr}");
        assert_eq!(addr.len(), 34);
    }

    #[test]
    fn deterministic_address() {
        let s1 = Signer::from_hex(TEST_KEY).unwrap();
        let s2 = Signer::from_hex(TEST_KEY).unwrap();
        assert_eq!(s1.address(), s2.address());
    }

    #[test]
    fn sign_message_65_bytes() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let sig = signer.sign_message(b"hello tron").unwrap();
        assert_eq!(sig.bytes.len(), 65);
    }

    #[test]
    fn sign_transaction_works() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let sig = signer.sign_transaction(b"fake tx").unwrap();
        assert_eq!(sig.bytes.len(), 65);
    }

    #[test]
    fn deterministic_signing() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let s1 = signer.sign_message(b"test").unwrap();
        let s2 = signer.sign_message(b"test").unwrap();
        assert_eq!(s1.bytes, s2.bytes);
    }

    #[test]
    fn invalid_key_rejected() {
        assert!(Signer::from_hex("bad").is_err());
    }

    #[test]
    fn base58check_roundtrip() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let addr = signer.address();
        let decoded = bs58::decode(&addr).with_check(None).into_vec().unwrap();
        assert_eq!(decoded[0], 0x41);
        assert_eq!(decoded.len(), 21);
    }
}
