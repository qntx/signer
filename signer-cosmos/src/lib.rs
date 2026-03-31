//! Cosmos transaction signer using secp256k1.
//!
//! Provides message and transaction signing, plus bech32 address derivation
//! from raw private keys. Cosmos signs SHA-256 hashes of serialized messages.

mod error;

use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub use error::Error;

/// Cosmos signer with configurable bech32 human-readable part.
#[derive(Debug, Clone)]
pub struct Signer {
    /// The secp256k1 signing key.
    signing_key: SigningKey,
    /// Bech32 human-readable part (e.g. "cosmos").
    hrp: String,
}

/// Signature output from a Cosmos signing operation.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Raw signature bytes (64 bytes r||s + 1 byte recovery id = 65).
    pub bytes: Vec<u8>,
    /// ECDSA recovery ID.
    pub recovery_id: u8,
}

impl Signer {
    /// Create a signer from raw 32-byte private key with default "cosmos" prefix.
    pub fn from_bytes(private_key: &[u8; 32]) -> Result<Self, Error> {
        Self::from_bytes_with_hrp(private_key, "cosmos")
    }

    /// Create a signer from raw 32-byte private key with custom bech32 prefix.
    pub fn from_bytes_with_hrp(private_key: &[u8; 32], hrp: &str) -> Result<Self, Error> {
        let signing_key =
            SigningKey::from_slice(private_key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self {
            signing_key,
            hrp: hrp.to_owned(),
        })
    }

    /// Create a signer from a hex-encoded private key.
    pub fn from_hex(hex_key: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Self::from_bytes(&key)
    }

    /// Create a signer from a kobe-cosmos derived address.
    #[cfg(feature = "kobe")]
    pub fn from_derived(derived: &kobe_cosmos::DerivedAddress) -> Result<Self, Error> {
        let bytes =
            hex::decode(&*derived.private_key_hex).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Self::from_bytes(&key)
    }

    /// Get the bech32-encoded address.
    #[must_use]
    pub fn address(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let hash = Ripemd160::digest(Sha256::digest(pubkey.as_bytes()));
        let hrp = bech32::Hrp::parse(&self.hrp).expect("valid HRP");
        bech32::encode::<bech32::Bech32>(hrp, &hash).expect("valid bech32")
    }

    /// Sign a pre-hashed 32-byte message digest.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature, Error> {
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| Error::Signing(e.to_string()))?;
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(recid.to_byte());
        Ok(Signature {
            bytes,
            recovery_id: recid.to_byte(),
        })
    }

    /// Sign an arbitrary message (SHA-256 hashed, then ECDSA signed).
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, Error> {
        let hash: [u8; 32] = Sha256::digest(message).into();
        self.sign_prehash(&hash)
    }

    /// Sign a transaction (SHA-256 of raw bytes, then ECDSA signed).
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<Signature, Error> {
        self.sign_message(tx_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    #[test]
    fn address_starts_with_cosmos1() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        assert!(signer.address().starts_with("cosmos1"));
    }

    #[test]
    fn deterministic_address() {
        let s1 = Signer::from_hex(TEST_KEY).unwrap();
        let s2 = Signer::from_hex(TEST_KEY).unwrap();
        assert_eq!(s1.address(), s2.address());
    }

    #[test]
    fn sign_message_produces_65_bytes() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let sig = signer.sign_message(b"hello cosmos").unwrap();
        assert_eq!(sig.bytes.len(), 65);
    }

    #[test]
    fn sign_transaction_works() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let sig = signer.sign_transaction(b"fake tx bytes").unwrap();
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
        assert!(Signer::from_hex("not-hex").is_err());
        assert!(Signer::from_hex("aabb").is_err());
    }

    #[test]
    fn custom_hrp() {
        let key: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let signer = Signer::from_bytes_with_hrp(&key, "osmo").unwrap();
        assert!(signer.address().starts_with("osmo1"));
    }
}
