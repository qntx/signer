//! Filecoin transaction signer using secp256k1 with Blake2b hashing.
//!
//! Filecoin f1 addresses use Blake2b-160 of uncompressed pubkey, with a base32
//! + Blake2b-4 checksum encoding. Signing uses Blake2b-256 prehash.

mod error;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use k256::ecdsa::SigningKey;

pub use error::Error;

/// Filecoin lowercase base32 alphabet (RFC 4648, no padding).
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Filecoin signer.
#[derive(Debug, Clone)]
pub struct Signer {
    /// The secp256k1 signing key.
    signing_key: SigningKey,
}

/// Signature output from a Filecoin signing operation.
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

    /// Create a signer from a kobe-fil derived address.
    #[cfg(feature = "kobe")]
    pub fn from_derived(derived: &kobe_fil::DerivedAddress) -> Result<Self, Error> {
        let bytes =
            hex::decode(&*derived.private_key_hex).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Self::from_bytes(&key)
    }

    /// Get the Filecoin f1 address.
    #[must_use]
    pub fn address(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        let payload = blake2b(pubkey.as_bytes(), 20);
        let protocol: u8 = 1;
        let mut checksum_input = Vec::with_capacity(1 + payload.len());
        checksum_input.push(protocol);
        checksum_input.extend_from_slice(&payload);
        let checksum = blake2b(&checksum_input, 4);
        let mut addr_bytes = Vec::with_capacity(payload.len() + checksum.len());
        addr_bytes.extend_from_slice(&payload);
        addr_bytes.extend_from_slice(&checksum);
        format!("f1{}", base32_encode(&addr_bytes))
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

    /// Sign an arbitrary message (Blake2b-256 hashed, then ECDSA signed).
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, Error> {
        let hash_vec = blake2b(message, 32);
        let hash: [u8; 32] = hash_vec.try_into().expect("blake2b-256 output is 32 bytes");
        self.sign_prehash(&hash)
    }

    /// Sign a transaction (Blake2b-256 of raw bytes, then ECDSA signed).
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<Signature, Error> {
        self.sign_message(tx_bytes)
    }
}

/// Compute a Blake2b hash with variable output length.
fn blake2b(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(output_len).expect("valid output length");
    hasher.update(data);
    let mut buf = vec![0u8; output_len];
    hasher
        .finalize_variable(&mut buf)
        .expect("valid output length");
    buf
}

/// Encode bytes using Filecoin's lowercase base32 (no padding).
fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    #[test]
    fn address_starts_with_f1() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        assert!(signer.address().starts_with("f1"));
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
        let sig = signer.sign_message(b"hello filecoin").unwrap();
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
}
