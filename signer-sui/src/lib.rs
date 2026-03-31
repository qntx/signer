//! Sui transaction signer built on [`ed25519_dalek`] and [`blake2`].
//!
//! Sui uses **BLAKE2b-256** for address derivation and intent-based
//! transaction/message signing. The wire signature format is
//! `flag(0x00) || sig(64) || pubkey(32)` (97 bytes).
//!
//! Address derivation is handled by [`kobe-sui`].

mod error;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey};
pub use error::Error;
pub use signer_core::{self, Sign, SignExt, SignOutput};

/// Ed25519 signature scheme flag used by Sui.
const ED25519_FLAG: u8 = 0x00;

/// Sui transaction intent prefix: `[scope=0, version=0, app_id=0]`.
const TX_INTENT: [u8; 3] = [0x00, 0x00, 0x00];

/// Sui personal message intent prefix: `[scope=3, version=0, app_id=0]`.
const MSG_INTENT: [u8; 3] = [0x03, 0x00, 0x00];

/// Sui transaction signer.
#[derive(Debug, Clone)]
pub struct Signer {
    key: SigningKey,
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
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Generate a random signer.
    #[must_use]
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signer = Self::from_bytes(&bytes);
        bytes.fill(0);
        signer
    }

    /// Sign arbitrary bytes with Ed25519 (raw, no intent prefix).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.key.sign(message)
    }

    /// Sign a Sui transaction with intent-based BLAKE2b-256 hashing.
    ///
    /// Computes `BLAKE2b-256(intent[0,0,0] || tx_bytes)` then signs the digest.
    #[must_use]
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Signature {
        let digest = intent_hash(TX_INTENT, tx_bytes);
        self.key.sign(&digest)
    }

    /// Sign a personal message with intent-based BLAKE2b-256 hashing.
    ///
    /// The message is first BCS-serialized (ULEB128 length prefix), then
    /// `BLAKE2b-256(intent[3,0,0] || bcs_bytes)` is signed.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let bcs = bcs_serialize_bytes(message);
        let digest = intent_hash(MSG_INTENT, &bcs);
        self.key.sign(&digest)
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

    /// Verify an Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        use ed25519_dalek::Verifier;
        self.key.verifying_key().verify(message, signature)?;
        Ok(())
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.key.verifying_key().as_bytes()
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
}

impl Sign for Signer {
    type Error = Error;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, Error> {
        let sig = self.key.sign(hash);
        let pubkey = self.key.verifying_key().as_bytes().to_vec();
        Ok(SignOutput::ed25519_with_pubkey(
            sig.to_bytes().to_vec(),
            pubkey,
        ))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Error> {
        let sig = Self::sign_message(self, message);
        let pubkey = self.key.verifying_key().as_bytes().to_vec();
        Ok(SignOutput::ed25519_with_pubkey(
            sig.to_bytes().to_vec(),
            pubkey,
        ))
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Error> {
        let sig = Self::sign_transaction(self, tx_bytes);
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
    pub fn from_derived(account: &kobe_sui::DerivedAccount) -> Result<Self, Error> {
        Self::from_hex(&account.private_key)
    }
}

/// BLAKE2b-256 hash.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct length");
    out
}

/// Compute intent message hash: `BLAKE2b-256(intent_prefix || data)`.
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
        #[allow(clippy::cast_possible_truncation)] // guarded: & 0x7F always fits u8
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
mod tests {
    use super::*;

    #[test]
    fn address_uses_blake2b() {
        let s = Signer::random();
        let addr = s.address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66); // 0x + 64 hex chars

        // Verify manually
        let mut buf = Vec::with_capacity(33);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(&s.public_key_bytes());
        let hash = blake2b_256(&buf);
        assert_eq!(addr, format!("0x{}", hex::encode(hash)));
    }

    #[test]
    fn sign_transaction_uses_intent_and_blake2b() {
        let s = Signer::random();
        let tx = b"fake transaction bytes";
        let sig = s.sign_transaction(tx);

        // Verify against the intent-hashed digest
        let digest = intent_hash(TX_INTENT, tx);
        s.verify(&digest, &sig).unwrap();
    }

    #[test]
    fn sign_message_uses_bcs_and_intent() {
        let s = Signer::random();
        let msg = b"hello sui";
        let sig = s.sign_message(msg);

        // Verify against the BCS + intent-hashed digest
        let bcs = bcs_serialize_bytes(msg);
        let digest = intent_hash(MSG_INTENT, &bcs);
        s.verify(&digest, &sig).unwrap();
    }

    #[test]
    fn encode_signature_length() {
        let s = Signer::random();
        let sig = s.sign_raw(b"test");
        let encoded = s.encode_signature(&sig);
        assert_eq!(encoded.len(), 97);
        assert_eq!(encoded[0], ED25519_FLAG);
    }

    #[test]
    fn sign_trait_includes_pubkey() {
        let s = Signer::random();
        let out = Sign::sign_transaction(&s, b"tx").unwrap();
        assert_eq!(out.signature.len(), 64);
        assert!(out.public_key.is_some());
        assert_eq!(out.public_key.unwrap().len(), 32);
    }

    #[test]
    fn bcs_uleb128_encoding() {
        // Short message: length < 128 → single byte
        let bcs = bcs_serialize_bytes(b"hi");
        assert_eq!(bcs[0], 2); // length = 2
        assert_eq!(&bcs[1..], b"hi");

        // Longer message: length = 200 → two bytes
        let data = vec![0xAA; 200];
        let bcs = bcs_serialize_bytes(&data);
        assert_eq!(bcs[0], 0xC8); // 200 & 0x7F | 0x80 = 0xC8
        assert_eq!(bcs[1], 0x01); // 200 >> 7 = 1
        assert_eq!(&bcs[2..], data.as_slice());
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.key.as_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.public_key_bytes(), restored.public_key_bytes());
    }
}
