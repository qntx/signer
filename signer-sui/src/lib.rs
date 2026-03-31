//! Sui transaction signer built on [`ed25519_dalek`].
//!
//! Provides Ed25519 signing with Sui's intent-based hashing.
//! Address derivation is handled by [`kobe-sui`].

mod error;

pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey};
pub use error::Error;
use sha2::Digest as _;

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

    /// Sign arbitrary bytes with Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.key.sign(message)
    }

    /// Sign a Sui transaction with intent prefix `[0, 0, 0]` + SHA-256.
    #[must_use]
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Signature {
        let mut prefixed = Vec::with_capacity(3 + tx_bytes.len());
        prefixed.extend_from_slice(&[0, 0, 0]); // TransactionData intent
        prefixed.extend_from_slice(tx_bytes);
        let hash = sha2::Sha256::digest(&prefixed);
        self.key.sign(&hash)
    }

    /// Sign a personal message with intent prefix `[3, 0, 0]` + SHA-256.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let mut prefixed = Vec::with_capacity(3 + message.len());
        prefixed.extend_from_slice(&[3, 0, 0]); // PersonalMessage intent
        prefixed.extend_from_slice(message);
        let hash = sha2::Sha256::digest(&prefixed);
        self.key.sign(&hash)
    }

    /// Encode a Sui serialized signature: `flag(1) || sig(64) || pubkey(32)`.
    #[must_use]
    pub fn encode_signature(&self, signature: &Signature) -> Vec<u8> {
        let mut out = Vec::with_capacity(97);
        out.push(0x00); // Ed25519 scheme flag
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

    /// Sui address: `0x` + hex(SHA3-256(`0x00` || pubkey)).
    #[must_use]
    pub fn address(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut data = Vec::with_capacity(33);
        data.push(0x00); // Ed25519 scheme flag
        data.extend_from_slice(self.key.verifying_key().as_bytes());
        let hash = Sha3_256::digest(&data);
        format!("0x{}", hex::encode(hash))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let s = Signer::random();
        let sig = s.sign(b"hello Sui");
        s.verify(b"hello Sui", &sig).unwrap();
    }

    #[test]
    fn address_format() {
        let s = Signer::random();
        let addr = s.address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn encode_signature_length() {
        let s = Signer::random();
        let sig = s.sign(b"test");
        let encoded = s.encode_signature(&sig);
        assert_eq!(encoded.len(), 97); // 1 + 64 + 32
        assert_eq!(encoded[0], 0x00); // Ed25519 flag
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.key.as_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.public_key_bytes(), restored.public_key_bytes());
    }
}
