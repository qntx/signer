//! TON transaction signer built on [`ed25519_dalek`].
//!
//! Provides Ed25519 signing for TON transactions and messages.
//! Address derivation is handled by [`kobe-ton`].

mod error;

pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey};
pub use error::Error;

/// TON transaction signer.
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

    /// Sign a TON transaction (Ed25519 over raw message bytes).
    #[must_use]
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Signature {
        self.key.sign(tx_bytes)
    }

    /// Verify an Ed25519 signature.
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

    /// Public key in hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_ton::DerivedAccount`].
    pub fn from_derived(account: &kobe_ton::DerivedAccount) -> Result<Self, Error> {
        Self::from_hex(&account.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let s = Signer::random();
        let sig = s.sign(b"hello TON");
        s.verify(b"hello TON", &sig).unwrap();
    }

    #[test]
    fn verify_wrong_message_fails() {
        let s = Signer::random();
        let sig = s.sign(b"correct");
        assert!(s.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.key.as_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn public_key_is_32_bytes() {
        let s = Signer::random();
        assert_eq!(s.public_key_bytes().len(), 32);
    }
}
