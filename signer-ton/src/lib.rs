//! TON transaction signer using Ed25519.
//!
//! TON signs messages directly with Ed25519 (no prehashing).

mod error;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};

pub use ed25519_dalek;
pub use error::Error;

/// TON signer.
#[derive(Debug)]
pub struct Signer {
    /// The Ed25519 signing key.
    signing_key: SigningKey,
}

/// Signature output from a TON signing operation.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Raw Ed25519 signature bytes (64 bytes).
    pub bytes: [u8; 64],
}

impl Signer {
    /// Create a signer from raw 32-byte private key.
    pub fn from_bytes(private_key: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(private_key),
        }
    }

    /// Create a signer from a hex-encoded private key.
    pub fn from_hex(hex_key: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(&key))
    }

    /// Create a signer from a kobe-ton derived address.
    #[cfg(feature = "kobe")]
    pub fn from_derived(derived: &kobe_ton::DerivedAddress) -> Result<Self, Error> {
        let bytes =
            hex::decode(&*derived.private_key_hex).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(&key))
    }

    /// Get the public key bytes.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    /// Sign arbitrary bytes (Ed25519 direct sign, no prehashing).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature {
            bytes: sig.to_bytes(),
        }
    }

    /// Sign a message (same as `sign` for TON — Ed25519 direct).
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.sign(message)
    }

    /// Sign a transaction (same as `sign` for TON — Ed25519 direct).
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Signature {
        self.sign(tx_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    #[test]
    fn sign_produces_64_bytes() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let sig = signer.sign(b"hello ton");
        assert_eq!(sig.bytes.len(), 64);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let message = b"test message for ton";
        let sig = signer.sign(message);

        let verifying_key = signer.signing_key.verifying_key();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.bytes);
        verifying_key.verify(message, &dalek_sig).unwrap();
    }

    #[test]
    fn deterministic_signing() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let s1 = signer.sign(b"test");
        let s2 = signer.sign(b"test");
        assert_eq!(s1.bytes, s2.bytes);
    }

    #[test]
    fn different_messages_different_sigs() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let s1 = signer.sign(b"hello");
        let s2 = signer.sign(b"world");
        assert_ne!(s1.bytes, s2.bytes);
    }

    #[test]
    fn invalid_key_rejected() {
        assert!(Signer::from_hex("bad").is_err());
        assert!(Signer::from_hex("aabb").is_err());
    }

    #[test]
    fn public_key_is_32_bytes() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        assert_eq!(signer.public_key().len(), 32);
    }
}
