//! TRON transaction signer built on [`k256`] and [`sha3`].
//!
//! Provides secp256k1 ECDSA signing for TRON transactions and messages.
//! Address derivation is handled by [`kobe-tron`].

mod error;

pub use error::Error;
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// TRON transaction signer.
#[derive(Debug, Clone)]
pub struct Signer {
    key: SigningKey,
}

impl Signer {
    /// Create from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or the key is out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Self::from_bytes(&bytes)
    }

    /// Generate a random signer.
    #[must_use]
    pub fn random() -> Self {
        Self {
            key: SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng),
        }
    }

    /// Sign a 32-byte hash. Returns 65 bytes: `r(32) || s(32) || recovery_id(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not 32 bytes or signing fails.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<Vec<u8>, Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidMessage(format!(
                "expected 32-byte hash, got {}",
                hash.len()
            )));
        }
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(hash)
            .map_err(|e| Error::SigningFailed(e.to_string()))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(rid.to_byte());
        Ok(out)
    }

    /// Sign a TRON transaction (SHA-256 of the raw transaction bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = Sha256::digest(tx_bytes);
        self.sign_hash(&hash)
    }

    /// Sign a message with TRON message signing convention.
    ///
    /// `hash = keccak256("\x19TRON Signed Message:\n" || len || message)`
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let hash = Keccak256::digest(&data);
        self.sign_hash(&hash)
    }

    /// Expose the inner [`SigningKey`].
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_tron::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_tron::DerivedAccount) -> Result<Self, Error> {
        Self::from_hex(&account.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_hash_length() {
        let s = Signer::random();
        let sig = s.sign_hash(&[0u8; 32]).unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.key.to_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(
            hex::encode(s.key.to_bytes()),
            hex::encode(restored.key.to_bytes())
        );
    }
}
