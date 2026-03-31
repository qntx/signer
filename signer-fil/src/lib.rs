//! Filecoin transaction signer built on [`k256`] and [`blake2`].
//!
//! Provides secp256k1 ECDSA signing with Blake2b-256 hashing for Filecoin.
//! Address derivation is handled by [`kobe-fil`].

mod error;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
pub use error::Error;
use k256::ecdsa::SigningKey;

type Blake2b256 = Blake2b<U32>;

/// Filecoin transaction signer.
#[derive(Debug, Clone)]
pub struct Signer {
    key: SigningKey,
}

impl Signer {
    /// Create from a raw 32-byte private key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
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

    /// Sign a Filecoin transaction (Blake2b-256 hash then ECDSA).
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = Blake2b256::digest(tx_bytes);
        self.sign_hash(&hash)
    }

    /// Sign a message (Blake2b-256 hash then ECDSA).
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = Blake2b256::digest(message);
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
    /// Create from a [`kobe_fil::DerivedAccount`].
    pub fn from_derived(account: &kobe_fil::DerivedAccount) -> Result<Self, Error> {
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
