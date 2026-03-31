//! Bitcoin transaction signer built on [`k256`] and [`sha2`].
//!
//! Provides secp256k1 ECDSA signing for Bitcoin sighash preimages
//! and BIP-322 / legacy message signing.
//!
//! **Address derivation is handled by [`kobe-btc`] — this crate is signing only.**
//!
//! # Examples
//!
//! ```
//! use signer_btc::Signer;
//!
//! let signer = Signer::random();
//! let hash = [0u8; 32];
//! let sig = signer.sign_hash(&hash).unwrap();
//! assert_eq!(sig.len(), 65); // r(32) + s(32) + recovery_id(1)
//! ```

mod error;

pub use error::Error;
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

/// Bitcoin transaction signer.
///
/// Wraps a secp256k1 signing key. The inner key is zeroized on drop.
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

    /// Sign a 32-byte sighash. Returns 65 bytes: `r(32) || s(32) || recovery_id(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not 32 bytes or the signing primitive fails.
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

    /// Sign a Bitcoin transaction sighash preimage (double-SHA256 then ECDSA).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_transaction(&self, sighash_preimage: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = Sha256::digest(Sha256::digest(sighash_preimage));
        self.sign_hash(&hash)
    }

    /// Sign a message using Bitcoin message signing convention.
    ///
    /// `hash = SHA256(SHA256(prefix || varint(len) || message))`
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let mut data = Vec::with_capacity(prefix.len() + 9 + message.len());
        data.extend_from_slice(prefix);
        encode_compact_size(&mut data, message.len());
        data.extend_from_slice(message);
        let hash = Sha256::digest(Sha256::digest(&data));
        self.sign_hash(&hash)
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

    /// Expose the inner [`SigningKey`].
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_btc::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(addr: &kobe_btc::DerivedAddress) -> Result<Self, Error> {
        Self::from_hex(&addr.private_key_hex)
    }
}

#[allow(clippy::cast_possible_truncation)]
fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    use super::*;

    #[test]
    fn sign_hash_and_verify() {
        let s = Signer::random();
        let hash = Sha256::digest(b"test");
        let sig_bytes = s.sign_hash(&hash).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        let r: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let s_arr: [u8; 32] = sig_bytes[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s_arr).unwrap();
        s.signing_key()
            .verifying_key()
            .verify_prehash(&hash, &sig)
            .unwrap();
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.key.to_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn sign_message_short() {
        let s = Signer::random();
        let sig = s.sign_message(b"Hello Bitcoin!").unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn sign_message_long_varint() {
        let s = Signer::random();
        let msg = vec![0x42u8; 300];
        let sig = s.sign_message(&msg).unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn rejects_wrong_hash_length() {
        let s = Signer::random();
        assert!(s.sign_hash(b"short").is_err());
    }

    #[test]
    fn public_key_is_33_bytes() {
        let s = Signer::random();
        assert_eq!(s.public_key_bytes().len(), 33);
    }
}
