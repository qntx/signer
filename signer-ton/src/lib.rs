//! TON transaction signer built on [`ed25519_dalek`].
//!
//! Provides Ed25519 signing for TON transactions and messages.
//! Address derivation is handled by [`kobe-ton`].

mod error;

pub use ed25519_dalek::{self, Signature};
use ed25519_dalek::{Signer as _, SigningKey};
pub use error::Error;
pub use signer_core::{self, Sign, SignExt, SignOutput};

/// TON transaction signer.
///
/// Wraps an Ed25519 signing key. The inner key is zeroized on drop.
pub struct Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
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

    /// Sign a TON transaction (Ed25519 over raw message bytes).
    #[must_use]
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Signature {
        self.key.sign(tx_bytes)
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

    /// Public key in hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }
}

impl Sign for Signer {
    type Error = Error;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, Error> {
        use ed25519_dalek::Signer as _;
        let sig = self.key.sign(hash);
        Ok(SignOutput::ed25519(sig.to_bytes().to_vec()))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Error> {
        self.sign_hash(message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Error> {
        self.sign_hash(tx_bytes)
    }
}
#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_ton::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_ton::DerivedAccount) -> Result<Self, Error> {
        Self::from_hex(&account.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 Test Vector 1
    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_PUBKEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn test_signer() -> Signer {
        Signer::from_hex(TEST_KEY).unwrap()
    }

    #[test]
    fn rfc8032_pubkey() {
        assert_eq!(test_signer().public_key_hex(), TEST_PUBKEY);
    }

    #[test]
    fn from_bytes_matches_from_hex() {
        let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
        let s = Signer::from_bytes(&bytes);
        assert_eq!(s.public_key_bytes(), test_signer().public_key_bytes());
    }

    #[test]
    fn sign_and_verify() {
        let s = test_signer();
        let msg = b"hello TON";
        let sig = s.sign(msg);
        s.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn sign_wrong_message_fails() {
        let s = test_signer();
        let sig = s.sign(b"correct");
        assert!(s.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn sign_trait_verify() {
        let s = test_signer();
        let out = Sign::sign_message(&s, b"test").unwrap();
        assert_eq!(out.signature.len(), 64);
        assert!(out.recovery_id.is_none());
        let sig = Signature::from_slice(&out.signature).unwrap();
        s.verify(b"test", &sig)
            .expect("trait signature must verify");
    }

    #[test]
    fn deterministic_signature() {
        let s = test_signer();
        let s1 = s.sign(b"deterministic");
        let s2 = s.sign(b"deterministic");
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", test_signer());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("9d61b1"));
    }
}
