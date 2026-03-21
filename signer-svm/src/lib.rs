//! Solana transaction signer built on [`ed25519-dalek`].
//!
//! [`Signer`] wraps an [`ed25519_dalek::SigningKey`], adding Base58 address
//! support, keypair import/export, and convenient constructors.
//!
//! **Zero hand-rolled cryptography.**
//!
//! # Signing
//!
//! `Signer` implements `Deref<Target = SigningKey>`, so all
//! [`ed25519_dalek::Signer`](ed25519_dalek::Signer) methods are available
//! directly (e.g. `signer.sign(msg)`).
//!
//! | Method | Description |
//! |---|---|
//! | `sign` (via Deref) | Ed25519 signature on arbitrary bytes |
//! | [`Signer::verify`] | Verify an Ed25519 signature |
//! | [`Signer::sign_transaction_message`] | Sign serialized Solana tx message bytes |

mod error;

use core::ops::Deref;

pub use ed25519_dalek::{self, Signature, VerifyingKey};
use ed25519_dalek::{SigningKey, Verifier};
pub use error::Error;
use zeroize::Zeroizing;

/// Solana transaction signer.
///
/// Wraps an [`ed25519_dalek::SigningKey`] with [`Deref`] for full upstream
/// access. The inner key implements [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop).
///
/// # Examples
///
/// ```
/// use signer_svm::Signer;
/// use ed25519_dalek::Signer as _;
///
/// let signer = Signer::random();
/// let sig = signer.sign(b"hello solana");
/// signer.verify(b"hello solana", &sig).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct Signer {
    key: SigningKey,
}

impl Deref for Signer {
    type Target = SigningKey;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Signer {
    /// Create a signer from raw 32-byte secret key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }

    /// Create a signer from a hex-encoded 32-byte private key.
    ///
    /// Accepts keys with or without `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the key length is wrong.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Create a signer from a Base58-encoded keypair (64 bytes: secret ‖ public).
    ///
    /// This is the standard format used by Phantom, Backpack, and Solflare.
    ///
    /// # Errors
    ///
    /// Returns an error if the Base58 string is invalid or not 64 bytes.
    pub fn from_keypair_base58(b58: &str) -> Result<Self, Error> {
        let decoded = bs58::decode(b58)
            .into_vec()
            .map_err(|e| Error::InvalidKeypair(e.to_string()))?;

        if decoded.len() != 64 {
            return Err(Error::InvalidKeypair(format!(
                "expected 64 bytes, got {}",
                decoded.len()
            )));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decoded[..32]);
        let signer = Self::from_bytes(&secret);
        secret.fill(0);
        Ok(signer)
    }

    /// Generate a random signer.
    ///
    /// # Panics
    ///
    /// Panics if the system CSPRNG is unavailable.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("system CSPRNG unavailable");
        let signer = Self::from_bytes(&bytes);
        bytes.fill(0);
        signer
    }

    /// Verify an Ed25519 signature against this signer's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        self.key.verifying_key().verify(msg, signature)?;
        Ok(())
    }

    /// Sign serialized Solana transaction message bytes.
    ///
    /// A Solana transaction signature is an Ed25519 signature over the
    /// serialized message. Use this with any serialization method
    /// (e.g. `solana-sdk`, `solana-transaction`).
    #[must_use]
    pub fn sign_transaction_message(&self, message_bytes: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        self.key.sign(message_bytes)
    }

    /// Get the Solana address (Base58-encoded 32-byte public key).
    #[must_use]
    pub fn address(&self) -> String {
        bs58::encode(self.key.verifying_key().as_bytes()).into_string()
    }

    /// Get the public key in hex format.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    /// Export the keypair as Base58 (64 bytes: secret ‖ public).
    ///
    /// Compatible with Phantom, Backpack, and Solflare wallet format.
    #[must_use]
    pub fn keypair_base58(&self) -> Zeroizing<String> {
        let vk = self.key.verifying_key();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.key.as_bytes());
        buf[32..].copy_from_slice(vk.as_bytes());
        let encoded = bs58::encode(&buf).into_string();
        buf.fill(0);
        Zeroizing::new(encoded)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_svm::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key hex is invalid.
    pub fn from_derived(derived: &kobe_svm::DerivedAddress) -> Result<Self, Error> {
        Self::from_hex(&derived.private_key_hex)
    }

    /// Create a signer from a [`kobe_svm::StandardWallet`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key hex is invalid.
    pub fn from_standard_wallet(wallet: &kobe_svm::StandardWallet) -> Result<Self, Error> {
        Self::from_hex(&wallet.secret_hex())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;

    #[test]
    fn assert_send_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<Signer>();
    }

    #[test]
    fn assert_clone() {
        let s = Signer::random();
        let s2 = s.clone();
        assert_eq!(s.address(), s2.address());
    }

    #[test]
    fn random_address() {
        let s = Signer::random();
        let addr = s.address();
        assert!(addr.len() >= 32 && addr.len() <= 44);
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.key.as_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.address(), restored.address());
    }

    #[test]
    fn keypair_base58_roundtrip() {
        let s = Signer::random();
        let b58 = s.keypair_base58();
        let restored = Signer::from_keypair_base58(&b58).unwrap();
        assert_eq!(s.address(), restored.address());
    }

    #[test]
    fn from_bytes_deterministic() {
        let key = [42u8; 32];
        assert_eq!(
            Signer::from_bytes(&key).address(),
            Signer::from_bytes(&key).address()
        );
    }

    #[test]
    fn sign_and_verify() {
        let s = Signer::random();
        let sig = s.sign(b"hello solana");
        s.verify(b"hello solana", &sig).unwrap();
    }

    #[test]
    fn verify_wrong_message_fails() {
        let s = Signer::random();
        let sig = s.sign(b"correct");
        assert!(s.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn sign_transaction_message() {
        let s = Signer::random();
        let fake_msg = [0u8; 128];
        let sig = s.sign_transaction_message(&fake_msg);
        s.verify(&fake_msg, &sig).unwrap();
    }

    #[test]
    fn public_key_hex_length() {
        let s = Signer::random();
        assert_eq!(s.public_key_hex().len(), 64);
    }

    #[test]
    fn deref_to_signing_key() {
        let s = Signer::random();
        let _vk: VerifyingKey = s.verifying_key();
    }
}
