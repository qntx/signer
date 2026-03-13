//! Solana transaction signer built on [`ed25519-dalek`].
//!
//! This crate provides a [`Signer`] that wraps [`ed25519_dalek::SigningKey`],
//! adding convenient constructors, Base58 address/keypair support, and
//! optional [`kobe`](https://github.com/qntx/kobe) wallet bridging.
//!
//! **Zero hand-rolled cryptography.**
//!
//! # Exposed signing methods
//!
//! | Method | Description |
//! |---|---|
//! | [`Signer::sign`] | Ed25519 signature on arbitrary bytes |
//! | [`Signer::verify`] | Verify an Ed25519 signature |

mod error;

pub use ed25519_dalek::{self, Signature, VerifyingKey};
use ed25519_dalek::{Signer as DalekSigner, SigningKey, Verifier};
pub use error::Error;
use zeroize::Zeroizing;

/// Solana transaction signer.
///
/// A thin wrapper around [`ed25519_dalek::SigningKey`] that delegates all
/// cryptographic operations to the `ed25519-dalek` crate.
///
/// # Examples
///
/// ```
/// use signer_svm::Signer;
///
/// let signer = Signer::random();
/// let sig = signer.sign(b"hello solana");
/// signer.verify(b"hello solana", &sig).unwrap();
/// ```
#[derive(Debug)]
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Create a signer from raw 32-byte secret key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Create a signer from a hex-encoded 32-byte private key.
    ///
    /// Compatible with [`kobe_svm::DerivedAddress::private_key_hex`] output.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the key length is wrong.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidPrivateKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Create a signer from a Base58-encoded keypair (64 bytes: secret 32B + public 32B).
    ///
    /// This is the standard format used by Phantom, Backpack, and Solflare wallets.
    /// Compatible with [`kobe_svm::DerivedAddress::keypair_base58`] output.
    ///
    /// # Errors
    ///
    /// Returns an error if the Base58 string is invalid or the decoded length
    /// is not 64 bytes.
    pub fn from_keypair_base58(b58: &str) -> Result<Self, Error> {
        let decoded = bs58::decode(b58)
            .into_vec()
            .map_err(|e| Error::InvalidKeypairBase58(e.to_string()))?;

        if decoded.len() != 64 {
            return Err(Error::InvalidKeypairBase58(format!(
                "expected 64 bytes, got {}",
                decoded.len()
            )));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decoded[..32]);
        Ok(Self::from_bytes(&secret))
    }

    /// Generate a random signer.
    #[must_use]
    pub fn random() -> Self {
        use rand_core::OsRng;
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Sign arbitrary bytes with Ed25519.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Verify an Ed25519 signature against this signer's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        self.signing_key.verifying_key().verify(msg, signature)?;
        Ok(())
    }

    /// Get the Ed25519 verifying (public) key.
    #[inline]
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the Solana address (Base58-encoded public key).
    #[must_use]
    pub fn address(&self) -> String {
        bs58::encode(self.signing_key.verifying_key().as_bytes()).into_string()
    }

    /// Get the public key in hex format.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Export the keypair as Base58 (64 bytes: secret 32B + public 32B).
    ///
    /// This is the standard format used by Phantom, Backpack, and Solflare wallets.
    #[must_use]
    pub fn keypair_base58(&self) -> Zeroizing<String> {
        let verifying = self.signing_key.verifying_key();
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(self.signing_key.as_bytes());
        keypair_bytes[32..].copy_from_slice(verifying.as_bytes());
        let encoded = bs58::encode(&keypair_bytes).into_string();
        keypair_bytes.fill(0);
        Zeroizing::new(encoded)
    }

    /// Get a reference to the inner [`SigningKey`].
    #[inline]
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
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
    use super::*;

    #[test]
    fn test_random_signer() {
        let signer = Signer::random();
        let addr = signer.address();
        assert!(addr.len() >= 32 && addr.len() <= 44);
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let signer = Signer::random();
        let hex_key = hex::encode(signer.signing_key.as_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(signer.address(), restored.address());
    }

    #[test]
    fn test_from_keypair_base58_roundtrip() {
        let signer = Signer::random();
        let b58 = signer.keypair_base58();
        let restored = Signer::from_keypair_base58(&b58).unwrap();
        assert_eq!(signer.address(), restored.address());
    }

    #[test]
    fn test_from_bytes() {
        let key = [42u8; 32];
        let signer1 = Signer::from_bytes(&key);
        let signer2 = Signer::from_bytes(&key);
        assert_eq!(signer1.address(), signer2.address());
    }

    #[test]
    fn test_sign_and_verify() {
        let signer = Signer::random();
        let msg = b"hello solana";
        let sig = signer.sign(msg);
        signer.verify(msg, &sig).unwrap();
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let signer = Signer::random();
        let sig = signer.sign(b"correct");
        assert!(signer.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn test_public_key_hex() {
        let signer = Signer::random();
        let hex_pk = signer.public_key_hex();
        assert_eq!(hex_pk.len(), 64);
    }
}
