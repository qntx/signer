//! EVM transaction signer built on [`alloy-signer-local`].
//!
//! [`Signer`] wraps a [`PrivateKeySigner`] with [`Deref`](core::ops::Deref)
//! for full alloy API access. The inner key is `ZeroizeOnDrop`.
//!
//! **Zero hand-rolled cryptography.**
//!
//! # Signing methods (via `Deref` to `PrivateKeySigner`)
//!
//! | Method | Standard |
//! |---|---|
//! | `sign_hash_sync` / `sign_hash` | Raw 32-byte hash |
//! | `sign_message_sync` / `sign_message` | EIP-191 personal_sign |
//! | `sign_typed_data_sync` / `sign_typed_data` | EIP-712 |
//! | `sign_transaction_sync` / `sign_transaction` | All EVM tx types |
//! | `address` | Signer's Ethereum address |
//! | `chain_id` / `set_chain_id` | EIP-155 chain ID |

mod error;

use core::ops::{Deref, DerefMut};

pub use alloy_consensus;
pub use alloy_network;
pub use alloy_network::{TxSigner, TxSignerSync};
pub use alloy_primitives;
pub use alloy_primitives::{Address, B256, ChainId, U256};
pub use alloy_signer;
pub use alloy_signer::{Signature, Signer as AlloySigner, SignerSync};
pub use alloy_signer_local;
use alloy_signer_local::PrivateKeySigner;
pub use error::Error;

/// EVM transaction signer.
///
/// Wraps a [`PrivateKeySigner`] with [`Deref`] for full alloy API access.
/// The inner `k256::SigningKey` implements `ZeroizeOnDrop`.
///
/// # Examples
///
/// ```no_run
/// use signer_evm::{Signer, SignerSync};
///
/// let signer = Signer::random();
/// let sig = signer.sign_message_sync(b"hello").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct Signer {
    inner: PrivateKeySigner,
}

impl Deref for Signer {
    type Target = PrivateKeySigner;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Signer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<PrivateKeySigner> for Signer {
    #[inline]
    fn from(inner: PrivateKeySigner) -> Self {
        Self { inner }
    }
}

impl From<Signer> for PrivateKeySigner {
    #[inline]
    fn from(signer: Signer) -> Self {
        signer.inner
    }
}

impl Signer {
    /// Create a signer from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid secp256k1 private key.
    pub fn from_bytes(bytes: &B256) -> Result<Self, Error> {
        let inner =
            PrivateKeySigner::from_bytes(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Create a signer from a hex-encoded private key.
    ///
    /// Accepts keys with or without `0x` prefix.
    /// Compatible with [`kobe_evm::DerivedAddress::private_key_hex`] output.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the key is not a valid
    /// secp256k1 private key.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Self::from_bytes(&B256::from(bytes))
    }

    /// Generate a random signer.
    #[must_use]
    pub fn random() -> Self {
        Self {
            inner: PrivateKeySigner::random(),
        }
    }

    /// Consume the wrapper and return the inner [`PrivateKeySigner`].
    #[must_use]
    pub fn into_inner(self) -> PrivateKeySigner {
        self.inner
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_evm::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key in the derived address is invalid.
    pub fn from_derived(derived: &kobe_evm::DerivedAddress) -> Result<Self, Error> {
        Self::from_hex(&derived.private_key_hex)
    }

    /// Create a signer from a [`kobe_evm::StandardWallet`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_standard_wallet(wallet: &kobe_evm::StandardWallet) -> Result<Self, Error> {
        Self::from_hex(&wallet.secret_hex())
    }
}

#[cfg(test)]
mod tests {
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
    fn random_signer() {
        let s = Signer::random();
        assert_ne!(s.address(), Address::ZERO);
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random();
        let hex_key = hex::encode(s.inner.credential().to_bytes());
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.address(), restored.address());
    }

    #[test]
    fn hex_with_prefix() {
        let s = Signer::random();
        let hex_key = format!("0x{}", hex::encode(s.inner.credential().to_bytes()));
        let restored = Signer::from_hex(&hex_key).unwrap();
        assert_eq!(s.address(), restored.address());
    }

    #[test]
    fn sign_message_sync() {
        let s = Signer::random();
        let sig = s.sign_message_sync(b"hello").unwrap();
        let recovered = sig.recover_address_from_msg("hello").unwrap();
        assert_eq!(recovered, s.address());
    }

    #[test]
    fn sign_hash_sync() {
        let s = Signer::random();
        let hash = B256::from([0xab; 32]);
        let sig = s.sign_hash_sync(&hash).unwrap();
        let recovered = sig.recover_address_from_prehash(&hash).unwrap();
        assert_eq!(recovered, s.address());
    }

    #[test]
    fn into_inner() {
        let s = Signer::random();
        let addr = s.address();
        let inner = s.into_inner();
        assert_eq!(inner.address(), addr);
    }

    #[test]
    fn from_private_key_signer() {
        let pks = PrivateKeySigner::random();
        let addr = pks.address();
        let s = Signer::from(pks);
        assert_eq!(s.address(), addr);
    }
}
