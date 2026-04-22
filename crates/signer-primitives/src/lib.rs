//! Unified signing trait and types for multi-chain transaction signers.
//!
//! This crate defines the [`Sign`] trait that all chain-specific signer crates
//! implement, plus shared types like [`SignOutput`] and [`SignError`].
//!
//! Mirrors the role of `kobe-core` for derivation — this is the equivalent
//! for signing.
//!
//! # Design
//!
//! - **Stateful signers** — each `Signer` holds its private key internally.
//! - **`Send + Sync`** — signers are safe to share across threads and async runtimes.
//! - **No address derivation** — that's `kobe`'s responsibility.
//! - **Associated error type** — matches kobe's `Derive` trait pattern.
//! - **[`SignExt`]** — blanket extension trait (like kobe's `DeriveExt`).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(feature = "ed25519")]
mod ed25519;
mod error;
mod macros;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "testing")]
pub mod testing;

#[cfg(feature = "ed25519")]
pub use ed25519::Ed25519Signer;
pub use error::SignError;
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Signer;

/// Internal re-exports used by exported macros. Not a stable public API.
#[doc(hidden)]
pub mod __private {
    pub use alloc::string::String;

    pub use hex::FromHexError;
}

/// Output of a signing operation.
///
/// Unified across all chains. Secp256k1 chains populate `recovery_id`;
/// Ed25519 chains leave it `None`. Chains like Sui that include the public
/// key in their wire format populate `public_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutput {
    /// Raw signature bytes (65 for secp256k1 r‖s‖v, 64 for Ed25519).
    pub signature: Vec<u8>,
    /// Recovery ID (secp256k1 only; `None` for Ed25519).
    pub recovery_id: Option<u8>,
    /// Public key bytes (only set by chains that need it in the wire format).
    pub public_key: Option<Vec<u8>>,
}

impl SignOutput {
    /// Create a secp256k1 sign output (65 bytes: r‖s‖v).
    #[must_use]
    pub const fn secp256k1(signature: Vec<u8>, recovery_id: u8) -> Self {
        Self {
            signature,
            recovery_id: Some(recovery_id),
            public_key: None,
        }
    }

    /// Create an Ed25519 sign output (64 bytes).
    #[must_use]
    pub const fn ed25519(signature: Vec<u8>) -> Self {
        Self {
            signature,
            recovery_id: None,
            public_key: None,
        }
    }

    /// Create an Ed25519 sign output with public key attached.
    #[must_use]
    pub const fn ed25519_with_pubkey(signature: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            signature,
            recovery_id: None,
            public_key: Some(public_key),
        }
    }
}

/// Unified signing trait implemented by all chain signers.
///
/// Each chain crate (`signer-evm`, `signer-btc`, etc.) implements this
/// trait on its `Signer` type. The signer holds the private key internally.
///
/// **Thread-safety**: all signers must be `Send + Sync` for use in async
/// runtimes and multi-threaded applications.
///
/// Extension methods are provided by the blanket [`SignExt`] trait.
///
/// # Example
///
/// ```
/// use signer_primitives::{Sign, SignOutput};
///
/// fn sign_with_any<S: Sign>(signer: &S, msg: &[u8]) -> SignOutput {
///     signer.sign_message(msg).unwrap()
/// }
/// ```
pub trait Sign: Send + Sync {
    /// The error type returned by signing operations.
    type Error: core::fmt::Debug + core::fmt::Display + From<SignError> + Send + Sync;

    /// Sign a pre-hashed digest.
    ///
    /// For secp256k1: expects exactly 32 bytes.
    /// For Ed25519: signs the raw bytes (no pre-hashing required).
    ///
    /// # Errors
    ///
    /// Returns an error if the hash length is wrong or the signing primitive fails.
    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, Self::Error>;

    /// Sign an arbitrary message with chain-specific prefixing/hashing.
    ///
    /// - EVM: EIP-191 `personal_sign`
    /// - Bitcoin: `\x18Bitcoin Signed Message:\n` prefix
    /// - TRON: `\x19TRON Signed Message:\n` prefix
    /// - Solana/TON: raw Ed25519 sign
    /// - Sui: intent prefix + BCS + BLAKE2b-256
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error>;

    /// Sign an unsigned transaction.
    ///
    /// Each chain hashes the transaction bytes according to its own rules
    /// before signing.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is malformed or signing fails.
    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Self::Error>;

    /// Extract the signable portion from a full serialized transaction.
    ///
    /// Some wire formats include non-signed metadata (e.g. Solana prepends
    /// signature-slot placeholders). This method strips that metadata and
    /// returns only the bytes that must be signed.
    ///
    /// The default implementation returns the input unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is malformed.
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], Self::Error> {
        Ok(tx_bytes)
    }

    /// Encode a signed transaction from unsigned bytes + signature output.
    ///
    /// Returns bytes suitable for broadcasting to the network.
    ///
    /// The default returns `Err` — chains that support encoding must override.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding is not supported or inputs are malformed.
    fn encode_signed_transaction(
        &self,
        _tx_bytes: &[u8],
        _signature: &SignOutput,
    ) -> Result<Vec<u8>, Self::Error> {
        Err(
            SignError::InvalidTransaction("encode_signed_transaction not implemented".into())
                .into(),
        )
    }
}

/// Extension trait providing additional operations for all [`Sign`] implementors.
///
/// Automatically implemented for any type implementing `Sign`.
pub trait SignExt: Sign {
    /// Sign a hash and return only the raw signature bytes (discarding metadata).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_hash_bytes(&self, hash: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_hash(hash).map(|out| out.signature)
    }

    /// Sign a transaction and return only the raw signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_transaction_bytes(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_transaction(tx_bytes).map(|out| out.signature)
    }
}

impl<T: Sign> SignExt for T {}
