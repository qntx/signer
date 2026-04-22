//! Reusable Ed25519 signing primitive shared by all ed25519-dalek-backed chains.
//!
//! Wraps [`ed25519_dalek::SigningKey`] and provides the common boilerplate
//! (key loading, public-key extraction, `sign_raw`, `verify`) that every
//! Ed25519 chain needs. Chain crates compose this into their own `Signer`
//! newtype and layer chain-specific address derivation and intent/domain
//! prefixing on top.
//!
//! Unlike [`Secp256k1Signer`](crate::Secp256k1Signer), Ed25519 key material
//! is already zeroized on drop by `ed25519-dalek` itself, so no additional
//! [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop) impl is required.

use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, vec::Vec};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::SignError;

/// Shared Ed25519 signer.
///
/// Loads a 32-byte secret key, exposes the derived public key, and produces
/// standard 64-byte Ed25519 signatures via deterministic RFC 8032 signing.
/// The inner [`SigningKey`] zeroizes itself on drop.
///
/// Chain crates typically wrap this in a newtype:
///
/// ```ignore
/// use signer_primitives::Ed25519Signer;
/// pub struct Signer { inner: Ed25519Signer }
/// ```
pub struct Ed25519Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Ed25519Signer {
    /// Create from raw 32-byte secret key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }

    /// Create from a hex-encoded 32-byte secret key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the hex is malformed or not
    /// exactly 32 bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let decoded = hex::decode(stripped).map_err(|e| SignError::InvalidKey(e.to_string()))?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            SignError::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Generate a random signer using OS-provided entropy.
    ///
    /// # Panics
    ///
    /// Panics if the OS random number generator fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    #[allow(clippy::expect_used, reason = "getrandom failure is unrecoverable")]
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let signer = Self::from_bytes(&bytes);
        bytes.fill(0);
        signer
    }

    /// Expose the inner [`SigningKey`].
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Expose the derived [`VerifyingKey`].
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Public-key bytes (32 bytes, raw Ed25519 point encoding).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }

    /// Public key in hex (64 characters, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    /// Sign arbitrary bytes with raw Ed25519 (no prefix or hashing).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.key.sign(message)
    }

    /// Verify an Ed25519 signature against this signer's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.key.verifying_key().verify(message, signature)
    }
}
