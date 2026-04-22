//! Reusable secp256k1 signing primitive shared by all k256-backed chains.
//!
//! Wraps [`k256::ecdsa::SigningKey`] and provides the common boilerplate
//! (key loading, compressed/uncompressed public key extraction,
//! `sign_prehash`) that every secp256k1 chain needs. Chain crates compose
//! this into their own `Signer` newtype and layer chain-specific address
//! derivation and message/transaction signing on top.

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, vec::Vec};

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

use crate::{SignError, SignOutput};

/// Shared secp256k1 ECDSA signer.
///
/// Loads a private key, exposes public-key material, and produces either
/// 65-byte recoverable or DER-encoded signatures. Zeroized on drop.
///
/// Chain crates typically wrap this in a newtype:
///
/// ```ignore
/// use signer_primitives::Secp256k1Signer;
/// pub struct Signer { inner: Secp256k1Signer }
/// ```
pub struct Secp256k1Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Secp256k1Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ZeroizeOnDrop for Secp256k1Signer {}

impl Secp256k1Signer {
    /// Create from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the bytes are not a valid
    /// secp256k1 scalar (zero or ≥ curve order).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        let key =
            SigningKey::from_slice(bytes).map_err(|e| SignError::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the hex is malformed, not 32
    /// bytes long, or not a valid secp256k1 scalar.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let decoded = hex::decode(stripped).map_err(|e| SignError::InvalidKey(e.to_string()))?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            SignError::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Self::from_bytes(&bytes)
    }

    /// Generate a random signer using OS-provided entropy.
    ///
    /// # Panics
    ///
    /// Panics if the OS random number generator fails or produces an
    /// out-of-range scalar (probability ≈ 2⁻¹²⁸, cryptographically negligible).
    #[cfg(feature = "getrandom")]
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "getrandom failure is unrecoverable; secp256k1 rejection has p ≈ 2⁻¹²⁸"
    )]
    pub fn random() -> Self {
        use zeroize::Zeroize as _;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let key = SigningKey::from_slice(&bytes).expect("invalid random key");
        bytes.zeroize();
        Self { key }
    }

    /// Expose the inner [`SigningKey`].
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Expose the [`VerifyingKey`].
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.key.verifying_key()
    }

    /// Compressed SEC1-encoded public key (33 bytes, leading `0x02` or `0x03`).
    #[must_use]
    pub fn compressed_public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Uncompressed SEC1-encoded public key (65 bytes, leading `0x04`).
    #[must_use]
    pub fn uncompressed_public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Sign a 32-byte pre-hashed digest with recoverable ECDSA.
    ///
    /// Returns 65 bytes: `r(32) || s(32) || recovery_id(1)` where
    /// `recovery_id ∈ {0, 1}`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidMessage`] if `hash` is not exactly 32
    /// bytes, or [`SignError::SigningFailed`] if the signing primitive fails.
    pub fn sign_prehash_recoverable(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        if hash.len() != 32 {
            return Err(SignError::InvalidMessage(format!(
                "expected 32-byte hash, got {}",
                hash.len()
            )));
        }
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(hash)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(rid.to_byte());
        Ok(SignOutput::secp256k1(out, rid.to_byte()))
    }

    /// Sign a 32-byte pre-hashed digest and return a DER-encoded signature.
    ///
    /// Variable length (typically 70–72 bytes). No recovery ID.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidMessage`] if `hash` is not exactly 32
    /// bytes, or [`SignError::SigningFailed`] if the signing primitive fails.
    pub fn sign_prehash_der(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = hash.try_into().map_err(|_| {
            SignError::InvalidMessage(format!("expected 32-byte hash, got {}", hash.len()))
        })?;
        let sig: Signature = self
            .key
            .sign_prehash(&digest)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;
        Ok(SignOutput {
            signature: sig.to_der().as_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }
}
