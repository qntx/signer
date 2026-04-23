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

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

use crate::{SignError, SignOutput};

/// Digest length (all chains sign 32-byte hashes).
pub(crate) const DIGEST_LEN: usize = 32;

/// Shared secp256k1 ECDSA signer.
///
/// Loads a private key, exposes public-key material, and produces either
/// 65-byte recoverable or DER-encoded signatures. Zeroized on drop.
///
/// # Example
///
/// ```
/// use signer_primitives::Secp256k1Signer;
///
/// let signer = Secp256k1Signer::from_hex(
///     "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
/// )?;
/// assert_eq!(signer.compressed_public_key().len(), 33);
/// assert_eq!(signer.uncompressed_public_key().len(), 65);
///
/// let out = signer.sign_prehash_recoverable(&[0u8; 32])?;
/// assert_eq!(out.to_bytes().len(), 65); // r(32) + s(32) + recovery_id(1)
/// # Ok::<_, signer_primitives::SignError>(())
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
    /// Returns a [`SignOutput::Ecdsa`] variant with a 64-byte compact signature
    /// and a `0 | 1` recovery id.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if the signing primitive fails.
    pub fn sign_prehash_recoverable(
        &self,
        hash: &[u8; DIGEST_LEN],
    ) -> Result<SignOutput, SignError> {
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(hash)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;
        let sig_bytes = sig.to_bytes();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);
        Ok(SignOutput::Ecdsa {
            signature,
            v: rid.to_byte(),
        })
    }

    /// Sign a 32-byte pre-hashed digest and return a DER-encoded signature.
    ///
    /// Variable length (typically 70–72 bytes). No recovery id.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if the signing primitive fails.
    pub fn sign_prehash_der(&self, hash: &[u8; DIGEST_LEN]) -> Result<SignOutput, SignError> {
        let sig: Signature = self
            .key
            .sign_prehash(hash)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;
        Ok(SignOutput::EcdsaDer(sig.to_der().as_bytes().to_vec()))
    }

    /// Verify a recoverable / compact ECDSA signature against a 32-byte
    /// pre-hashed digest.
    ///
    /// Accepts either 64-byte (`r || s`) or 65-byte (`r || s || v`) input;
    /// the recovery id is ignored for verification purposes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] if the bytes are malformed or
    /// fail verification.
    pub fn verify_prehash(
        &self,
        hash: &[u8; DIGEST_LEN],
        signature: &[u8],
    ) -> Result<(), SignError> {
        let sig_bytes = match signature.len() {
            64 | 65 => signature.get(..64).unwrap_or_default(),
            n => {
                return Err(SignError::InvalidSignature(format!(
                    "expected 64 or 65 bytes, got {n}"
                )));
            }
        };
        let sig = Signature::from_slice(sig_bytes)
            .map_err(|e| SignError::InvalidSignature(e.to_string()))?;
        self.key
            .verifying_key()
            .verify_prehash(hash, &sig)
            .map_err(|e| SignError::InvalidSignature(e.to_string()))
    }
}
