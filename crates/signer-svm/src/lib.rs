//! Solana transaction signer built on Ed25519 (RFC 8032).
//!
//! Provides Solana's compact-u16 transaction envelope parsing,
//! signed transaction encoding, and the Phantom/Backpack Base58 keypair
//! format (`secret || public`).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};

mod error;

pub use ed25519_dalek::{self, Signature};
pub use error::SignError;
use signer_primitives::Ed25519Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};
use zeroize::Zeroizing;

/// Solana transaction signer.
///
/// Wraps an [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
pub struct Signer {
    inner: Ed25519Signer,
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
            inner: Ed25519Signer::from_bytes(bytes),
        }
    }

    /// Create from a hex-encoded 32-byte private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or not 32 bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        Ok(Self {
            inner: Ed25519Signer::from_hex(hex_str)?,
        })
    }

    /// Create from a Base58-encoded keypair (64 bytes: secret || public).
    ///
    /// Standard format used by Phantom, Backpack, and Solflare.
    ///
    /// # Errors
    ///
    /// Returns an error if the Base58 is invalid or not 64 bytes.
    #[allow(
        clippy::indexing_slicing,
        reason = "length is checked to be exactly 64 before slicing"
    )]
    pub fn from_keypair_base58(b58: &str) -> Result<Self, SignError> {
        let decoded = bs58::decode(b58)
            .into_vec()
            .map_err(|e| SignError::InvalidKeypair(e.to_string()))?;
        if decoded.len() != 64 {
            return Err(SignError::InvalidKeypair(format!(
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
    /// Panics if the OS random number generator fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn random() -> Self {
        Self {
            inner: Ed25519Signer::random(),
        }
    }

    /// Solana address (Base58-encoded 32-byte public key).
    #[must_use]
    pub fn address(&self) -> String {
        bs58::encode(self.inner.public_key_bytes()).into_string()
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes()
    }

    /// Public key in hex (64 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no hashing or prefixing).
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.inner.sign_raw(message)
    }

    /// Sign serialized Solana transaction message bytes.
    #[must_use]
    pub fn sign_transaction_message(&self, message_bytes: &[u8]) -> Signature {
        self.sign_raw(message_bytes)
    }

    /// Verify an Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignError> {
        self.inner.verify(msg, signature)?;
        Ok(())
    }

    /// Export keypair as Base58 (64 bytes: secret || public).
    #[must_use]
    pub fn keypair_base58(&self) -> Zeroizing<String> {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.inner.signing_key().as_bytes());
        buf[32..].copy_from_slice(&self.inner.public_key_bytes());
        let encoded = bs58::encode(&buf).into_string();
        buf.fill(0);
        Zeroizing::new(encoded)
    }

    /// Extract the signable message portion from a full serialized Solana transaction.
    ///
    /// Strips the compact-u16 header and signature slot placeholders.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is empty or malformed.
    #[allow(clippy::indexing_slicing, reason = "bounds are checked before slicing")]
    pub fn extract_signable_bytes(tx_bytes: &[u8]) -> Result<&[u8], SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::InvalidTransaction("empty transaction".into()));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        let msg_start = header_len + num_sigs * 64;
        if tx_bytes.len() <= msg_start {
            return Err(SignError::InvalidTransaction(
                "transaction too short".into(),
            ));
        }
        Ok(&tx_bytes[msg_start..])
    }

    /// Encode a signed transaction by splicing the signature into the first slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is empty or has no signature slots.
    #[allow(clippy::indexing_slicing, reason = "bounds are checked before slicing")]
    pub fn encode_signed_transaction(
        tx_bytes: &[u8],
        signature: &Signature,
    ) -> Result<Vec<u8>, SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::InvalidTransaction("empty transaction".into()));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        if num_sigs == 0 {
            return Err(SignError::InvalidTransaction("no signature slots".into()));
        }
        if tx_bytes.len() < header_len + num_sigs * 64 {
            return Err(SignError::InvalidTransaction(
                "transaction too short".into(),
            ));
        }
        let mut signed = tx_bytes.to_vec();
        signed[header_len..header_len + 64].copy_from_slice(&signature.to_bytes());
        Ok(signed)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8]) -> Result<SignOutput, SignError> {
        let sig = self.inner.sign_raw(hash);
        Ok(SignOutput::ed25519(sig.to_bytes().to_vec()))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_hash(tx_bytes)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignError> {
        Self::extract_signable_bytes(tx_bytes)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        let sig = Signature::from_slice(&signature.signature)
            .map_err(|e| SignError::InvalidTransaction(e.to_string()))?;
        Self::encode_signed_transaction(tx_bytes, &sig)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_svm::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(derived: &kobe_svm::DerivedAddress) -> Result<Self, SignError> {
        let bytes = derived
            .private_key_bytes()
            .map_err(|e| SignError::InvalidKey(alloc::format!("{e}")))?;
        Ok(Self::from_bytes(&bytes))
    }
}

fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), SignError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 3 {
            return Err(SignError::InvalidTransaction(
                "compact-u16 exceeds 3 bytes".into(),
            ));
        }
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(SignError::InvalidTransaction(
        "truncated compact-u16".into(),
    ))
}

#[cfg(test)]
mod tests;
