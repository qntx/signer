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

pub use ed25519_dalek::Signature;
pub use error::SignError;
pub use signer_primitives::{
    self, EncodeSignedTransaction, ExtractSignableBytes, Sign, SignExt, SignOutput,
};
use signer_primitives::{Ed25519Signer, delegate_ed25519_ctors};
use zeroize::Zeroizing;

/// Solana transaction signer.
///
/// Newtype over [`Ed25519Signer`]. The inner key is zeroized on drop by
/// `ed25519-dalek`.
#[derive(Debug)]
pub struct Signer(Ed25519Signer);

impl Signer {
    delegate_ed25519_ctors!(SignError);

    /// Create from a Base58-encoded keypair (64 bytes: secret || public).
    ///
    /// Standard format used by Phantom, Backpack, and Solflare.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKeypair`] if the Base58 is invalid or the
    /// decoded length is not 64 bytes.
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
        let signer = Self::from_bytes(&secret)?;
        secret.fill(0);
        Ok(signer)
    }

    /// Solana address (Base58-encoded 32-byte public key).
    #[must_use]
    pub fn address(&self) -> String {
        bs58::encode(self.0.public_key_bytes()).into_string()
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key_bytes()
    }

    /// Public key in hex (64 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.0.public_key_hex()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no hashing or prefixing).
    ///
    /// Returns the native [`Signature`]. For the unified
    /// [`SignOutput::Ed25519`] wire form, use [`Sign::sign_message`].
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.0.sign_raw(message)
    }

    /// Verify a 64-byte Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on verification failure.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), SignError> {
        Ok(self.0.verify(msg, signature)?)
    }

    /// Export keypair as Base58 (64 bytes: secret || public).
    #[must_use]
    pub fn keypair_base58(&self) -> Zeroizing<String> {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.0.signing_key().as_bytes());
        buf[32..].copy_from_slice(&self.0.public_key_bytes());
        let encoded = bs58::encode(&buf).into_string();
        buf.fill(0);
        Zeroizing::new(encoded)
    }

    /// Extract the signable message portion from a full serialized Solana
    /// transaction.
    ///
    /// Strips the compact-u16 header and signature slot placeholders.
    ///
    /// Also available via the [`ExtractSignableBytes`] trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is empty or malformed.
    #[allow(clippy::indexing_slicing, reason = "bounds are checked before slicing")]
    pub fn extract_signable_bytes(tx_bytes: &[u8]) -> Result<&[u8], SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::invalid_transaction("empty transaction"));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        let msg_start = header_len + num_sigs * 64;
        if tx_bytes.len() <= msg_start {
            return Err(SignError::invalid_transaction("transaction too short"));
        }
        Ok(&tx_bytes[msg_start..])
    }

    /// Encode a signed transaction by splicing the signature into the first
    /// slot.
    ///
    /// Also available via the [`EncodeSignedTransaction`] trait.
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
            return Err(SignError::invalid_transaction("empty transaction"));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        if num_sigs == 0 {
            return Err(SignError::invalid_transaction("no signature slots"));
        }
        if tx_bytes.len() < header_len + num_sigs * 64 {
            return Err(SignError::invalid_transaction("transaction too short"));
        }
        let mut signed = tx_bytes.to_vec();
        signed[header_len..header_len + 64].copy_from_slice(&signature.to_bytes());
        Ok(signed)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(hash))
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(message))
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.0.sign_output(tx_bytes))
    }
}

impl ExtractSignableBytes for Signer {
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignError> {
        Self::extract_signable_bytes(tx_bytes)
    }
}

impl EncodeSignedTransaction for Signer {
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        let SignOutput::Ed25519(sig_bytes) = *signature else {
            return Err(SignError::invalid_signature(
                "expected Ed25519 signature output",
            ));
        };
        let sig = Signature::from_bytes(&sig_bytes);
        Self::encode_signed_transaction(tx_bytes, &sig)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_svm::SvmAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_svm::SvmAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), SignError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 3 {
            return Err(SignError::invalid_transaction(
                "compact-u16 exceeds 3 bytes",
            ));
        }
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(SignError::invalid_transaction("truncated compact-u16"))
}

#[cfg(test)]
mod tests;
