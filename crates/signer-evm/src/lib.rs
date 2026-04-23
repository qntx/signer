//! EVM transaction signer built on `k256` and [`sha3`].
//!
//! Provides EIP-191 personal signing, EIP-712 typed data signing,
//! and typed transaction signing with RLP encoding.
//!
//! **No alloy dependency.** Pure cryptographic primitives only.
//!
//! # Examples
//!
//! ```
//! use signer_evm::{SignMessage as _, Signer};
//!
//! let signer = Signer::random();
//! let out = signer.sign_message(b"hello").unwrap();
//! assert_eq!(out.to_bytes().len(), 65); // r(32) + s(32) + v(1)
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

mod eip712;
mod rlp;

use sha3::{Digest, Keccak256};
pub use signer_primitives::{
    self, EncodeSignedTransaction, Sign, SignError, SignExt, SignMessage, SignMessageExt,
    SignOutput,
};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// EVM transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Ethereum address derived from this signing key (EIP-55 checksummed).
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "uncompressed pubkey is always 65B, Keccak256 is always 32B"
    )]
    pub fn address(&self) -> String {
        let uncompressed = self.0.uncompressed_public_key();
        let hash = Keccak256::digest(&uncompressed[1..]);
        eip55_checksum(&hex::encode(&hash[12..]))
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.compressed_public_key())
    }

    /// Verify an ECDSA signature against a 32-byte pre-hashed digest.
    ///
    /// Accepts 64-byte (`r || s`) or 65-byte (`r || s || v`) input;
    /// the `v` byte is ignored for verification.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on malformed input or
    /// failed verification.
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8]) -> Result<(), SignError> {
        self.0.verify_prehash_any(hash, signature)
    }

    /// Sign EIP-712 typed structured data (JSON input). Returns a
    /// [`SignOutput::Ecdsa`] with `v = 27 | 28`.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or signing fails.
    pub fn sign_typed_data(&self, typed_data_json: &str) -> Result<SignOutput, SignError> {
        let digest = eip712::hash_typed_data_json(typed_data_json)?;
        Ok(bump_v_by_27(self.0.sign_prehash_recoverable(&digest)?))
    }

    /// Encode a signed typed transaction: `type || RLP([…fields, v, r, s])`.
    ///
    /// `signature` must be a [`SignOutput::Ecdsa`] produced by
    /// [`sign_transaction`](Sign::sign_transaction) (with raw `v = 0 | 1`).
    ///
    /// Also available via the [`EncodeSignedTransaction`] trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the unsigned tx or signature variant is malformed.
    pub fn encode_signed_transaction(
        unsigned_tx: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        let SignOutput::Ecdsa { signature: sig, v } = *signature else {
            return Err(SignError::InvalidSignature(
                "expected Ecdsa signature output".into(),
            ));
        };
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        rlp::encode_signed_typed_tx(unsigned_tx, v, &r, &s)
            .map_err(|e| SignError::InvalidTransaction(String::from(e)))
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(hash)
    }

    /// Sign an unsigned typed transaction (EIP-1559 / EIP-2930).
    ///
    /// Returns a [`SignOutput::Ecdsa`] with the **raw** `v` byte (`0 | 1`) —
    /// do **not** add 27 when feeding the result into
    /// [`Signer::encode_signed_transaction`].
    fn sign_transaction(&self, unsigned_tx: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Keccak256::digest(unsigned_tx).into();
        self.0.sign_prehash_recoverable(&digest)
    }
}

impl SignMessage for Signer {
    /// EIP-191 `personal_sign`. Returns a [`SignOutput::Ecdsa`] with
    /// `v = 27 | 28`.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let digest: [u8; 32] = Keccak256::digest(&data).into();
        Ok(bump_v_by_27(self.0.sign_prehash_recoverable(&digest)?))
    }
}

impl EncodeSignedTransaction for Signer {
    fn encode_signed_transaction(
        &self,
        unsigned_tx: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        Self::encode_signed_transaction(unsigned_tx, signature)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_evm::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_evm::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// Bump the `v` byte of an [`SignOutput::Ecdsa`] by 27 (EIP-191 encoding).
fn bump_v_by_27(out: SignOutput) -> SignOutput {
    match out {
        SignOutput::Ecdsa { signature, v } => SignOutput::Ecdsa {
            signature,
            v: v.wrapping_add(27),
        },
        other => other,
    }
}

fn eip55_checksum(addr_hex: &str) -> String {
    let lower = addr_hex.to_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());
    let hash_hex = hex::encode(hash);

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = u8::from_str_radix(&hash_hex[i..=i], 16).unwrap_or(0);
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
    }
    out
}

#[cfg(test)]
mod tests;
