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
//! use signer_evm::Signer;
//!
//! let signer = Signer::random();
//! let out = signer.sign_message(b"hello").unwrap();
//! assert_eq!(out.to_bytes().len(), 65); // r(32) + s(32) + v(1)
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

mod eip712;
mod error;
mod rlp;

pub use error::SignError;
use sha3::{Digest, Keccak256};
use signer_primitives::Secp256k1Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// EVM transaction signer.
///
/// Wraps a [`Secp256k1Signer`]. The inner key is zeroized on drop.
pub struct Signer {
    inner: Secp256k1Signer,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Signer {
    /// Create a signer from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Ok(Self {
            inner: Secp256k1Signer::from_bytes(bytes)?,
        })
    }

    /// Create a signer from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or the key is out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        Ok(Self {
            inner: Secp256k1Signer::from_hex(hex_str)?,
        })
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
            inner: Secp256k1Signer::random(),
        }
    }

    /// Ethereum address derived from this signing key (EIP-55 checksummed).
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "uncompressed pubkey is always 65B, Keccak256 is always 32B"
    )]
    pub fn address(&self) -> String {
        let uncompressed = self.inner.uncompressed_public_key();
        let hash = Keccak256::digest(&uncompressed[1..]);
        eip55_checksum(&hex::encode(&hash[12..]))
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.compressed_public_key()
    }

    /// Sign a 32-byte digest with recoverable ECDSA.
    ///
    /// The returned [`SignOutput::Ecdsa`] carries the raw recovery id
    /// (`0` or `1`). Use [`sign_message`](Self::sign_message) or
    /// [`sign_typed_data`](Self::sign_typed_data) if you need EIP-191
    /// semantics (`v = 27 | 28`).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_prehash_recoverable(hash)?)
    }

    /// EIP-191 `personal_sign`. Returns a [`SignOutput::Ecdsa`] with
    /// `recovery_id = 27 | 28`.
    ///
    /// The EVM wire format stores `v = 27 + parity`; the returned
    /// `recovery_id` field already reflects that.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let digest: [u8; 32] = Keccak256::digest(&data).into();
        Ok(bump_v_by_27(self.sign_hash(&digest)?))
    }

    /// Sign EIP-712 typed structured data (JSON input). Returns a
    /// [`SignOutput::Ecdsa`] with `recovery_id = 27 | 28`.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or signing fails.
    pub fn sign_typed_data(&self, typed_data_json: &str) -> Result<SignOutput, SignError> {
        let digest = eip712::hash_typed_data_json(typed_data_json)?;
        Ok(bump_v_by_27(self.sign_hash(&digest)?))
    }

    /// Sign an unsigned typed transaction (EIP-1559 / EIP-2930).
    ///
    /// Returns a [`SignOutput::Ecdsa`] with the **raw** recovery id
    /// (`0 | 1`) — do **not** add 27 when using this output directly in
    /// signed-transaction RLP encoding via
    /// [`encode_signed_transaction`](Self::encode_signed_transaction).
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction bytes are malformed.
    pub fn sign_transaction(&self, unsigned_tx: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Keccak256::digest(unsigned_tx).into();
        self.sign_hash(&digest)
    }

    /// Encode a signed typed transaction: `type || RLP([…fields, v, r, s])`.
    ///
    /// `signature` must be an [`SignOutput::Ecdsa`] produced by
    /// [`sign_transaction`](Self::sign_transaction) (with raw `recovery_id`).
    ///
    /// # Errors
    ///
    /// Returns an error if the unsigned tx or signature variant is malformed.
    pub fn encode_signed_transaction(
        unsigned_tx: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError> {
        let SignOutput::Ecdsa {
            signature: sig,
            recovery_id,
        } = *signature
        else {
            return Err(SignError::InvalidSignature(
                "expected Ecdsa signature output".into(),
            ));
        };
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        rlp::encode_signed_typed_tx(unsigned_tx, recovery_id, &r, &s)
            .map_err(|e| SignError::InvalidTransaction(String::from(e)))
    }
}

/// Bump the `recovery_id` of an [`SignOutput::Ecdsa`] by 27 (EIP-191 v).
fn bump_v_by_27(out: SignOutput) -> SignOutput {
    match out {
        SignOutput::Ecdsa {
            signature,
            recovery_id,
        } => SignOutput::Ecdsa {
            signature,
            recovery_id: recovery_id.wrapping_add(27),
        },
        other => other,
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, Self::Error> {
        Self::sign_hash(self, hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error> {
        Self::sign_message(self, message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Self::Error> {
        Self::sign_transaction(self, tx_bytes)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, Self::Error> {
        Self::encode_signed_transaction(tx_bytes, signature)
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
