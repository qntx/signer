//! XRP Ledger transaction signer built on `k256` and [`sha2`].
//!
//! Provides secp256k1 ECDSA signing for XRPL transactions using the
//! SHA-512-half hash algorithm and DER-encoded signatures.
//!
//! Address derivation is handled by `kobe-xrpl`.
//!
//! ## Signing algorithm
//!
//! XRPL single-signing uses a unique hash-then-sign scheme:
//!
//! 1. Prepend the `STX\0` prefix (`0x53545800`) to the serialized transaction
//! 2. Compute SHA-512 and take the first 32 bytes ("SHA-512-half")
//! 3. Sign the 32-byte digest with secp256k1 ECDSA
//! 4. Encode the signature in DER format (variable length, typically 70-72 bytes)
//!
//! ## Message signing
//!
//! XRPL has no canonical off-chain message signing standard (no EIP-191
//! equivalent). [`sign_message`](Signer::sign_message) returns an error.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

mod error;

pub use error::SignError;
use ripemd::{Digest as _, Ripemd160};
use sha2::{Digest, Sha256, Sha512};
use signer_primitives::Secp256k1Signer;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};

/// XRPL single-signing hash prefix: `STX\0` (`0x53545800`).
const STX_PREFIX: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

/// XRP Ledger transaction signer.
///
/// Wraps a [`Secp256k1Signer`]. Produces DER-encoded ECDSA signatures over
/// SHA-512-half digests, matching the XRPL signing specification.
/// The inner key is zeroized on drop.
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
    /// Create from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Ok(Self {
            inner: Secp256k1Signer::from_bytes(bytes)?,
        })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
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

    /// Derive the XRPL classic `r`-address from the signing key.
    #[must_use]
    pub fn address(&self) -> String {
        let pubkey = self.inner.compressed_public_key();
        encode_classic_address(&pubkey)
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.compressed_public_key())
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
        Ok(self.inner.verify_prehash(hash, signature)?)
    }

    /// Sign a 32-byte pre-hashed digest with secp256k1.
    ///
    /// Returns a [`SignOutput::EcdsaDer`] (variable length, typically 70–72 bytes).
    /// Recovery id is not included — XRPL does not use it.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing primitive fails.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_prehash_der(hash)?)
    }

    /// Sign an unsigned XRPL transaction.
    ///
    /// `tx_bytes` must be the raw binary-encoded unsigned transaction fields
    /// (output of the XRPL binary codec, **without** the `STX\0` prefix).
    ///
    /// This method prepends `STX\0`, computes SHA-512-half, then signs.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is empty or signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::InvalidTransaction(
                "transaction bytes must not be empty".into(),
            ));
        }
        let hash = sha512_half_prefixed(&STX_PREFIX, tx_bytes);
        self.sign_hash(&hash)
    }

    /// XRPL has no canonical off-chain message signing standard.
    ///
    /// Always returns an error. Once the community adopts a convention,
    /// this can be implemented.
    ///
    /// # Errors
    ///
    /// Always returns [`SignError::SigningFailed`].
    pub fn sign_message(&self, _message: &[u8]) -> Result<SignOutput, SignError> {
        Err(SignError::SigningFailed(
            "XRPL has no canonical message signing standard".into(),
        ))
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
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_xrpl::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_xrpl::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// XRPL base58 alphabet.
const XRPL_ALPHABET: bs58::Alphabet = *bs58::Alphabet::RIPPLE;

/// XRPL account address version byte.
const ACCOUNT_VERSION: u8 = 0x00;

/// Hash160: SHA-256 then RIPEMD-160.
fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

/// Double SHA-256 (used for checksum).
fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Encode a compressed public key as an XRPL classic `r`-address.
#[allow(
    clippy::indexing_slicing,
    reason = "double_sha256 returns [u8; 32], slicing first 4 is safe"
)]
fn encode_classic_address(compressed_pubkey: &[u8]) -> String {
    let account_id = hash160(compressed_pubkey);
    let mut payload = Vec::with_capacity(25);
    payload.push(ACCOUNT_VERSION);
    payload.extend_from_slice(&account_id);
    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(&payload)
        .with_alphabet(&XRPL_ALPHABET)
        .into_string()
}

/// SHA-512-half: SHA-512 of `prefix || data`, taking the first 32 bytes.
#[allow(
    clippy::indexing_slicing,
    reason = "SHA-512 output is always 64 bytes, slicing first 32 is safe"
)]
fn sha512_half_prefixed(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(data);
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

#[cfg(test)]
mod tests;
