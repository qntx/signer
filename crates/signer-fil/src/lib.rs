//! Filecoin transaction signer built on secp256k1 ECDSA and `BLAKE2b`.
//!
//! Uses the `f1` (protocol-1) address scheme derived from the uncompressed
//! public key, and signs transactions with `BLAKE2b-256` + ECDSA.
//!
//! # Input to [`Sign::sign_transaction`]
//!
//! Per the [Filecoin signatures spec](https://spec.filecoin.io/algorithms/crypto/signatures/),
//! "to generate a signature for the `Message` type, compute the signature
//! over the message's CID (taken as a byte array)". Callers are therefore
//! expected to hand this signer the **CID byte array** of their
//! CBOR-encoded `Message` (`CIDv1`, codec `DAG-CBOR`, multihash
//! `BLAKE2b-256`). The signer then computes `BLAKE2b-256(cid_bytes)` as
//! the ECDSA prehash — matching the Zondax `filecoin-signing-tools`
//! `transaction_sign_raw` convention and every on-chain validator.
//!
//! For off-chain scenarios where a Filecoin-specific CID is not
//! meaningful, callers may pass any payload they like and interpret the
//! signature accordingly; the wrapper places no restriction on the
//! input bytes.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use blake2::digest::consts::{U4, U20, U32};
use blake2::{Blake2b, Digest};
pub use signer_primitives::{
    self, Sign, SignError, SignExt, SignMessage, SignMessageExt, SignOutput,
};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

type Blake2b256 = Blake2b<U32>;
type Blake2b160 = Blake2b<U20>;
type Blake2b4 = Blake2b<U4>;

/// Filecoin transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Filecoin protocol-1 (secp256k1) address (`f1…`).
    ///
    /// Computed as `"f1" + base32_lower(BLAKE2b-160(uncompressed_pubkey) || BLAKE2b-4(0x01 || payload))`.
    #[must_use]
    pub fn address(&self) -> String {
        let uncompressed = self.0.uncompressed_public_key();
        let payload = Blake2b160::digest(&uncompressed);
        let mut checksum_input = Vec::with_capacity(1 + payload.len());
        checksum_input.push(0x01); // protocol 1
        checksum_input.extend_from_slice(&payload);
        let checksum = Blake2b4::digest(&checksum_input);
        let mut addr_bytes = Vec::with_capacity(payload.len() + checksum.len());
        addr_bytes.extend_from_slice(&payload);
        addr_bytes.extend_from_slice(&checksum);
        let encoded = base32_lower_encode(&addr_bytes);
        format!("f1{encoded}")
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
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(hash)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Blake2b256::digest(tx_bytes).into();
        self.0.sign_prehash_recoverable(&digest)
    }
}

impl SignMessage for Signer {
    /// BLAKE2b-256 of the raw message bytes, signed with secp256k1 ECDSA.
    ///
    /// No domain prefix is applied — Filecoin's wallet ecosystem does not
    /// specify a canonical off-chain message framing; callers who need one
    /// should hash their own preimage and call [`Sign::sign_hash`].
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Blake2b256::digest(message).into();
        self.0.sign_prehash_recoverable(&digest)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_fil::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_fil::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// RFC 4648 base32 lowercase encoding without padding.
#[allow(
    clippy::indexing_slicing,
    reason = "idx is masked with 0x1F, always < 32 = ALPHABET.len()"
)]
fn base32_lower_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "masked with 0x1F, always <= 31"
            )]
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "masked with 0x1F, always <= 31"
        )]
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests;
