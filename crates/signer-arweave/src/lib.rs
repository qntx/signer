//! Arweave **ECDSA-only** offline signer (protocol 2.9+).
//!
//! ## Protocol (authoritative)
//!
//! | Step | Algorithm |
//! | --- | --- |
//! | Address | `Base64URL_nopad(SHA-256(compressed 33-byte secp256k1 pubkey))` |
//! | Tx `owner` field | **empty** for ECDSA |
//! | Preimage (format=2) | `deep_hash` of fields **without** owner ([`signature_data_segment_v2_ecdsa`]) |
//! | Deep-hash | recursive **SHA-384** (`ar_deep_hash` / arweave-js `deepHash`) → 48 bytes |
//! | ECDSA digest | `SHA-256(deep_hash_output)` then recoverable ECDSA |
//! | Signature | 65 bytes: `r ‖ s ‖ recovery_id` (`SignOutput::Ecdsa`, `v` raw `0\|1`) |
//! | Tx id | `Base64URL_nopad(SHA-256(sig65))` |
//!
//! Sources: Arweave docs *ECDSA Keys*; `ar_tx.erl` / `ar_wallet.erl` /
//! `secp256k1_nif.erl` (N.2.9.1); arweave-js `origin/master-ec`.
//!
//! ## Scope
//!
//! - Sign digests and deep-hash outputs; optional pure deep-hash helpers.
//! - **Not** RSA, format=1, chunk/Merkle builders, HTTP, or full JSON tx assembly.
//! - No [`SignMessage`](signer_primitives::SignMessage) (no AR ECDSA personal-message standard).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine;
use sha2::{Digest, Sha256, Sha384};
pub use signer_primitives::{self, SignDigest, SignError, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// SHA-384 digest length used by Arweave deep-hash leaves and roots.
pub const DEEP_HASH_LEN: usize = 48;

/// Recoverable ECDSA wire length (`r ‖ s ‖ v`).
pub const SIGNATURE_LEN: usize = 65;

/// Arweave ECDSA transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// **Identity (not HD):** pure function of this private key only.
    /// Multi-path addresses → [`kobe`](https://github.com/qntx/kobe) `kobe-arweave`.
    #[must_use]
    pub fn address(&self) -> String {
        address_from_compressed_pubkey(&self.0.compressed_public_key())
    }

    /// Recovered-owner encoding: `Base64URL(compressed_pk)`.
    ///
    /// On format-2 ECDSA transactions the JSON `owner` field is **empty**;
    /// clients recover this string from the signature when needed.
    #[must_use]
    pub fn owner(&self) -> String {
        owner_from_compressed_pubkey(&self.0.compressed_public_key())
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.0.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x`).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.compressed_public_key())
    }

    /// Sign a deep-hash (or other) message the way the node does:
    /// `SHA-256(msg)` then recoverable ECDSA (`secp256k1_nif:sign/2`).
    ///
    /// Typical `msg` is the 48-byte output of [`deep_hash`] /
    /// [`signature_data_segment_v2_ecdsa`].
    ///
    /// # Errors
    ///
    /// Propagates primitive signing failures.
    pub fn sign_payload(&self, msg: &[u8]) -> Result<SignOutput, SignError> {
        let digest = sha256_32(msg);
        self.sign_digest(&digest)
    }

    /// Verify a 65-byte recoverable signature against `SHA-256(msg)`.
    ///
    /// # Errors
    ///
    /// Malformed signature or verification failure.
    pub fn verify_payload(
        &self,
        msg: &[u8],
        signature_65: &[u8; SIGNATURE_LEN],
    ) -> Result<(), SignError> {
        let digest = sha256_32(msg);
        self.0.verify_prehash_recoverable(&digest, signature_65)
    }

    /// Verify a 65-byte signature against an already-hashed 32-byte digest.
    ///
    /// # Errors
    ///
    /// See [`Secp256k1Signer::verify_prehash_recoverable`].
    pub fn verify_digest(
        &self,
        digest: &[u8; 32],
        signature_65: &[u8; SIGNATURE_LEN],
    ) -> Result<(), SignError> {
        self.0.verify_prehash_recoverable(digest, signature_65)
    }

    /// Transaction id: `Base64URL_nopad(SHA-256(signature_65))`.
    #[must_use]
    pub fn transaction_id(signature_65: &[u8; SIGNATURE_LEN]) -> String {
        base64url_nopad(&sha256_32(signature_65))
    }

    /// Flatten [`SignOutput::Ecdsa`] to 65 wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] if the output is not recoverable ECDSA.
    #[allow(
        clippy::indexing_slicing,
        reason = "SIGNATURE_LEN is 65; r||s is 64 then v at index 64 by construction"
    )]
    pub fn signature_65(out: &SignOutput) -> Result<[u8; SIGNATURE_LEN], SignError> {
        match *out {
            SignOutput::Ecdsa { signature, v } => {
                let mut wire = [0u8; SIGNATURE_LEN];
                wire[..64].copy_from_slice(&signature);
                wire[64] = v;
                Ok(wire)
            }
            _ => Err(SignError::InvalidSignature(
                "expected recoverable ECDSA (Ecdsa) SignOutput".into(),
            )),
        }
    }

    /// Sign format=2 ECDSA fields: deep-hash → SHA-256 → recoverable ECDSA.
    ///
    /// # Errors
    ///
    /// Rejects `format != 2`; propagates signing failures.
    pub fn sign_format2(&self, fields: &Format2EcdsaFields<'_>) -> Result<SignOutput, SignError> {
        sign_format2_ecdsa(self, fields)
    }
}

impl SignDigest for Signer {
    /// Sign a 32-byte pre-hashed digest with recoverable ECDSA (`v` = `0|1`).
    ///
    /// Use when the caller already computed `SHA-256(deep_hash_output)`.
    /// Prefer [`Signer::sign_payload`] when starting from the deep-hash bytes.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(digest)
    }
}

#[cfg(feature = "kobe")]
pub use signer_primitives::FromDerived;

signer_primitives::impl_from_secret_key!();

/// Protocol address: `Base64URL_nopad(SHA-256(compressed_pk))`.
#[must_use]
pub fn address_from_compressed_pubkey(pk: &[u8; 33]) -> String {
    base64url_nopad(&sha256_32(pk))
}

/// Recovered-owner string: `Base64URL_nopad(compressed_pk)`.
#[must_use]
pub fn owner_from_compressed_pubkey(pk: &[u8; 33]) -> String {
    base64url_nopad(pk)
}

/// A leaf blob or nested list for Arweave deep-hash.
#[derive(Debug, Clone)]
pub enum DeepHashItem<'a> {
    /// Raw binary blob.
    Blob(&'a [u8]),
    /// Nested list of items.
    List(Vec<Self>),
}

impl<'a> DeepHashItem<'a> {
    /// Convenience: blob from a slice.
    #[must_use]
    pub const fn blob(data: &'a [u8]) -> Self {
        Self::Blob(data)
    }

    /// Convenience: list from a `Vec` of items.
    #[must_use]
    pub const fn list(items: Vec<Self>) -> Self {
        Self::List(items)
    }
}

/// Recursive deep-hash used by Arweave v2 signature data segments.
///
/// Matches `ar_deep_hash:hash/1` and arweave-js `deepHash` (SHA-384 throughout).
/// Output is always **48 bytes**.
#[must_use]
pub fn deep_hash(item: &DeepHashItem<'_>) -> [u8; DEEP_HASH_LEN] {
    match item {
        DeepHashItem::Blob(data) => deep_hash_blob(data),
        DeepHashItem::List(items) => deep_hash_list(items),
    }
}

/// Deep-hash a top-level list (common case for signature segments).
///
/// Avoids allocating a temporary [`DeepHashItem::List`] wrapper.
#[must_use]
pub fn deep_hash_list(items: &[DeepHashItem<'_>]) -> [u8; DEEP_HASH_LEN] {
    let tag = list_tag(items.len());
    let mut acc = sha384_48(&tag);
    for child in items {
        let child_hash = deep_hash(child);
        let mut pair = Vec::with_capacity(DEEP_HASH_LEN * 2);
        pair.extend_from_slice(&acc);
        pair.extend_from_slice(&child_hash);
        acc = sha384_48(&pair);
    }
    acc
}

fn deep_hash_blob(data: &[u8]) -> [u8; DEEP_HASH_LEN] {
    let tag = blob_tag(data.len());
    let tag_h = sha384_48(&tag);
    let data_h = sha384_48(data);
    let mut pair = Vec::with_capacity(DEEP_HASH_LEN * 2);
    pair.extend_from_slice(&tag_h);
    pair.extend_from_slice(&data_h);
    sha384_48(&pair)
}

fn blob_tag(len: usize) -> Vec<u8> {
    tagged_len_prefix(b"blob", len)
}

fn list_tag(len: usize) -> Vec<u8> {
    tagged_len_prefix(b"list", len)
}

fn tagged_len_prefix(kind: &[u8], len: usize) -> Vec<u8> {
    let digits = len.to_string();
    let mut t = Vec::with_capacity(kind.len() + digits.len());
    t.extend_from_slice(kind);
    t.extend_from_slice(digits.as_bytes());
    t
}

/// Fields for format=2 **ECDSA** signature preimage (owner omitted).
///
/// Matches `signature_data_segment_v2_no_public_key` without denomination.
/// Callers supply raw bytes for `target` / `last_tx` / `data_root` (already
/// decoded from `Base64URL` when coming from JSON).
#[derive(Debug, Clone, Copy)]
pub struct Format2EcdsaFields<'a> {
    /// Transaction format (must be `2` for ECDSA).
    pub format: u32,
    /// Destination address bytes (may be empty).
    pub target: &'a [u8],
    /// Winston quantity as decimal ASCII (e.g. `"0"`, `"1"`).
    pub quantity: &'a str,
    /// Reward in winston as decimal ASCII.
    pub reward: &'a str,
    /// Anchor `last_tx` id bytes (may be empty).
    pub last_tx: &'a [u8],
    /// Tags as `(name, value)` raw byte pairs (`Base64URL`-decoded).
    pub tags: &'a [(&'a [u8], &'a [u8])],
    /// Declared data size in bytes.
    pub data_size: u64,
    /// Merkle `data_root` bytes (may be empty).
    pub data_root: &'a [u8],
}

/// Build the 48-byte deep-hash preimage for ECDSA format=2 (no owner).
///
/// Does **not** include denomination (matches arweave-js `master-ec` today).
#[must_use]
pub fn signature_data_segment_v2_ecdsa(fields: &Format2EcdsaFields<'_>) -> [u8; DEEP_HASH_LEN] {
    let format_bin = fields.format.to_string();
    let data_size_bin = fields.data_size.to_string();

    let tag_items: Vec<DeepHashItem<'_>> = fields
        .tags
        .iter()
        .map(|(n, v)| DeepHashItem::List(alloc::vec![DeepHashItem::Blob(n), DeepHashItem::Blob(v)]))
        .collect();

    let items = alloc::vec![
        DeepHashItem::Blob(format_bin.as_bytes()),
        DeepHashItem::Blob(fields.target),
        DeepHashItem::Blob(fields.quantity.as_bytes()),
        DeepHashItem::Blob(fields.reward.as_bytes()),
        DeepHashItem::Blob(fields.last_tx),
        DeepHashItem::List(tag_items),
        DeepHashItem::Blob(data_size_bin.as_bytes()),
        DeepHashItem::Blob(fields.data_root),
    ];
    deep_hash_list(&items)
}

/// Sign format=2 ECDSA fields: deep-hash → SHA-256 → recoverable ECDSA.
///
/// # Errors
///
/// Signing primitive failures; rejects `format != 2`.
pub fn sign_format2_ecdsa(
    signer: &Signer,
    fields: &Format2EcdsaFields<'_>,
) -> Result<SignOutput, SignError> {
    if fields.format != 2 {
        return Err(SignError::InvalidTransaction(
            "Arweave ECDSA requires format=2".into(),
        ));
    }
    let preimage = signature_data_segment_v2_ecdsa(fields);
    signer.sign_payload(&preimage)
}

fn sha256_32(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn sha384_48(data: &[u8]) -> [u8; DEEP_HASH_LEN] {
    Sha384::digest(data).into()
}

fn base64url_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "unit tests")]
mod tests;
