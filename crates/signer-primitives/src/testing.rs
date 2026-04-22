//! Test helpers shared across chain signer crates.
//!
//! Only enabled when the `testing` feature is active (typically via a
//! `dev-dependencies` flag). These helpers parse and verify signatures
//! produced by the shared primitive types, eliminating ~10 duplicate
//! implementations of `verify_secp256k1` across chain test modules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test helpers: panics on bad input are the intended behaviour"
)]

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

/// Verify a 65-byte recoverable secp256k1 signature against a pre-hashed
/// digest and a compressed-SEC1-encoded public key.
///
/// Panics if the signature or public key bytes are malformed, or if
/// verification fails.
pub fn verify_secp256k1_recoverable(public_key: &[u8], hash: &[u8], signature: &[u8]) {
    assert_eq!(
        signature.len(),
        65,
        "expected 65-byte recoverable signature"
    );
    let r: [u8; 32] = signature[..32].try_into().unwrap();
    let s: [u8; 32] = signature[32..64].try_into().unwrap();
    let sig = Signature::from_scalars(r, s).expect("valid signature scalars");
    let vk = VerifyingKey::from_sec1_bytes(public_key).expect("valid SEC1 public key");
    vk.verify_prehash(hash, &sig)
        .expect("signature must verify");
}

/// Verify a DER-encoded secp256k1 signature against a pre-hashed digest
/// and a compressed-SEC1-encoded public key.
///
/// Panics if inputs are malformed or verification fails.
pub fn verify_secp256k1_der(public_key: &[u8], hash: &[u8], signature_der: &[u8]) {
    let sig = Signature::from_der(signature_der).expect("valid DER signature");
    let vk = VerifyingKey::from_sec1_bytes(public_key).expect("valid SEC1 public key");
    vk.verify_prehash(hash, &sig)
        .expect("signature must verify");
}
