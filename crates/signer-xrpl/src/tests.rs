//! Unit tests for the XRPL signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use sha2::{Digest, Sha512};
use signer_primitives::testing::verify_secp256k1_der;

use super::{STX_PREFIX, Signer, sha512_half_prefixed};

const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

#[test]
fn sign_hash_returns_der() {
    let s = test_signer();
    let hash = sha512_half_prefixed(b"", b"xrpl test data");
    let out = s.sign_hash(&hash).unwrap();
    // DER signatures are variable-length, typically 70-72 bytes
    let sig_bytes = out.to_bytes();
    assert!(
        (68..=72).contains(&sig_bytes.len()),
        "DER sig should be 68-72 bytes, got {}",
        sig_bytes.len()
    );
    assert!(out.v().is_none());
}

#[test]
fn sign_hash_verifies() {
    let s = test_signer();
    let hash = sha512_half_prefixed(b"", b"verify me");
    let out = s.sign_hash(&hash).unwrap();
    verify_secp256k1_der(&s.public_key_bytes(), &hash, &out.to_bytes());
}

#[test]
fn sign_transaction_uses_stx_prefix() {
    let s = test_signer();
    let tx = b"some serialized tx fields";
    let out = s.sign_transaction(tx).unwrap();
    let expected_hash = sha512_half_prefixed(&STX_PREFIX, tx);
    verify_secp256k1_der(&s.public_key_bytes(), &expected_hash, &out.to_bytes());
}

#[test]
fn sign_transaction_rejects_empty() {
    let s = test_signer();
    assert!(s.sign_transaction(b"").is_err());
}

#[test]
fn sign_message_returns_error() {
    let s = test_signer();
    let result = s.sign_message(b"hello xrpl");
    assert!(result.is_err());
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let out1 = s.sign_transaction(b"same tx").unwrap();
    let out2 = s.sign_transaction(b"same tx").unwrap();
    assert_eq!(out1.to_bytes(), out2.to_bytes());
}

#[test]
fn different_data_different_signature() {
    let s = test_signer();
    let out1 = s.sign_transaction(b"tx a").unwrap();
    let out2 = s.sign_transaction(b"tx b").unwrap();
    assert_ne!(out1.to_bytes(), out2.to_bytes());
}

#[test]
fn compressed_public_key_33_bytes() {
    let pk = test_signer().public_key_bytes();
    assert_eq!(pk.len(), 33);
    assert!(pk[0] == 0x02 || pk[0] == 0x03);
}

#[test]
fn from_bytes_roundtrip() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s = Signer::from_bytes(&bytes).unwrap();
    assert_eq!(s.public_key_bytes(), test_signer().public_key_bytes());
}

#[test]
fn rejects_invalid_input() {
    assert!(Signer::from_hex("not-hex").is_err());
    assert!(Signer::from_bytes(&[0u8; 32]).is_err());
}

#[test]
fn debug_does_not_leak_key() {
    let debug = format!("{:?}", test_signer());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("4c0883"));
}

#[test]
fn sha512_half_correctness() {
    let hash = sha512_half_prefixed(b"", b"");
    assert_eq!(hash.len(), 32);
    let full = Sha512::digest(b"");
    assert_eq!(&hash[..], &full[..32]);
}
