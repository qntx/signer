//! Unit tests for the Filecoin signer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use blake2::Digest;
use signer_primitives::testing::verify_secp256k1_recoverable;

use super::{Blake2b256, SignOutput, Signer};

const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

fn verify(s: &Signer, hash: &[u8], out: &SignOutput) {
    verify_secp256k1_recoverable(&s.public_key_bytes(), hash, &out.signature);
}

#[test]
fn sign_hash_verify() {
    let s = test_signer();
    let hash = Blake2b256::digest(b"filecoin test");
    let out = s.sign_hash(&hash).unwrap();
    assert_eq!(out.signature.len(), 65);
    assert!(out.recovery_id.is_some());
    verify(&s, &hash, &out);
}

#[test]
fn sign_transaction_blake2b_verify() {
    let s = test_signer();
    let tx = b"fil tx bytes";
    let out = s.sign_transaction(tx).unwrap();
    let expected = Blake2b256::digest(tx);
    verify(&s, &expected, &out);
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let out1 = s.sign_message(b"same").unwrap();
    let out2 = s.sign_message(b"same").unwrap();
    assert_eq!(out1.signature, out2.signature);
}

#[test]
fn from_bytes_roundtrip() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s = Signer::from_bytes(&bytes).unwrap();
    assert_eq!(s.public_key_bytes(), test_signer().public_key_bytes());
}

#[test]
fn rejects_non_32_byte_hash() {
    assert!(test_signer().sign_hash(b"short").is_err());
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
