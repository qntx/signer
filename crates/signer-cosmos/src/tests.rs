//! Unit tests for the Cosmos signer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use sha2::{Digest, Sha256};
use signer_primitives::testing::verify_secp256k1_recoverable;

use super::{Sign, SignOutput, Signer};

const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

fn verify(s: &Signer, hash: &[u8; 32], out: &SignOutput) {
    verify_secp256k1_recoverable(&s.public_key_bytes(), hash, &out.to_bytes());
}

#[test]
fn sign_hash_verify() {
    let s = test_signer();
    let hash: [u8; 32] = Sha256::digest(b"cosmos test").into();
    let out = s.sign_hash(&hash).unwrap();
    assert_eq!(out.to_bytes().len(), 65);
    assert!(out.v().is_some());
    verify(&s, &hash, &out);
}

#[test]
fn sign_transaction_sha256_verify() {
    let s = test_signer();
    let tx = b"cosmos tx bytes";
    let out = s.sign_transaction(tx).unwrap();
    let expected: [u8; 32] = Sha256::digest(tx).into();
    verify(&s, &expected, &out);
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
fn deterministic_signature() {
    let s = test_signer();
    let out1 = s.sign_transaction(b"same data").unwrap();
    let out2 = s.sign_transaction(b"same data").unwrap();
    assert_eq!(out1.to_bytes(), out2.to_bytes());
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
