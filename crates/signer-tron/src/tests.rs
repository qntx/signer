//! Unit tests for the TRON signer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use signer_primitives::testing::verify_secp256k1_recoverable;

use super::{SignOutput, Signer};

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
    let hash = Sha256::digest(b"tron test");
    let out = s.sign_hash(&hash).unwrap();
    assert_eq!(out.signature.len(), 65);
    assert!(out.recovery_id.is_some());
    verify(&s, &hash, &out);
}

#[test]
fn sign_transaction_sha256_verify() {
    let s = test_signer();
    let tx = b"tron tx bytes";
    let out = s.sign_transaction(tx).unwrap();
    let expected = Sha256::digest(tx);
    verify(&s, &expected, &out);
}

#[test]
fn sign_message_tron_prefix_verify() {
    let s = test_signer();
    let msg = b"Hello TRON";
    let out = s.sign_message(msg).unwrap();

    let v = out.signature[64];
    assert!(v == 27 || v == 28, "TRON v must be 27 or 28, got {v}");

    let prefix = format!("\x19TRON Signed Message:\n{}", msg.len());
    let mut data = Vec::new();
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(msg);
    let hash = Keccak256::digest(&data);
    verify(&s, &hash, &out);
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let out1 = s.sign_hash(&[0u8; 32]).unwrap();
    let out2 = s.sign_hash(&[0u8; 32]).unwrap();
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
