//! Unit tests for the TON signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use super::{Sign, Signature, Signer};

/// RFC 8032 Test Vector 1.
const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const TEST_PUBKEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

#[test]
fn rfc8032_pubkey() {
    assert_eq!(test_signer().public_key_hex(), TEST_PUBKEY);
}

#[test]
fn from_bytes_matches_from_hex() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s = Signer::from_bytes(&bytes);
    assert_eq!(s.public_key_bytes(), test_signer().public_key_bytes());
}

#[test]
fn sign_and_verify() {
    let s = test_signer();
    let msg = b"hello TON";
    let sig = s.sign_raw(msg);
    s.verify(msg, &sig).expect("signature must verify");
}

#[test]
fn sign_wrong_message_fails() {
    let s = test_signer();
    let sig = s.sign_raw(b"correct");
    assert!(s.verify(b"wrong", &sig).is_err());
}

#[test]
fn sign_trait_verify() {
    let s = test_signer();
    let out = Sign::sign_message(&s, b"test").unwrap();
    assert_eq!(out.signature.len(), 64);
    assert!(out.recovery_id.is_none());
    let sig = Signature::from_slice(&out.signature).unwrap();
    s.verify(b"test", &sig)
        .expect("trait signature must verify");
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let s1 = s.sign_raw(b"deterministic");
    let s2 = s.sign_raw(b"deterministic");
    assert_eq!(s1.to_bytes(), s2.to_bytes());
}

#[test]
fn debug_does_not_leak_key() {
    let debug = format!("{:?}", test_signer());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("9d61b1"));
}
