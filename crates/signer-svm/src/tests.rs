//! Unit tests for the Solana signer.

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
fn rfc8032_vector1_pubkey() {
    assert_eq!(test_signer().public_key_hex(), TEST_PUBKEY);
}

#[test]
fn address_is_base58_pubkey() {
    let s = test_signer();
    let decoded = bs58::decode(&s.address()).into_vec().unwrap();
    assert_eq!(decoded.len(), 32);
    assert_eq!(hex::encode(&decoded), TEST_PUBKEY);
}

#[test]
fn from_bytes_matches_from_hex() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s1 = Signer::from_bytes(&bytes);
    assert_eq!(s1.address(), test_signer().address());
}

#[test]
fn keypair_base58_roundtrip() {
    let s = test_signer();
    let b58 = s.keypair_base58();
    let restored = Signer::from_keypair_base58(&b58).unwrap();
    assert_eq!(s.address(), restored.address());
    assert_eq!(s.public_key_hex(), restored.public_key_hex());
}

#[test]
fn sign_and_verify() {
    let s = test_signer();
    let msg = b"test message for solana";
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
    let out = Sign::sign_message(&s, b"hello").unwrap();
    assert_eq!(out.signature.len(), 64);
    assert!(out.recovery_id.is_none());
    let sig = Signature::from_slice(&out.signature).unwrap();
    s.verify(b"hello", &sig)
        .expect("trait signature must verify");
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let out1 = Sign::sign_hash(&s, b"deterministic").unwrap();
    let out2 = Sign::sign_hash(&s, b"deterministic").unwrap();
    assert_eq!(out1.signature, out2.signature);
}

#[test]
fn extract_signable_bytes_strips_header() {
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(b"message_body");
    let signable = Signer::extract_signable_bytes(&tx).unwrap();
    assert_eq!(signable, b"message_body");
}

#[test]
fn extract_signable_bytes_rejects_empty() {
    assert!(Signer::extract_signable_bytes(&[]).is_err());
}

#[test]
fn encode_signed_transaction_splices_sig() {
    let s = test_signer();
    let msg = b"message_body";
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(msg);

    let sig = s.sign_raw(msg);
    let signed = Signer::encode_signed_transaction(&tx, &sig).unwrap();

    assert_eq!(&signed[1..65], &sig.to_bytes());
    assert_eq!(&signed[65..], msg);
}

#[test]
fn rejects_invalid_keypair_base58() {
    assert!(Signer::from_keypair_base58("invalid!!!").is_err());
    assert!(Signer::from_keypair_base58("3J98t1").is_err());
}

#[test]
fn debug_does_not_leak_key() {
    let debug = format!("{:?}", test_signer());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("9d61b1"));
}
