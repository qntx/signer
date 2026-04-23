//! Unit tests for the Solana signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use signer_primitives::SignOutput;

use super::{EncodeSignedTransaction, Sign, SignMessage, Signer};

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
    let s1 = Signer::from_bytes(&bytes).unwrap();
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
    s.verify(msg, sig.to_bytes().as_slice())
        .expect("signature must verify");
}

#[test]
fn sign_wrong_message_fails() {
    let s = test_signer();
    let sig = s.sign_raw(b"correct");
    assert!(s.verify(b"wrong", sig.to_bytes().as_slice()).is_err());
}

#[test]
fn sign_trait_verify() {
    let s = test_signer();
    let out = SignMessage::sign_message(&s, b"hello").unwrap();
    let sig_bytes = out.to_bytes();
    assert_eq!(sig_bytes.len(), 64);
    assert!(out.v().is_none());
    s.verify(b"hello", &sig_bytes)
        .expect("trait signature must verify");
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let digest = [0u8; 32];
    let out1 = Sign::sign_hash(&s, &digest).unwrap();
    let out2 = Sign::sign_hash(&s, &digest).unwrap();
    assert_eq!(out1.to_bytes(), out2.to_bytes());
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
    let sig_bytes = sig.to_bytes();

    // Low-level splicer: accepts raw 64-byte compact signature.
    let signed_raw = Signer::splice_signature(&tx, &sig_bytes).unwrap();
    assert_eq!(&signed_raw[1..65], &sig_bytes);
    assert_eq!(&signed_raw[65..], msg);

    // High-level entry: accepts the unified SignOutput enum.
    let sig_output = SignOutput::Ed25519(sig_bytes);
    let signed_output = Signer::encode_signed_transaction(&tx, &sig_output).unwrap();
    assert_eq!(signed_raw, signed_output);
}

#[test]
fn sign_trait_encode_signed_transaction_requires_ed25519_variant() {
    let s = test_signer();
    let digest = [0u8; 32];
    let out = Sign::sign_hash(&s, &digest).unwrap();
    // Trait-level encode_signed_transaction accepts the unified SignOutput enum.
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(b"body");
    let encoded = EncodeSignedTransaction::encode_signed_transaction(&s, &tx, &out).unwrap();
    assert_eq!(&encoded[1..65], &out.to_bytes());
}

#[test]
fn sign_trait_encode_signed_transaction_rejects_non_ed25519() {
    let s = test_signer();
    let wrong = SignOutput::Ecdsa {
        signature: [0u8; 64],
        v: 0,
    };
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    assert!(EncodeSignedTransaction::encode_signed_transaction(&s, &tx, &wrong).is_err());
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
