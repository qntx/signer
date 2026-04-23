//! Unit tests for the Sui signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use super::{
    ED25519_FLAG, MSG_INTENT, Sign, SignMessage, Signer, TX_INTENT, bcs_serialize_bytes,
    blake2b_256, intent_hash,
};

/// RFC 8032 Test Vector 1.
const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const TEST_PUBKEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

#[test]
fn rfc8032_pubkey() {
    assert_eq!(hex::encode(test_signer().public_key_bytes()), TEST_PUBKEY);
}

#[test]
fn address_is_blake2b_of_flagged_pubkey() {
    let s = test_signer();
    let addr = s.address();
    assert!(addr.starts_with("0x"));
    assert_eq!(addr.len(), 66);

    let mut buf = vec![ED25519_FLAG];
    buf.extend_from_slice(&s.public_key_bytes());
    let expected = blake2b_256(&buf);
    assert_eq!(addr, format!("0x{}", hex::encode(expected)));
}

#[test]
fn from_bytes_matches_from_hex() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s = Signer::from_bytes(&bytes).unwrap();
    assert_eq!(s.address(), test_signer().address());
}

#[test]
fn sign_transaction_intent_verify() {
    let s = test_signer();
    let tx = b"bcs transaction data";
    let out = s.sign_transaction(tx).unwrap();
    let digest = intent_hash(TX_INTENT, tx);
    s.verify(&digest, &out.to_bytes())
        .expect("intent digest must verify");
}

#[test]
fn sign_message_bcs_intent_verify() {
    let s = test_signer();
    let msg = b"hello sui";
    let out = s.sign_message(msg).unwrap();
    let bcs = bcs_serialize_bytes(msg);
    let digest = intent_hash(MSG_INTENT, &bcs);
    s.verify(&digest, &out.to_bytes())
        .expect("personal msg digest must verify");
}

#[test]
fn encode_signature_wire_format() {
    let s = test_signer();
    let sig = s.sign_raw(b"data");
    let encoded = s.encode_signature(&sig);

    assert_eq!(encoded.len(), 97);
    assert_eq!(encoded[0], ED25519_FLAG);
    assert_eq!(&encoded[1..65], &sig.to_bytes());
    assert_eq!(&encoded[65..], s.public_key_bytes());
}

#[test]
fn sign_trait_includes_pubkey() {
    let s = test_signer();
    let out = Sign::sign_transaction(&s, b"tx").unwrap();
    assert_eq!(out.to_bytes().len(), 64);
    let pk = out.public_key().expect("must include pubkey");
    assert_eq!(pk.len(), 32);
    assert_eq!(hex::encode(pk), TEST_PUBKEY);
}

#[test]
fn deterministic_signing() {
    let s = test_signer();
    let s1 = s.sign_transaction(b"same input").unwrap();
    let s2 = s.sign_transaction(b"same input").unwrap();
    assert_eq!(s1.to_bytes(), s2.to_bytes());
}

#[test]
fn bcs_uleb128_encoding() {
    let bcs_short = bcs_serialize_bytes(b"hi");
    assert_eq!(bcs_short[0], 2);
    assert_eq!(&bcs_short[1..], b"hi");

    let data = vec![0xAA; 200];
    let bcs_long = bcs_serialize_bytes(&data);
    assert_eq!(bcs_long[0], 0xC8);
    assert_eq!(bcs_long[1], 0x01);
    assert_eq!(&bcs_long[2..], data.as_slice());

    let bcs_empty = bcs_serialize_bytes(b"");
    assert_eq!(bcs_empty, vec![0]);
}

#[test]
fn bcs_128_byte_boundary() {
    let data = vec![0xBB; 128];
    let bcs = bcs_serialize_bytes(&data);
    assert_eq!(bcs[0], 0x80);
    assert_eq!(bcs[1], 0x01);
    assert_eq!(&bcs[2..], data.as_slice());
}

#[test]
fn debug_does_not_leak_key() {
    let debug = format!("{:?}", test_signer());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("9d61b1"));
}
