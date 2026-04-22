//! Unit tests for the Aptos signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use super::{ED25519_SCHEME, Sign, Signer, sha3_256, tx_signing_message};

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
fn address_is_sha3_of_pubkey_with_scheme() {
    let s = test_signer();
    let addr = s.address();
    assert!(addr.starts_with("0x"), "address must start with 0x");
    assert_eq!(addr.len(), 66, "address must be 66 chars (0x + 64 hex)");

    let mut buf = s.public_key_bytes();
    buf.push(ED25519_SCHEME);
    let expected = sha3_256(&buf);
    assert_eq!(addr, format!("0x{}", hex::encode(expected)));
}

#[test]
fn from_bytes_matches_from_hex() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s = Signer::from_bytes(&bytes);
    assert_eq!(s.address(), test_signer().address());
}

#[test]
fn sign_and_verify() {
    let s = test_signer();
    let msg = b"hello aptos";
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
fn sign_transaction_bcs_verify() {
    let s = test_signer();
    let bcs_tx = b"fake bcs raw transaction";
    let sig = s.sign_transaction_bcs(bcs_tx);
    let signing_msg = tx_signing_message(bcs_tx);
    s.verify(&signing_msg, &sig)
        .expect("transaction signature must verify against signing message");
}

#[test]
fn tx_signing_message_prefix_is_correct() {
    let prefix = sha3_256(b"APTOS::RawTransaction");
    let bcs = b"test";
    let msg = tx_signing_message(bcs);
    assert_eq!(msg.len(), 32 + bcs.len());
    assert_eq!(&msg[..32], &prefix);
    assert_eq!(&msg[32..], bcs.as_slice());
}

#[test]
fn sign_trait_includes_pubkey() {
    let s = test_signer();
    let out = Sign::sign_transaction(&s, b"tx").unwrap();
    assert_eq!(out.signature.len(), 64);
    let pk = out.public_key.as_ref().expect("must include pubkey");
    assert_eq!(pk.len(), 32);
    assert_eq!(hex::encode(pk), TEST_PUBKEY);
}

#[test]
fn deterministic_signing() {
    let s = test_signer();
    let s1 = s.sign_transaction_bcs(b"same input");
    let s2 = s.sign_transaction_bcs(b"same input");
    assert_eq!(s1.to_bytes(), s2.to_bytes());
}

#[test]
fn debug_does_not_leak_key() {
    let debug = format!("{:?}", test_signer());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("9d61b1"));
}
