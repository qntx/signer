//! Unit tests and known-answer vectors for Arweave ECDSA.

use base64::Engine;
use sha2::{Digest, Sha256, Sha384};
use signer_primitives::FromSecretKey;

use super::*;

/// Fixed private key (not a wallet seed; for sign/verify shape only).
const SK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// Canonical BIP-39 abandon private key at m/44'/472'/0'/0/0 (kobe-arweave KAT).
const ABANDON_0_SK: &str = "130721c87ce0ace0999c94a5943d055b224411eda752680ca24969d0837ff152";
const ABANDON_0_ADDR: &str = "G3y00z9F3EvSzJprpIH6vPqHVZPH0rLqLrg0JOsd88Y";
const ABANDON_0_OWNER: &str = "A9-agndOu82Va7G9inhR8lqV3LEbBkp0zK3PJ3zLbTtv";
const ABANDON_0_PK: &str = "03df9a82774ebbcd956bb1bd8a7851f25a95dcb11b064a74ccadcf277ccb6d3b6f";

#[test]
fn address_matches_kobe_arweave_abandon0() {
    let s = Signer::from_hex(ABANDON_0_SK).unwrap();
    assert_eq!(s.public_key_hex(), ABANDON_0_PK);
    assert_eq!(s.address(), ABANDON_0_ADDR);
    assert_eq!(s.owner(), ABANDON_0_OWNER);
    assert_eq!(s.address().len(), 43);
}

#[test]
fn owner_is_not_address() {
    let s = Signer::from_hex(ABANDON_0_SK).unwrap();
    assert_ne!(s.owner(), s.address());
}

#[test]
fn sign_digest_recoverable_shape() {
    let s = Signer::from_hex(SK_HEX).unwrap();
    let dig = [0x11u8; 32];
    let out = s.sign_digest(&dig).unwrap();
    assert!(matches!(out, SignOutput::Ecdsa { v: 0 | 1, .. }));
    assert_eq!(out.to_bytes().len(), SIGNATURE_LEN);
    let sig65 = Signer::signature_65(&out).unwrap();
    s.verify_digest(&dig, &sig65).unwrap();
}

#[test]
fn sign_payload_is_sha256_then_sign() {
    let s = Signer::from_hex(SK_HEX).unwrap();
    let msg = [0xABu8; DEEP_HASH_LEN];
    let out = s.sign_payload(&msg).unwrap();
    let sig65 = Signer::signature_65(&out).unwrap();
    s.verify_payload(&msg, &sig65).unwrap();

    let digest: [u8; 32] = Sha256::digest(msg).into();
    let out2 = s.sign_digest(&digest).unwrap();
    let a = out.to_bytes();
    let b = out2.to_bytes();
    assert_eq!(a.get(..64), b.get(..64));
}

#[test]
fn transaction_id_is_sha256_of_sig() {
    let s = Signer::from_hex(SK_HEX).unwrap();
    let out = s.sign_digest(&[7u8; 32]).unwrap();
    let sig65 = Signer::signature_65(&out).unwrap();
    let id = Signer::transaction_id(&sig65);
    assert_eq!(id.len(), 43);
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(sig65));
    assert_eq!(id, expected);
}

#[test]
fn deep_hash_empty_list() {
    let h = deep_hash_list(&[]);
    let expected: [u8; 48] = Sha384::digest(b"list0").into();
    assert_eq!(h, expected);
}

#[test]
fn deep_hash_blob_vs_list_distinct() {
    let a = deep_hash(&DeepHashItem::Blob(b"a"));
    let b = deep_hash(&DeepHashItem::List(alloc::vec![DeepHashItem::Blob(b"a")]));
    assert_ne!(a, b);
}

#[test]
fn deep_hash_order_matters() {
    let ab = deep_hash_list(&[DeepHashItem::Blob(b"a"), DeepHashItem::Blob(b"b")]);
    let ba = deep_hash_list(&[DeepHashItem::Blob(b"b"), DeepHashItem::Blob(b"a")]);
    assert_ne!(ab, ba);
}

#[test]
fn format2_segment_deterministic() {
    let fields = Format2EcdsaFields {
        format: 2,
        target: &[],
        quantity: "0",
        reward: "0",
        last_tx: &[],
        tags: &[],
        data_size: 0,
        data_root: &[],
    };
    let a = signature_data_segment_v2_ecdsa(&fields);
    let b = signature_data_segment_v2_ecdsa(&fields);
    assert_eq!(a, b);
    assert_eq!(a.len(), DEEP_HASH_LEN);
}

#[test]
fn sign_format2_rejects_non_v2() {
    let s = Signer::from_hex(SK_HEX).unwrap();
    let fields = Format2EcdsaFields {
        format: 1,
        target: &[],
        quantity: "0",
        reward: "0",
        last_tx: &[],
        tags: &[],
        data_size: 0,
        data_root: &[],
    };
    assert!(sign_format2_ecdsa(&s, &fields).is_err());
}

#[test]
fn sign_format2_roundtrip_verify() {
    let s = Signer::from_hex(SK_HEX).unwrap();
    let fields = Format2EcdsaFields {
        format: 2,
        target: b"\x01\x02",
        quantity: "1",
        reward: "1000",
        last_tx: b"",
        tags: &[(b"App-Name", b"kobe-test")],
        data_size: 0,
        data_root: b"",
    };
    let out = sign_format2_ecdsa(&s, &fields).unwrap();
    let sig65 = Signer::signature_65(&out).unwrap();
    let preimage = signature_data_segment_v2_ecdsa(&fields);
    s.verify_payload(&preimage, &sig65).unwrap();
}

#[test]
fn from_secret_key_trait() {
    let s = Signer::from_secret_hex(ABANDON_0_SK).unwrap();
    assert_eq!(s.address(), ABANDON_0_ADDR);
}
