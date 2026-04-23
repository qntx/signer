//! Unit tests for the Bitcoin signer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use sha2::{Digest, Sha256};
use signer_primitives::testing::verify_secp256k1_recoverable;

use super::{BitcoinMessageAddressType, Sign, SignMessage, SignOutput, Signer};

const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

/// Recover the 65-byte compact signature regardless of which BIP-137
/// header byte the signer prepended, so the underlying ECDSA proof can be
/// checked against the expected digest.
fn verify_compact(s: &Signer, hash: &[u8; 32], out: &SignOutput, header_offset: u8) {
    let bytes = out.to_bytes();
    assert_eq!(bytes.len(), 65);
    let header = bytes[64];
    assert!(
        header >= header_offset && header < header_offset + 4,
        "expected BIP-137 header in {}..{}, got {header}",
        header_offset,
        header_offset + 4,
    );
    let mut raw = bytes;
    raw[64] = header - header_offset;
    verify_secp256k1_recoverable(&s.public_key_bytes(), hash, &raw);
}

fn verify(s: &Signer, hash: &[u8; 32], out: &SignOutput) {
    verify_secp256k1_recoverable(&s.public_key_bytes(), hash, &out.to_bytes());
}

#[test]
fn sign_hash_verify() {
    let s = test_signer();
    let hash: [u8; 32] = Sha256::digest(b"test message").into();
    let out = s.sign_hash(&hash).unwrap();
    let sig_bytes = out.to_bytes();
    assert_eq!(sig_bytes.len(), 65);
    assert!(out.v().is_some());
    verify(&s, &hash, &out);
}

#[test]
fn sign_transaction_double_sha256_verify() {
    let s = test_signer();
    let tx = b"bitcoin tx bytes";
    let out = s.sign_transaction(tx).unwrap();
    let expected: [u8; 32] = Sha256::digest(Sha256::digest(tx)).into();
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
fn sign_message_short_bip137_compressed_p2pkh() {
    let s = test_signer();
    let msg = b"Hello Bitcoin!";
    let out = s.sign_message(msg).unwrap();

    let mut data = Vec::new();
    data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "test message is short, len fits in u8"
    )]
    data.push(msg.len() as u8);
    data.extend_from_slice(msg);
    let expected: [u8; 32] = Sha256::digest(Sha256::digest(&data)).into();

    // Default `sign_message` must emit the compressed-P2PKH header (31 | 32).
    verify_compact(&s, &expected, &out, 31);
}

#[test]
fn sign_message_long_varint_bip137_compressed_p2pkh() {
    let s = test_signer();
    let msg = vec![0x42u8; 300];
    let out = s.sign_message(&msg).unwrap();

    let mut data = Vec::new();
    data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    data.push(0xFD);
    data.extend_from_slice(&300u16.to_le_bytes());
    data.extend_from_slice(&msg);
    let expected: [u8; 32] = Sha256::digest(Sha256::digest(&data)).into();
    verify_compact(&s, &expected, &out, 31);
}

#[test]
fn sign_message_varint_boundary_253_bip137_compressed_p2pkh() {
    let s = test_signer();
    let msg = vec![0xAA; 253];
    let out = s.sign_message(&msg).unwrap();

    let mut data = Vec::new();
    data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    data.push(0xFD);
    data.extend_from_slice(&253u16.to_le_bytes());
    data.extend_from_slice(&msg);
    let expected: [u8; 32] = Sha256::digest(Sha256::digest(&data)).into();
    verify_compact(&s, &expected, &out, 31);
}

#[test]
fn sign_message_with_all_address_types_bip137() {
    let s = test_signer();
    let msg = b"header byte check";

    let cases: &[(BitcoinMessageAddressType, u8)] = &[
        (BitcoinMessageAddressType::P2pkhUncompressed, 27),
        (BitcoinMessageAddressType::P2pkhCompressed, 31),
        (BitcoinMessageAddressType::SegwitP2sh, 35),
        (BitcoinMessageAddressType::SegwitBech32, 39),
    ];
    let digest = super::bitcoin_message_digest(msg);
    for (ty, offset) in cases {
        let out = s.sign_message_with(*ty, msg).unwrap();
        assert_eq!(ty.header_offset(), *offset);
        verify_compact(&s, &digest, &out, *offset);
    }
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
