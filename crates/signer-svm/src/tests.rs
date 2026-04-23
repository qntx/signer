//! Solana signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` (ed25519) +
//! `@scure/base` (base58) run. The KATs pin the Base58 pubkey address,
//! all three Ed25519 entry points, and the compact-u16 + signature-slot
//! splicing machinery that makes Solana's wire format work.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{EncodeSignedTransaction, Sign, SignError, SignMessage, SignOutput, Signer};

/// RFC 8032 Test Vector 1.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `base58(public_key_bytes)`.
const ADDRESS: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

/// Ed25519 over each fixed input.
const SIGN_HASH_HEX: &str = "8d917876339a83dc45d1796e557c7baf8bff5e88ab000e166136fa8a32e8318c6e0c05d03a29f317ff7114c7b128ea9a80d57142b818dc0f515f950afef5660b";
const SIGN_MESSAGE_HEX: &str = "9bf92051ec0e310dd98463902e79f9ab406f100c26901526e415d8f1be3f9544cef179c7bb977eda3dc93df8acc5476d57c38d0bbe777165a68d50655c20d707";
const SIGN_TX_HEX: &str = "3e9d05cb132f2c766fd1a993bff79e168814d7241683a1bdb95fac2b8500805d009eb99a80000fcc14b5097c6f8d9850a03c275c8ebea1867454a0114d2f7a07";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

#[test]
fn address_base58_matches_noble_kat() {
    let s = signer_fixture();
    assert_eq!(s.public_key_hex(), PUBKEY_HEX);
    assert_eq!(s.address(), ADDRESS);
}

#[test]
fn sign_hash_matches_noble_ed25519_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
}

#[test]
fn sign_message_matches_noble_ed25519_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
}

#[test]
fn sign_transaction_matches_noble_ed25519_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// The Phantom / Backpack / Solflare 64-byte keypair (secret || public)
/// round-trips through `keypair_base58` → `from_keypair_base58`.
#[test]
fn keypair_base58_round_trip_preserves_identity() {
    let s = signer_fixture();
    let b58 = s.keypair_base58();
    let restored = Signer::from_keypair_base58(&b58).unwrap();
    assert_eq!(restored.address(), s.address());
    assert_eq!(restored.public_key_hex(), s.public_key_hex());
}

/// Malformed Base58 / wrong-length keypair payloads must not be accepted.
#[test]
fn from_keypair_base58_rejects_invalid_inputs() {
    assert!(matches!(
        Signer::from_keypair_base58("invalid!!!"),
        Err(SignError::InvalidKeypair(_))
    ));
    // Valid Base58 but wrong length (< 64 bytes decoded).
    assert!(matches!(
        Signer::from_keypair_base58("3J98t1"),
        Err(SignError::InvalidKeypair(_))
    ));
}

/// Compact-u16 header stripping: the single-signature envelope is
/// `0x01 || zeros(64) || message_body`; the stripped body must equal the
/// signable payload verbatim.
#[test]
fn extract_signable_bytes_strips_compact_u16_header_and_signature_slots() {
    let mut tx = vec![1u8]; // compact-u16 `num_sigs = 1`
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(b"message_body");
    let body = Signer::extract_signable_bytes(&tx).unwrap();
    assert_eq!(body, b"message_body");

    assert!(matches!(
        Signer::extract_signable_bytes(&[]),
        Err(SignError::Core(_))
    ));
}

/// Splicing: both the low-level `splice_signature` and the
/// `SignOutput`-accepting `encode_signed_transaction` must produce the
/// same bytes — same 64-byte signature in the first slot, identical tail.
#[test]
fn encode_signed_transaction_matches_splice_signature() {
    let s = signer_fixture();
    let msg_body = b"message_body";
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(msg_body);

    let raw_sig = s.sign_raw(msg_body).to_bytes();
    let spliced_low = Signer::splice_signature(&tx, &raw_sig).unwrap();
    assert_eq!(&spliced_low[1..65], &raw_sig);
    assert_eq!(&spliced_low[65..], msg_body);

    let spliced_high =
        Signer::encode_signed_transaction(&tx, &SignOutput::Ed25519(raw_sig)).unwrap();
    assert_eq!(spliced_low, spliced_high);
}

/// `encode_signed_transaction` must refuse non-Ed25519 variants — this is
/// the type-level contract behind the `EncodeSignedTransaction` trait.
#[test]
fn encode_signed_transaction_rejects_non_ed25519_variant() {
    let s = signer_fixture();
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(b"body");
    let wrong = SignOutput::Ecdsa {
        signature: [0u8; 64],
        v: 0,
    };
    assert!(matches!(
        EncodeSignedTransaction::encode_signed_transaction(&s, &tx, &wrong),
        Err(SignError::Core(_))
    ));
}
