//! TON signer Known Answer Tests.
//!
//! TON wallet addresses depend on the deployed contract code and workchain
//! ID, so [`Signer::address`] returns the raw hex public key — that is the
//! entire "chain-specific" surface. Every sign entry point (hash, message,
//! transaction) delegates to plain Ed25519 over the input bytes, so the
//! three goldens below prove we stay byte-identical with `@noble/curves`
//! under RFC 8032 Test Vector 1.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

/// RFC 8032 Test Vector 1 — shared by SVM / Sui / Aptos as well.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// Ed25519 over `DIGEST_HEX`.
const SIGN_HASH_HEX: &str = "8d917876339a83dc45d1796e557c7baf8bff5e88ab000e166136fa8a32e8318c6e0c05d03a29f317ff7114c7b128ea9a80d57142b818dc0f515f950afef5660b";
/// Ed25519 over `MESSAGE` (`"signer kat v3"` UTF-8).
const SIGN_MESSAGE_HEX: &str = "9bf92051ec0e310dd98463902e79f9ab406f100c26901526e415d8f1be3f9544cef179c7bb977eda3dc93df8acc5476d57c38d0bbe777165a68d50655c20d707";
/// Ed25519 over `TX_HEX`.
const SIGN_TX_HEX: &str = "3e9d05cb132f2c766fd1a993bff79e168814d7241683a1bdb95fac2b8500805d009eb99a80000fcc14b5097c6f8d9850a03c275c8ebea1867454a0114d2f7a07";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

/// Address is the raw hex public key (full wallet address requires a
/// workchain ID and contract code; that lives above this crate).
#[test]
fn address_is_hex_public_key_matches_rfc8032_tv1() {
    let s = signer_fixture();
    assert_eq!(s.public_key_hex(), PUBKEY_HEX);
    assert_eq!(s.address(), PUBKEY_HEX);
}

#[test]
fn sign_hash_matches_noble_ed25519_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    assert!(out.v().is_none(), "plain Ed25519 carries no `v`");
    assert!(out.public_key().is_none());
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
