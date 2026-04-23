//! Aptos signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` (ed25519) +
//! `@noble/hashes` (sha3-256) run. The four KATs pin every moving piece
//! of the Aptos signing contract: address derivation, domain-separator
//! pre-hash, raw message signing, and domain-prefixed transaction signing.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

/// RFC 8032 Test Vector 1.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `0x` + `hex(SHA3-256(pubkey || 0x00))`.
const ADDRESS: &str = "0x63c5215e87770d17b9f4cd47c777e322f4eb152cfd2054c1080fd9d57c48913b";

/// `SHA3-256("APTOS::RawTransaction")` — pin the domain prefix.
const RAW_TX_DOMAIN_HASH_HEX: &str =
    "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193";

/// Ed25519 over `DIGEST_HEX`.
const SIGN_HASH_HEX: &str = "8d917876339a83dc45d1796e557c7baf8bff5e88ab000e166136fa8a32e8318c6e0c05d03a29f317ff7114c7b128ea9a80d57142b818dc0f515f950afef5660b";
/// Ed25519 over `MESSAGE` (no Aptos domain prefix).
const SIGN_MESSAGE_HEX: &str = "9bf92051ec0e310dd98463902e79f9ab406f100c26901526e415d8f1be3f9544cef179c7bb977eda3dc93df8acc5476d57c38d0bbe777165a68d50655c20d707";
/// Ed25519 over `SHA3-256("APTOS::RawTransaction") || TX_HEX`.
const SIGN_TX_HEX: &str = "b63e642190fb953456a210605d6a72aae8719e974306e9c25d17a4c4d44b412d106b3c261a1a961c0f3121be47b8d02509a1dfac9d45b3a284687ad42c4ac201";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

#[test]
fn address_sha3_256_flagged_pubkey_matches_noble_kat() {
    let s = signer_fixture();
    assert_eq!(s.public_key_hex(), PUBKEY_HEX);
    assert_eq!(s.address(), ADDRESS);
    assert!(s.address().starts_with("0x") && s.address().len() == 66);
}

/// The 32-byte domain-separator prefix `SHA3-256("APTOS::RawTransaction")`
/// is pinned independently so any accidental change to the literal is
/// caught before it reaches a production sighash.
#[test]
fn raw_tx_domain_hash_matches_noble_kat() {
    let pref = super::sha3_256(b"APTOS::RawTransaction");
    assert_eq!(hex::encode(pref), RAW_TX_DOMAIN_HASH_HEX);
}

#[test]
fn sign_hash_matches_noble_ed25519_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    // Aptos attaches the public key to every `Sign`-trait signature so
    // callers can forward it into the on-chain `Ed25519PublicKey` slot.
    assert_eq!(
        hex::encode(out.public_key().unwrap()),
        PUBKEY_HEX,
        "Aptos wraps Ed25519 with the signer's x-only pubkey",
    );
}

/// Aptos message signing is raw Ed25519 — no domain prefix is applied.
#[test]
fn sign_message_is_raw_ed25519_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
}

/// Aptos transaction signing hashes `domain_prefix || bcs_bytes` under
/// Ed25519. The golden confirms the prefix bytes land in the right order.
#[test]
fn sign_transaction_domain_prefixed_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}
