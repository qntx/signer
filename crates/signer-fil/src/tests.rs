//! Filecoin signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` +
//! `@noble/hashes` (`blake2b`) + `@scure/base` run so address, message and
//! transaction assertions are real cross-implementation checks.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `"f1" || base32_lower(BLAKE2b-160(uncompressed_pubkey) || BLAKE2b-32(0x01 || payload))`.
const ADDRESS: &str = "f1utzlswpqelskilx7nxzz3ocwjrsc3ejwwhooyhq";

/// ECDSA over `BLAKE2b-256(MESSAGE)`.
const SIGN_MESSAGE_HEX: &str = "31b80c83405c13758283d37716ebb396927da0a3c5746be422a7d8ab8075087b32533148d950f939bbc960a81257c1e897f7f9a97a6fd0bebe6b66174a301ba200";

/// ECDSA over `BLAKE2b-256(TX_HEX)`.
const SIGN_TX_HEX: &str = "7b30af7ea3acd312a098f62ff59960dd43f8a7bae8b34ddcd7c443dcb568dabb0b8c3f31e5455b58bf61afd1511eb2c60bd06d7c72c5e7261539253093ec813801";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

/// `f1…` protocol-1 address — BLAKE2b-160 of the uncompressed pubkey,
/// followed by a 4-byte `BLAKE2b` checksum over `0x01 || payload`, encoded
/// with RFC 4648 base32 lowercase (no padding).
#[test]
fn address_f1_blake2b_protocol1_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

#[test]
fn sign_message_blake2b256_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
}

#[test]
fn sign_transaction_blake2b256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}
