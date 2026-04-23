//! TRON signer Known Answer Tests.
//!
//! Goldens are produced by the independent `@noble/curves` +
//! `@noble/hashes` + `@scure/base` JS stack so the assertions are real
//! cross-implementation checks, not self-confirming dumps.
//!
//! Cross-cutting plumbing (constructor validation, determinism,
//! `Debug` redaction) lives in `signer_primitives::tests`.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `Base58Check(0x41 || Keccak256(uncompressed_pubkey[1..])[12..])`.
const ADDRESS: &str = "TE2H9hWjzYdwzDFRJfx9BFhr4MmjH1CHaz";

/// RFC 6979 deterministic ECDSA over `DIGEST_HEX`, raw parity tail.
const SIGN_HASH_HEX: &str = "68597f9553ac0acc453b5a75af2c731e3ca14dbfeae2231123fd202765b12738247bc920ef3e3ceebbc865651f98dc26a25a0d63240c5da091863fe0296e389b00";

/// ECDSA over `SHA-256(TX_HEX)` — TRON uses a plain SHA-256 sighash.
const SIGN_TX_HEX: &str = "15b8b358ef121aec278447ad105a23c7c157b3be7f6c86a263efecd38449cb5638bb8efbd57a1e47b4c80b5738dfd02d8ea981da11a7e550772448b57a97bc4700";

/// ECDSA over `Keccak256("\x19TRON Signed Message:\n{len}" || msg)` with
/// EVM-style header byte `v = 27 | 28` (matches `TronWeb` `signMessageV2`).
const SIGN_MESSAGE_HEX: &str = "04a06ace4ef7d14d87347a0315fb15b6f42953a3894571bb4cfb15eb8a8a9c5708642994ebd54abc37ed627d5fe5c6748c41561053a1daa8ea2116a75ebf34fe1b";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

/// Address KAT — `0x41` version byte, Keccak-256 of the uncompressed
/// pubkey body, `Base58Check` checksum.
#[test]
fn address_base58check_t_prefix_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

#[test]
fn sign_hash_matches_noble_rfc6979_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    let v = out.v().unwrap();
    assert!(v == 0 || v == 1, "sign_hash returns raw parity");
}

/// TRON transaction sighash: `ECDSA(SHA-256(tx_bytes))`.
#[test]
fn sign_transaction_framing_is_plain_sha256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// TRON message signing: `Keccak256("\x19TRON Signed Message:\n{len}" ||
/// msg)` with EVM-style `v = 27 | 28` wire header.
#[test]
fn sign_message_tron_prefix_keccak_v27_28_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
    let v = out.v().unwrap();
    assert!(v == 27 || v == 28, "TronWeb header byte must be 27 or 28");
}
