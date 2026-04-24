//! Filecoin signer Known Answer Tests.
//!
//! Focus: Filecoin-specific wire format. Core ECDSA determinism and key
//! validation live in `signer_primitives::tests`.
//!
//! What this file pins:
//!
//! - **`f1…` address**: BLAKE2b-160 of the uncompressed pubkey, framed
//!   per the protocol-1 spec, cross-verified with `@noble/hashes`.
//! - **Sign contract**: `ECDSA(BLAKE2b-256(tx_bytes))`. Callers that
//!   follow the Filecoin spec pass the CID bytes of their CBOR-encoded
//!   `Message` so that this inner BLAKE2b-256 computes the canonical
//!   per-message sighash. The wrapper is oblivious to whether
//!   `tx_bytes` is a CID or an arbitrary payload — the KAT keeps the
//!   byte-level contract stable.
//! - **Verify round-trip**: `verify_hash` must accept the 65-byte wire
//!   signature against the same BLAKE2b-256 digest.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use blake2::{Blake2b, Digest, digest::consts::U32};

use super::{Sign, SignMessage, Signer};

type Blake2b256 = Blake2b<U32>;

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

/// Verify round-trip: `verify_hash` must accept the wire signature
/// against the `BLAKE2b-256(tx_bytes)` digest, and must reject any
/// single-bit mutation. Same invariant holds for `sign_message`.
#[test]
fn sign_verify_hash_roundtrip_for_tx_and_message() {
    let signer = signer_fixture();

    for input in [hex::decode(TX_HEX).unwrap(), MESSAGE.as_bytes().to_vec()] {
        let digest: [u8; 32] = Blake2b256::digest(&input).into();
        let out = signer.sign_transaction(&input).unwrap();
        signer.verify_hash(&digest, &out.to_bytes()).unwrap();

        let mut tampered = out.to_bytes();
        tampered[0] ^= 0x01;
        assert!(signer.verify_hash(&digest, &tampered).is_err());
    }
}
