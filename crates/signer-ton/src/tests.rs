//! TON signer Known Answer Tests.
//!
//! TON has no single "personal message signing" standard — production
//! uses differ across `TON Connect` (`Ed25519(SHA-256(0xffff ||
//! "ton-connect" || SHA-256(message)))`), `TonProof`
//! (`"ton-proof-item-v2/"` prefix), and in-contract `sign_raw`. Our
//! signer provides the lowest common denominator: **raw Ed25519 over
//! the input bytes**, leaving the preimage construction to callers.
//!
//! Consequently this file has only one chain-specific invariant to pin:
//! `Signer::address` is the **hex-encoded public key**, not a full
//! wallet address (which depends on contract code and workchain ID).
//! Ed25519 determinism for every entry point is already covered by the
//! RFC 8032 TV1/TV2/TV3 suite in `signer_primitives::tests`; we only
//! assert here that the TON wrapper does not mutate its inputs before
//! hitting the primitive.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

/// RFC 8032 Test Vector 1 — shared by SVM / Sui / Aptos as well.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

/// `Signer::address()` returns the hex public key. The full TON wallet
/// address (`user-friendly` or `raw`) depends on the wallet contract
/// version and workchain ID, both of which live above this crate.
#[test]
fn address_is_hex_public_key() {
    let s = signer_fixture();
    assert_eq!(s.public_key_hex(), PUBKEY_HEX);
    assert_eq!(s.address(), PUBKEY_HEX);
}

/// Every sign entry point on TON delegates to raw Ed25519. Rather than
/// duplicate the RFC 8032 KATs from the primitives suite, we assert the
/// invariant that actually matters: each entry point must round-trip
/// through `verify` against its own input bytes. If any wrapper
/// accidentally starts hashing or prefixing, verification will fail.
#[test]
fn every_entry_point_is_raw_ed25519_and_self_verifies() {
    let s = signer_fixture();

    let cases: &[(&str, &[u8])] = &[
        ("sign_hash", &[1u8; 32]),
        ("sign_message", b"signer kat v3"),
        ("sign_transaction", b"\xde\xad\xbe\xef\x00\x01\x02\x03"),
    ];

    for (label, payload) in cases {
        let out = match *label {
            "sign_hash" => {
                let mut digest = [0u8; 32];
                digest.copy_from_slice(payload);
                s.sign_hash(&digest).unwrap()
            }
            "sign_message" => s.sign_message(payload).unwrap(),
            "sign_transaction" => s.sign_transaction(payload).unwrap(),
            _ => unreachable!(),
        };
        let sig = out.to_bytes();
        assert_eq!(sig.len(), 64, "{label}: raw Ed25519 is 64 bytes");
        assert!(out.v().is_none(), "{label}: no `v` on raw Ed25519");
        assert!(
            out.public_key().is_none(),
            "{label}: no pk on plain Ed25519"
        );
        s.verify(payload, &sig).unwrap_or_else(|e| {
            panic!("{label}: signature must verify against the raw input: {e}")
        });
    }
}
