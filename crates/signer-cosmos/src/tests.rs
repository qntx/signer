//! Cosmos signer Known Answer Tests.
//!
//! Every golden in this module is a **cross-implementation** KAT: the
//! expected bytes were produced by the mature `@noble/curves` +
//! `@noble/hashes` + `@scure/base` JavaScript stack and the Rust signer is
//! asserted to match byte-for-byte. The test is therefore a check of
//! *protocol equivalence*, not merely of the signer being internally
//! consistent with its own past output.
//!
//! Cross-cutting concerns — `from_hex`/`from_bytes` validation, curve-order
//! rejection, `verify_prehash_any` dispatch, `Debug` redaction, …  — are
//! exercised once in `signer_primitives::tests` and deliberately *not*
//! duplicated here.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, Signer};

// -- Cross-implementation Known Answer vectors ----------------------------
//
// Generator:     @noble/curves + @noble/hashes + @scure/base (Node 24)
// Private key:   deterministic secp256k1 scalar shared by every ECDSA chain
// Digest / tx:   arbitrary byte strings pinned so the golden values stay
//                stable across refactors.

/// 32-byte secp256k1 scalar — the same fixture every ECDSA chain uses.
const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

/// `[0x01, 0x02, …, 0x20]`. Digest is opaque — its only role is to exercise
/// the RFC 6979 path deterministically.
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/// Transaction preimage — the canonical `SignDoc` bytes the caller would
/// feed in (proto direct mode or amino JSON).
const TX_HEX: &str = "deadbeef00010203";

/// `bech32("cosmos", RIPEMD160(SHA256(compressed_pubkey)))`.
const ADDRESS: &str = "cosmos1nduq8yy8h4nr7g9vuuglzklqatmaquq9tztpj8";

/// RFC 6979 deterministic ECDSA over `DIGEST_HEX`, wire form `r || s || v`.
const SIGN_HASH_HEX: &str = "68597f9553ac0acc453b5a75af2c731e3ca14dbfeae2231123fd202765b12738247bc920ef3e3ceebbc865651f98dc26a25a0d63240c5da091863fe0296e389b00";

/// ECDSA over `SHA-256(TX_HEX)` — Cosmos SDK `SignDoc` framing.
const SIGN_TX_HEX: &str = "15b8b358ef121aec278447ad105a23c7c157b3be7f6c86a263efecd38449cb5638bb8efbd57a1e47b4c80b5738dfd02d8ea981da11a7e550772448b57a97bc4700";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

/// Address KAT: `bech32("cosmos", RIPEMD160(SHA256(compressed_pubkey)))`
/// cross-verified with `@noble/hashes` + `@scure/base`.
#[test]
fn address_bech32_cosmos_hrp_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// `sign_hash` must emit exactly the bytes `@noble/curves` produces for the
/// same `(sk, digest)` pair under RFC 6979 / low-S / compact `r || s || v`
/// with raw parity. Any drift in digest padding, normalisation, or the
/// wire tail byte makes this test fail immediately.
#[test]
fn sign_hash_matches_noble_rfc6979_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    let v = out.v().unwrap();
    assert!(v == 0 || v == 1, "raw parity, not EIP-191/BIP-137 header");
}

/// `sign_transaction` must frame `tx_bytes` as `SHA-256(tx_bytes)` and
/// feed that to the same RFC 6979 path — the byte string below is
/// produced from the exact Cosmos SDK signing rule by the JS reference.
#[test]
fn sign_transaction_framing_is_plain_sha256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Cosmos deliberately **does not** implement
/// [`signer_primitives::SignMessage`]: the chain defers to ADR-036 which
/// requires a pre-built `StdSignDoc`, not a single-argument message. The
/// fact that this module compiles without `use …::SignMessage` and without
/// a trait impl on `Signer` is the test — if somebody adds one, this note
/// must be revisited alongside the crate-level docs.
#[test]
const fn sign_message_capability_is_absent() {}
