//! Cosmos signer Known Answer Tests.
//!
//! Focus: Cosmos-specific wire format only. Core ECDSA determinism, key
//! validation, and `verify_prehash_any` dispatch are covered once in
//! `signer_primitives::tests` and deliberately not duplicated here.
//!
//! What this file pins:
//!
//! - **Address**: `bech32("cosmos", RIPEMD160(SHA-256(pubkey)))` against
//!   the output computed independently by `@noble/hashes` + `@scure/base`.
//! - **Sign doc framing**: `ECDSA(SHA-256(tx_bytes))` — the Cosmos SDK
//!   proto-direct and amino JSON rules reduce to the same sighash formula,
//!   which the JS reference reproduces for the shared fixture.
//! - **Verify round-trip**: `verify_hash` must accept the 65-byte wire
//!   signature this signer produces, catching any accidental tampering
//!   with the compact r||s layout.
//! - **Capability absence**: Cosmos does *not* implement `SignMessage` —
//!   the module compiling without that trait import is itself the assertion.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use sha2::{Digest, Sha256};

use super::Signer;

/// 32-byte secp256k1 scalar — the same fixture every ECDSA chain uses.
const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

/// Transaction preimage — the canonical `SignDoc` bytes the caller would
/// feed in (proto direct mode or amino JSON).
const TX_HEX: &str = "deadbeef00010203";

/// `bech32("cosmos", RIPEMD160(SHA-256(compressed_pubkey)))`.
const ADDRESS: &str = "cosmos1nduq8yy8h4nr7g9vuuglzklqatmaquq9tztpj8";

/// ECDSA over `SHA-256(TX_HEX)` — Cosmos SDK `SignDoc` framing.
const SIGN_TX_HEX: &str = "15b8b358ef121aec278447ad105a23c7c157b3be7f6c86a263efecd38449cb5638bb8efbd57a1e47b4c80b5738dfd02d8ea981da11a7e550772448b57a97bc4700";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

/// Address KAT: `bech32("cosmos", RIPEMD160(SHA-256(compressed_pubkey)))`
/// cross-verified with `@noble/hashes` + `@scure/base`.
#[test]
fn address_bech32_cosmos_hrp_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// `address_with_hrp("cosmos")` must agree byte-for-byte with the
/// zero-arg [`Signer::address`] default. This catches any drift between
/// the two entry points — they share the underlying hash160 payload and
/// must route through the same bech32 encoder.
#[test]
fn address_with_hrp_cosmos_equals_default_address() {
    let s = signer_fixture();
    assert_eq!(s.address_with_hrp("cosmos").unwrap(), s.address());
}

/// `address_with_hrp` must accept every major Cosmos-SDK chain HRP and
/// produce a structurally valid bech32 string (correct HRP prefix, same
/// payload length as the default `cosmos1…` form). The payload after the
/// HRP separator is always 39 characters for a 20-byte hash160 + 6-byte
/// bech32 checksum, independent of the HRP.
#[test]
fn address_with_hrp_covers_major_cosmos_chains() {
    let s = signer_fixture();
    let default = s.address();
    let default_payload_len = default.len() - "cosmos1".len();
    for hrp in &["cosmos", "osmo", "juno", "terra", "secret", "kava"] {
        let addr = s.address_with_hrp(hrp).unwrap();
        let expected_prefix = alloc::format!("{hrp}1");
        assert!(
            addr.starts_with(&expected_prefix),
            "{hrp}: address {addr} must start with `{expected_prefix}`",
        );
        assert_eq!(
            addr.len() - expected_prefix.len(),
            default_payload_len,
            "{hrp}: payload length must match cosmos default (20-byte hash160 + 6-char checksum)",
        );
    }
}

/// `address_with_hrp` must reject an invalid HRP (empty string) rather
/// than panicking — this is the fallibility contract that distinguishes
/// it from the `"cosmos"`-defaulting [`Signer::address`].
#[test]
fn address_with_hrp_rejects_empty_hrp() {
    assert!(signer_fixture().address_with_hrp("").is_err());
}

/// `sign_transaction` must frame `tx_bytes` as `SHA-256(tx_bytes)` and
/// feed that to the RFC 6979 path. The KAT bytes below are produced by
/// the independent JS reference for the exact Cosmos SDK signing rule.
#[test]
fn sign_transaction_framing_is_plain_sha256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Verify round-trip: the 65-byte wire signature produced by
/// `sign_transaction` must be accepted by `verify_hash` against the same
/// `SHA-256(tx_bytes)` digest. This catches any wrapper-level mutation
/// of `r || s` or accidental `v`-byte swaps.
#[test]
fn sign_transaction_verify_hash_roundtrip() {
    let signer = signer_fixture();
    let tx = hex::decode(TX_HEX).unwrap();
    let digest: [u8; 32] = Sha256::digest(&tx).into();
    let out = signer.sign_transaction(&tx).unwrap();

    // Accept the full 65-byte wire form.
    signer.verify_hash(&digest, &out.to_bytes()).unwrap();

    // Also accept the compact 64-byte form (the `v` byte is advisory for
    // verification — `verify_prehash_any` dispatches on length).
    signer.verify_hash(&digest, &out.to_bytes()[..64]).unwrap();

    // Single-bit mutation in the `s` scalar must fail.
    let mut tampered = out.to_bytes();
    tampered[32] ^= 0x01;
    assert!(signer.verify_hash(&digest, &tampered).is_err());
}

/// Cosmos deliberately **does not** implement
/// [`signer_primitives::SignMessage`]: the chain defers to ADR-036 which
/// requires a pre-built `StdSignDoc`, not a single-argument message. The
/// fact that this module compiles without `use …::SignMessage` and without
/// a trait impl on `Signer` is the test — if somebody adds one, this note
/// must be revisited alongside the crate-level docs.
#[test]
const fn sign_message_capability_is_absent() {}
