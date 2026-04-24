//! Aptos signer Known Answer Tests.
//!
//! Focus: Aptos-specific domain prefix and BCS-framed transaction
//! signing. Raw Ed25519 determinism lives in `signer_primitives::tests`
//! via the three RFC 8032 reference vectors.
//!
//! What this file pins:
//!
//! - **Address**: `0x || hex(SHA3-256(pubkey || scheme_byte(0x00)))`.
//! - **Domain hash**: the 32-byte `SHA3-256("APTOS::RawTransaction")`
//!   constant exactly as the Aptos Move runtime expects.
//! - **Transaction signing**: `Ed25519(domain_prefix || bcs_raw_tx)` —
//!   callers feed the BCS-serialized `RawTransaction`, the signer
//!   handles the prefix. The domain separator is distinct from the
//!   hash used for `wait_for_transaction` queries (`"Aptos::Transaction"`),
//!   which is a common point of confusion.
//! - **Sign round-trip**: the signing message and signature feed back
//!   through the primitive verify path.
//! - **Capability**: `sign_message` is raw Ed25519, matching the
//!   decision that Aptos has no built-in personal-message standard.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

/// RFC 8032 Test Vector 1.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `0x` + `hex(SHA3-256(pubkey || 0x00))`.
const ADDRESS: &str = "0x63c5215e87770d17b9f4cd47c777e322f4eb152cfd2054c1080fd9d57c48913b";

/// `SHA3-256("APTOS::RawTransaction")` — pin the domain prefix.
const RAW_TX_DOMAIN_HASH_HEX: &str =
    "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193";

/// Ed25519 over `SHA3-256("APTOS::RawTransaction") || TX_HEX`.
const SIGN_TX_HEX: &str = "b63e642190fb953456a210605d6a72aae8719e974306e9c25d17a4c4d44b412d106b3c261a1a961c0f3121be47b8d02509a1dfac9d45b3a284687ad42c4ac201";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
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

/// Aptos transaction signing hashes `domain_prefix || bcs_bytes` under
/// Ed25519. The golden confirms the prefix bytes land in the right order.
#[test]
fn sign_transaction_domain_prefixed_matches_noble_kat() {
    let out = signer_fixture()
        .sign_transaction(&hex::decode(TX_HEX).unwrap())
        .unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
    assert_eq!(
        hex::encode(out.public_key().unwrap()),
        PUBKEY_HEX,
        "Aptos bundles the pubkey on every Sign-trait signature",
    );
}

/// Verify round-trip: the signature `sign_transaction` emits must verify
/// against the manually constructed `domain_prefix || bcs_bytes` signing
/// message. This catches any mismatch in prefix bytes or byte ordering
/// before production traffic ever sees it.
#[test]
fn sign_transaction_signing_message_verifies_through_primitive() {
    let s = signer_fixture();
    let tx = hex::decode(TX_HEX).unwrap();

    let prefix = super::sha3_256(b"APTOS::RawTransaction");
    let mut msg = Vec::with_capacity(32 + tx.len());
    msg.extend_from_slice(&prefix);
    msg.extend_from_slice(&tx);

    let out = s.sign_transaction(&tx).unwrap();
    s.verify(&msg, &out.to_bytes()).unwrap();

    // Flip the prefix: verification must fail.
    let mut wrong = msg.clone();
    wrong[0] ^= 0x01;
    assert!(s.verify(&wrong, &out.to_bytes()).is_err());
}

/// Aptos `sign_message` is raw Ed25519 (no domain prefix), matching the
/// `sign_raw` API and leaving personal-message framing to higher-level
/// protocols like wallet adapters. Verify round-trip proves the wrapper
/// does not reframe the message before hitting the primitive.
#[test]
fn sign_message_is_raw_ed25519_and_verifies() {
    let s = signer_fixture();
    let out = s.sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_bytes().len(), 64);
    s.verify(MESSAGE.as_bytes(), &out.to_bytes()).unwrap();
    assert!(s.verify(b"different", &out.to_bytes()).is_err());
}
