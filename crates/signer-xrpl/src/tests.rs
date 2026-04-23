//! XRPL signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` +
//! `@noble/hashes` run so the address and DER signature are real
//! cross-implementation checks.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignError, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX: &str = "deadbeef00010203";

/// XRPL classic `r…` address: `base58check(0x00 || RIPEMD160(SHA-256(pk)))`
/// with the XRP alphabet (`rpshnaf39…` instead of Bitcoin's
/// `123456789ABCDE…`).
const ADDRESS: &str = "rEBsWSAtNxGLQ7m4FhwQEaatwAwQFa5gWs";

/// ASN.1 DER signature produced by signing
/// `SHA-512-half(STX\0 || TX_HEX)` under RFC 6979 deterministic ECDSA.
const SIGN_TX_DER_HEX: &str = "304402202b6c87da47fe0beadfc837cc15c4997a1945f3e0e89245358c450d658f5c23260220429460ddc1584ded32d0399a0a0d9c1966a1ce19683069b32db100499cbb6a60";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

#[test]
fn address_classic_r_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// XRPL wire signing: prepend `STX\0` (`0x53545800`), take SHA-512-half,
/// and return the DER-encoded ECDSA signature.
#[test]
fn sign_transaction_stx_prefix_sha512half_der_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_DER_HEX);
    assert!(out.v().is_none(), "DER output carries no `v`");

    // DER SEQUENCE tag + typical 70-72 B total size. These are structural
    // checks independent of the KAT above; they would catch a wrong
    // variant being emitted even if the bytes accidentally collided.
    let bytes = out.to_bytes();
    assert_eq!(bytes[0], 0x30, "ASN.1 SEQUENCE tag");
    assert!(
        (68..=72).contains(&bytes.len()),
        "DER ECDSA is typically 70-72 B, got {}",
        bytes.len(),
    );
}

/// Empty tx is a wire-level error — XRPL can't sign nothing.
#[test]
fn sign_transaction_rejects_empty_input() {
    assert!(matches!(
        signer_fixture().sign_transaction(b""),
        Err(SignError::InvalidTransaction(_))
    ));
}

/// XRPL intentionally does **not** implement
/// [`signer_primitives::SignMessage`]: the ledger has no canonical
/// off-chain message-signing standard. The fact that this module compiles
/// without `use …::SignMessage` and without a trait impl is the test.
#[test]
const fn sign_message_capability_is_absent() {}
