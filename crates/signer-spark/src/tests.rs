//! Spark signer Known Answer Tests.
//!
//! Goldens are cross-verified with `@noble/curves` + `@noble/hashes` +
//! `@scure/base`. Cross-cutting plumbing is in `signer_primitives::tests`.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// Spark reuses Bitcoin's legacy P2PKH derivation
/// (`Base58Check(0x00 || RIPEMD160(SHA-256(compressed_pubkey)))`).
const ADDRESS: &str = "1FB3WSwtExGLQUmNp4AQF66tAwAQp6igW3";

/// ECDSA over `double_SHA-256(TX_HEX)` — Bitcoin sighash framing.
const SIGN_TX_HEX: &str = "ea9298254514da415af8f810e618dd08440e24b3e8c9002d46ebd7ebb2bd97fe2a8ddce39abda97c3abddc0017746355be5f32bbf6f236258c3b8cba7e2578a401";

/// BIP-137 message over `MESSAGE` with compressed-P2PKH header `v = 31 | 32`.
const SIGN_MESSAGE_HEX: &str = "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc20";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

#[test]
fn address_p2pkh_matches_base58check_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// Spark transaction sighash: `ECDSA(double_SHA-256(tx))`.
#[test]
fn sign_transaction_double_sha256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Spark inherits BIP-137 compressed-P2PKH message signing from Bitcoin —
/// `v = 31 | 32`, directly consumable by `verifymessage`-compatible tools.
#[test]
fn sign_message_bip137_compressed_p2pkh_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
    let v = out.v().unwrap();
    assert!(
        v == 31 || v == 32,
        "BIP-137 compressed-P2PKH header must be 31 or 32"
    );
}
