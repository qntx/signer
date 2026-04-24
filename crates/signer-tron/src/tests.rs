//! TRON signer Known Answer Tests.
//!
//! Focus: TRON-specific wire format. Core ECDSA determinism and key
//! validation live in `signer_primitives::tests`.
//!
//! What this file pins:
//!
//! - **Address**: `Base58Check(0x41 || Keccak256(uncompressed_pk[1..])[12..])`,
//!   cross-verified with `@noble/curves` + `@noble/hashes`.
//! - **Tx sighash**: `ECDSA(SHA-256(raw_data_bytes))` — TRON's txID formula
//!   per the protocol docs (callers feed the proto-encoded `raw_data`).
//! - **Message prefix**: `Keccak-256("\x19TRON Signed Message:\n{len}" || msg)`
//!   with EVM-style `v = 27 | 28` (matches `TronWeb` `signMessageV2`).
//! - **Round-trips**: `verify_hash` accepts the 65-byte tx signature;
//!   `TronWeb`-style `ecrecover` recovers the original address from
//!   `sign_message`.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

use super::{Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `Base58Check(0x41 || Keccak256(uncompressed_pubkey[1..])[12..])`.
const ADDRESS: &str = "TE2H9hWjzYdwzDFRJfx9BFhr4MmjH1CHaz";

/// ECDSA over `SHA-256(TX_HEX)` — TRON uses a plain SHA-256 sighash.
const SIGN_TX_HEX: &str = "15b8b358ef121aec278447ad105a23c7c157b3be7f6c86a263efecd38449cb5638bb8efbd57a1e47b4c80b5738dfd02d8ea981da11a7e550772448b57a97bc4700";

/// ECDSA over `Keccak256("\x19TRON Signed Message:\n{len}" || msg)` with
/// EVM-style header byte `v = 27 | 28` (matches `TronWeb` `signMessageV2`).
const SIGN_MESSAGE_HEX: &str = "04a06ace4ef7d14d87347a0315fb15b6f42953a3894571bb4cfb15eb8a8a9c5708642994ebd54abc37ed627d5fe5c6748c41561053a1daa8ea2116a75ebf34fe1b";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

/// Address KAT — `0x41` version byte, Keccak-256 of the uncompressed
/// pubkey body, `Base58Check` checksum.
#[test]
fn address_base58check_t_prefix_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// TRON transaction sighash: `ECDSA(SHA-256(raw_data_bytes))`.
#[test]
fn sign_transaction_framing_is_plain_sha256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Verify round-trip: the wire signature produced by `sign_transaction`
/// must be accepted by `verify_hash` against `SHA-256(raw_data)`.
#[test]
fn sign_transaction_verify_hash_roundtrip() {
    let signer = signer_fixture();
    let tx = hex::decode(TX_HEX).unwrap();
    let digest: [u8; 32] = Sha256::digest(&tx).into();
    let out = signer.sign_transaction(&tx).unwrap();

    signer.verify_hash(&digest, &out.to_bytes()).unwrap();
    let mut tampered = out.to_bytes();
    tampered[0] ^= 0x01;
    assert!(signer.verify_hash(&digest, &tampered).is_err());
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

/// `TronWeb`'s `trx.ecRecover` works exactly like EVM's `ecrecover`:
/// subtract 27 from the wire `v` to get the raw recovery id, then
/// recover the uncompressed pubkey from the same `Keccak-256(prefix ||
/// msg)` digest the signer hashed. Deriving the TRON address from that
/// pubkey must yield the fixture's own address.
#[test]
fn sign_message_recovers_to_same_tron_address() {
    let signer = signer_fixture();
    let out = signer.sign_message(MESSAGE.as_bytes()).unwrap();
    let sig_bytes = out.to_bytes();
    let v = out.v().unwrap();

    let prefix = format!("\x19TRON Signed Message:\n{}", MESSAGE.len());
    let mut data = Vec::with_capacity(prefix.len() + MESSAGE.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(MESSAGE.as_bytes());
    let digest: [u8; 32] = Keccak256::digest(&data).into();

    let sig = K256Sig::from_slice(&sig_bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(v - 27).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();

    // Re-derive the TRON address (`Base58Check(0x41 || Keccak-256(uncompressed[1..])[12..])`).
    let uncompressed = recovered.to_encoded_point(false);
    let body = &uncompressed.as_bytes()[1..];
    let hash = Keccak256::digest(body);
    let mut payload = Vec::with_capacity(25);
    payload.push(0x41);
    payload.extend_from_slice(&hash[12..]);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    let recovered_addr = bs58::encode(&payload).into_string();

    assert_eq!(recovered_addr, signer.address());
}
