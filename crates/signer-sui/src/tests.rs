//! Sui signer Known Answer Tests.
//!
//! Focus: Sui-specific intent framing (BCS + BLAKE2b-256) and wire
//! signature layout. Raw Ed25519 determinism lives in
//! `signer_primitives::tests` via the three RFC 8032 reference vectors.
//!
//! What this file pins:
//!
//! - **Address**: `0x || hex(BLAKE2b-256(flag(0x00) || pubkey))`.
//! - **BCS ULEB128**: representative 13-byte length encoding and the
//!   127 → 128 continuation boundary.
//! - **Intent signing**: `Ed25519(BLAKE2b-256(intent || bcs(value)))`
//!   for both `PersonalMessage` (`[3,0,0]`) and `TransactionData`
//!   (`[0,0,0]`) — matches the spec at
//!   <https://docs.sui.io/guides/developer/transactions/transaction-auth/intent-signing>.
//! - **Verify round-trip**: the intent digest feeds back through
//!   `Signer::verify`, proving the output is a real Ed25519 signature
//!   over the computed 32-byte digest.
//! - **Wire format**: `flag(0x00) || sig(64) || pk(32)` = 97 bytes.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{ED25519_FLAG, SignMessage, Signer, bcs_serialize_bytes};

/// RFC 8032 Test Vector 1.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `0x` + `hex(BLAKE2b-256(0x00 || pubkey))`.
const ADDRESS: &str = "0x304af458e90e97c841685b8cbbc59b909f3e2cf150df590ada4c81452c29737d";

/// BCS serialization of `MESSAGE` as `Vec<u8>`:
/// `uleb128(len) || bytes`. For 13-byte input this is `0x0d || bytes`.
const BCS_MESSAGE_HEX: &str = "0d7369676e6572206b6174207633";

/// Ed25519 over `BLAKE2b-256([3, 0, 0] || BCS(MESSAGE))` — Sui
/// `IntentScope::PersonalMessage`.
const SIGN_MESSAGE_HEX: &str = "3604fe0b3d39f0f5445e428ee47e1ddfa1a20f03932de0b8fd419a2993cc9555fe61b88e7cd6c97f1127704aadf95cd8ff3b473a08c686d8c02becd9fe162e07";

/// Ed25519 over `BLAKE2b-256([0, 0, 0] || TX_HEX)` — Sui
/// `IntentScope::TransactionData`.
const SIGN_TX_HEX: &str = "e69ae7d37cdc0b67dd79da34d2562f7077aeefc1a5084c547d5d245caee6217c21d497ce2521f28b4ef8a81a4f07bdc5a586017248b52e0e306ea899f5354808";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

/// Pubkey + BLAKE2b-256 address under the Ed25519 flag (`0x00`).
#[test]
fn address_blake2b_of_flagged_pubkey_matches_noble_kat() {
    let s = signer_fixture();
    assert_eq!(hex::encode(s.public_key_bytes()), PUBKEY_HEX);
    assert_eq!(s.address(), ADDRESS);
}

/// Confirm our ULEB128 implementation matches the canonical BCS framing
/// byte-for-byte for the representative message length used in
/// [`sign_message`](super::Signer).
#[test]
fn bcs_serialize_bytes_matches_noble_kat() {
    let encoded = bcs_serialize_bytes(MESSAGE.as_bytes());
    assert_eq!(hex::encode(encoded), BCS_MESSAGE_HEX);
}

/// Double-check the ULEB128 boundary: 127 → 1 byte, 128 → `0x80 0x01`.
#[test]
fn bcs_uleb128_continuation_boundary() {
    let msg_127 = bcs_serialize_bytes(&[0u8; 127]);
    assert_eq!(msg_127[0], 127, "127 still fits in a single byte");
    assert_eq!(msg_127.len(), 128);

    let msg_128 = bcs_serialize_bytes(&[0u8; 128]);
    assert_eq!(&msg_128[..2], &[0x80, 0x01], "128 triggers continuation");
    assert_eq!(msg_128.len(), 130);
}

/// Sui personal-message intent signing: BCS-encode the message, prepend
/// `IntentScope::PersonalMessage = [3, 0, 0]`, BLAKE2b-256, then sign.
/// The KAT is cross-verified with `@noble/hashes` + `@noble/curves`.
#[test]
fn sign_message_intent_blake2b_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
    assert_eq!(
        hex::encode(out.public_key().unwrap()),
        PUBKEY_HEX,
        "Sui attaches the pubkey for its 97-byte wire signature",
    );
}

/// Sui transaction intent signing: prepend
/// `IntentScope::TransactionData = [0, 0, 0]`, BLAKE2b-256, then sign.
#[test]
fn sign_transaction_intent_blake2b_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Verify round-trip: recompute the intent digest locally, then prove
/// that `Signer::verify` accepts the signature over that exact digest.
/// This catches any drift in the intent prefix bytes or the BLAKE2b-256
/// parametrisation.
#[test]
fn sign_message_intent_digest_verifies_through_primitive() {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let s = signer_fixture();
    let bcs = bcs_serialize_bytes(MESSAGE.as_bytes());

    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(&[0x03, 0x00, 0x00]);
    hasher.update(&bcs);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).unwrap();

    let out = s.sign_message(MESSAGE.as_bytes()).unwrap();
    let sig = out.to_bytes();
    s.verify(&digest, &sig).unwrap();

    // Tampering the signature must break verification.
    let mut tampered = sig;
    tampered[0] ^= 0x01;
    assert!(s.verify(&digest, &tampered).is_err());
}

/// Sui's 97-byte on-chain wire signature: `flag(0x00) || sig(64) || pk(32)`.
#[test]
fn encode_signature_produces_97_byte_sui_wire_form() {
    let s = signer_fixture();
    let sig = s.sign_raw(b"data");
    let encoded = s.encode_signature(&sig);
    assert_eq!(encoded.len(), 97);
    assert_eq!(encoded[0], ED25519_FLAG);
    assert_eq!(&encoded[1..65], &sig.to_bytes());
    assert_eq!(&encoded[65..], s.public_key_bytes());
}
