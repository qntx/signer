//! Sui signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` (ed25519) +
//! `@noble/hashes` (blake2b) run. The KATs pin every moving piece of the
//! Sui intent-based signing contract: address derivation, BCS length
//! prefix, personal-message intent digest, and transaction intent digest.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{ED25519_FLAG, Sign, SignMessage, Signer, bcs_serialize_bytes};

/// RFC 8032 Test Vector 1.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `0x` + `hex(BLAKE2b-256(0x00 || pubkey))`.
const ADDRESS: &str = "0x304af458e90e97c841685b8cbbc59b909f3e2cf150df590ada4c81452c29737d";

/// BCS serialization of `MESSAGE` as `Vec<u8>`:
/// `uleb128(len) || bytes`. For 13-byte input this is `0x0d || bytes`.
const BCS_MESSAGE_HEX: &str = "0d7369676e6572206b6174207633";

/// Ed25519 over `DIGEST_HEX` (no intent prefix — `sign_hash` is raw).
const SIGN_HASH_HEX: &str = "8d917876339a83dc45d1796e557c7baf8bff5e88ab000e166136fa8a32e8318c6e0c05d03a29f317ff7114c7b128ea9a80d57142b818dc0f515f950afef5660b";

/// Ed25519 over `BLAKE2b-256([3, 0, 0] || BCS(MESSAGE))` — Sui
/// `IntentScope::PersonalMessage`.
const SIGN_MESSAGE_HEX: &str = "3604fe0b3d39f0f5445e428ee47e1ddfa1a20f03932de0b8fd419a2993cc9555fe61b88e7cd6c97f1127704aadf95cd8ff3b473a08c686d8c02becd9fe162e07";

/// Ed25519 over `BLAKE2b-256([0, 0, 0] || TX_HEX)` — Sui
/// `IntentScope::TransactionData`.
const SIGN_TX_HEX: &str = "e69ae7d37cdc0b67dd79da34d2562f7077aeefc1a5084c547d5d245caee6217c21d497ce2521f28b4ef8a81a4f07bdc5a586017248b52e0e306ea899f5354808";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
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

#[test]
fn sign_hash_matches_noble_ed25519_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    assert_eq!(
        hex::encode(out.public_key().unwrap()),
        PUBKEY_HEX,
        "Sui attaches the pubkey for its 97-byte wire signature",
    );
}

/// Sui personal-message intent signing: BCS-encode the message, prepend
/// `IntentScope::PersonalMessage = [3, 0, 0]`, BLAKE2b-256, then sign.
#[test]
fn sign_message_intent_blake2b_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
}

/// Sui transaction intent signing: prepend
/// `IntentScope::TransactionData = [0, 0, 0]`, BLAKE2b-256, then sign.
#[test]
fn sign_transaction_intent_blake2b_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
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
