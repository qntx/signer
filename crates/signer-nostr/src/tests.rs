//! Nostr signer Known Answer Tests.
//!
//! Two layers of authority pin the test values:
//!
//! - **NIP-06 Test Vectors 1 + 2** for the `nsec1…` / `npub1…` bech32
//!   encoding and x-only pubkey derivation — these are *protocol* KATs
//!   published alongside the spec.
//! - **Cross-implementation goldens** (`@noble/curves` BIP-340 Schnorr
//!   with `auxRand = [0u8; 32]`) for the three signing entry points.
//!   Matching them byte-for-byte proves our `k256::schnorr` wrapping
//!   does not accidentally deviate from the reference.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::*;

// -- NIP-06 Test Vector 1 -------------------------------------------------

const TV1_PRIV_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
const TV1_PUB_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const TV1_NSEC: &str = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
const TV1_NPUB: &str = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";

// -- NIP-06 Test Vector 2 -------------------------------------------------

const TV2_PRIV_HEX: &str = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
const TV2_NPUB: &str = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";

// -- Cross-implementation KATs (BIP-340 with aux_rand = zeros) ------------

const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// BIP-340 Schnorr over `DIGEST_HEX`, `aux_rand = [0u8; 32]`.
const SIGN_HASH_HEX: &str = "38170398b948d77ec62412ad4d8b4e8b098e56a2dd3186be11d86d7ef1371c4e3c6eebc56cd475874ef94771a179b4d46605af2ddc0c983a540de615ad32f677";
/// BIP-340 Schnorr over the raw `MESSAGE` bytes — no implicit SHA-256.
const SIGN_MESSAGE_HEX: &str = "161451d4e7edde557075f7f94fecdef168378ab24455a72da9c24a63e4e1de288c28d22e664c0809815bc7898b1181b166a922f29bb0047ac18cc0be72d6d779";
/// BIP-340 Schnorr over `SHA-256(TX_HEX)` — NIP-01 event-id path.
const SIGN_TX_HEX: &str = "25493b03c3f359bdb13c637e903852c9c34024414b8d9981abd9fdd7afafa2b24bd018b1d3bf5c206da29af504fc80116fce6472f3c7d268cba288dc009227ce";

fn tv1_signer() -> Signer {
    Signer::from_hex(TV1_PRIV_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

// ============================================================================
// NIP-06 bech32 and x-only public key KATs
// ============================================================================

#[test]
fn nip06_tv1_xonly_pubkey_matches_kat() {
    let s = tv1_signer();
    assert_eq!(s.public_key_hex(), TV1_PUB_HEX);
    assert_eq!(s.public_key_bytes().len(), 32);
}

#[test]
fn nip06_tv1_npub_and_nsec_match_kat() {
    let s = tv1_signer();
    assert_eq!(s.address(), TV1_NPUB);
    assert_eq!(s.nsec().as_str(), TV1_NSEC);
}

#[test]
fn nip06_tv2_npub_matches_kat() {
    let s = Signer::from_hex(TV2_PRIV_HEX).unwrap();
    assert_eq!(s.address(), TV2_NPUB);
}

/// `nsec1…` bech32 round-trip — decoding a signer's own `nsec` must
/// reproduce the same public identity.
#[test]
fn nsec_round_trip_preserves_public_identity() {
    let s = tv1_signer();
    let reloaded = Signer::from_nsec(s.nsec().as_str()).unwrap();
    assert_eq!(reloaded.public_key_hex(), s.public_key_hex());
}

/// HRP must match: an `npub1…` passed where an `nsec1…` is expected is a
/// bech32 error, not a silent fall-through.
#[test]
fn from_nsec_rejects_wrong_hrp_and_malformed_bech32() {
    assert!(matches!(
        Signer::from_nsec(TV1_NPUB),
        Err(SignError::Bech32(_))
    ));
    assert!(matches!(
        Signer::from_nsec("nsec1notvalid"),
        Err(SignError::Bech32(_))
    ));
}

// ============================================================================
// BIP-340 Schnorr cross-implementation KATs
// ============================================================================

/// `sign_hash` takes a 32-byte `event.id` and signs it with BIP-340
/// (`aux_rand` zero). Must match `@noble/curves` byte-for-byte.
#[test]
fn sign_hash_matches_noble_bip340_kat() {
    let out = tv1_signer().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    assert!(out.v().is_none(), "BIP-340 Schnorr has no recovery id");
    assert_eq!(
        hex::encode(out.public_key().unwrap()),
        TV1_PUB_HEX,
        "output must carry the signer's x-only pubkey",
    );
}

/// `sign_message` passes bytes verbatim into BIP-340 — no implicit hash.
#[test]
fn sign_message_is_raw_bip340_matches_noble_kat() {
    let out = tv1_signer().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_HEX);
}

/// `sign_transaction` hashes the serialized NIP-01 event with SHA-256
/// first, then signs the resulting event id with BIP-340.
#[test]
fn sign_transaction_sha256_event_id_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = tv1_signer().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Sanity: `sign_transaction(event)` must equal
/// `sign_hash(sha256(event))` — cheap equivalence check that keeps the
/// two sister code paths from drifting apart.
#[test]
fn sign_transaction_equals_sign_hash_of_sha256() {
    use sha2::{Digest as _, Sha256};
    let s = tv1_signer();
    let event_json =
        br#"[0,"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",1700000000,1,[],"hi"]"#;
    let direct = s.sign_transaction(event_json).unwrap();
    let event_id: [u8; 32] = Sha256::digest(event_json).into();
    let via_hash = s.sign_hash(&event_id).unwrap();
    assert_eq!(direct.to_bytes(), via_hash.to_bytes());
}

/// Tampered signature / wrong message must fail `verify`. This is
/// chain-specific because `Signer::verify` is the public NIP-01 entry
/// point used by clients to validate relayed events.
#[test]
fn verify_rejects_tampered_signature_and_wrong_message() {
    let s = tv1_signer();
    let msg = b"authentic message";
    let sig = s.sign_message(msg).unwrap().to_bytes();

    let mut tampered = sig.clone();
    tampered[0] ^= 0x01;
    assert!(s.verify(msg, &tampered).is_err());
    assert!(s.verify(b"different message", &sig).is_err());
}

#[cfg(feature = "kobe")]
mod kobe_integration {
    use zeroize::Zeroizing;

    use super::{Signer, TV1_NPUB, TV1_PRIV_HEX, TV1_PUB_HEX};

    /// NIP-06 TV1 surfaced through a `kobe_nostr::DerivedAccount` — the
    /// idiomatic integration path for consumers that derive an account
    /// from a mnemonic.
    fn tv1_derived_account() -> kobe_nostr::DerivedAccount {
        let mut sk = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(TV1_PRIV_HEX, sk.as_mut_slice()).unwrap();
        let pk = hex::decode(TV1_PUB_HEX).unwrap();
        kobe_nostr::DerivedAccount::new(
            String::from("m/44'/1237'/0'/0/0"),
            sk,
            pk,
            String::from(TV1_NPUB),
        )
    }

    #[test]
    fn from_derived_matches_nip06_tv1_kat() {
        let acct = tv1_derived_account();
        let via_derived = Signer::from_derived(&acct).unwrap();
        let via_hex = Signer::from_hex(acct.private_key_hex().as_str()).unwrap();
        assert_eq!(via_derived.address(), TV1_NPUB);
        assert_eq!(via_derived.address(), via_hex.address());
    }
}
