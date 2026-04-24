//! Nostr signer Known Answer Tests.
//!
//! Focus: NIP-specific encodings (bech32 `npub1…` / `nsec1…`), NIP-01
//! event-id construction, and the `sign_transaction` → SHA-256 →
//! BIP-340 pipeline. Raw BIP-340 determinism with `aux_rand = [0;32]`
//! is already pinned against the canonical CSV in
//! `signer_primitives::tests`.
//!
//! What this file pins:
//!
//! - **NIP-06 TV1 + TV2**: published protocol KATs for `nsec1…` and
//!   `npub1…` bech32 encoding. These ground our implementation against
//!   the public specification rather than against our own past output.
//! - **HRP rejection**: `from_nsec` refuses an `npub1…` payload.
//! - **`sign_transaction` = `sign_hash(SHA-256(event))`**: the NIP-01
//!   event-id pipeline has two equivalent entry points; their outputs
//!   must be byte-identical.
//! - **Full NIP-01 event signing**: build a real event per the NIP-01
//!   canonical serialization, sign via `sign_transaction`, and verify.
//! - **Verify rejection**: wrong message and single-bit mutations fail.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use sha2::{Digest as _, Sha256};

use super::*;

// -- NIP-06 Test Vector 1 -------------------------------------------------

const TV1_PRIV_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
const TV1_PUB_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const TV1_NSEC: &str = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
const TV1_NPUB: &str = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";

// -- NIP-06 Test Vector 2 -------------------------------------------------

const TV2_PRIV_HEX: &str = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
const TV2_NPUB: &str = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";

fn tv1_signer() -> Signer {
    Signer::from_hex(TV1_PRIV_HEX).unwrap()
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
// NIP-01 event signing pipeline
// ============================================================================

/// `sign_transaction(event)` must equal `sign_hash(sha256(event))`: the
/// two entry points are supposed to converge on the NIP-01 event-id
/// pipeline. This test catches any divergence between them without
/// pinning a signature byte value (which is already covered by the
/// BIP-340 CSV KATs in primitives).
#[test]
fn sign_transaction_equals_sign_hash_of_sha256() {
    let s = tv1_signer();
    let event_json =
        br#"[0,"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",1700000000,1,[],"hi"]"#;
    let direct = s.sign_transaction(event_json).unwrap();
    let event_id: [u8; 32] = Sha256::digest(event_json).into();
    let via_hash = s.sign_hash(&event_id).unwrap();
    assert_eq!(direct.to_bytes(), via_hash.to_bytes());

    // Verify round-trip through the public `Signer::verify` API.
    s.verify(&event_id, &direct.to_bytes()).unwrap();
}

/// End-to-end NIP-01 event signing. Serialize
/// `[0, pubkey, created_at, kind, tags, content]` per NIP-01 (whitespace
/// stripped), hash to obtain the `event.id`, sign via
/// `sign_transaction`, and confirm the result verifies against the
/// computed event id. This is the exact flow a Nostr client follows.
#[test]
fn nip01_event_roundtrip_signs_and_verifies() {
    let s = tv1_signer();
    let pubkey_hex = s.public_key_hex();

    // Canonical NIP-01 serialization (no whitespace, no trailing NL).
    let event_body = format!(r#"[0,"{pubkey_hex}",1700000000,1,[],"hello nostr"]"#);
    let event_id: [u8; 32] = Sha256::digest(event_body.as_bytes()).into();

    let sig = s.sign_transaction(event_body.as_bytes()).unwrap();
    assert_eq!(sig.to_bytes().len(), 64);
    assert_eq!(
        hex::encode(sig.public_key().unwrap()),
        pubkey_hex,
        "Schnorr variant must carry the signer's x-only pubkey",
    );

    // The 64-byte Schnorr signature must verify against the event.id —
    // this is what every Nostr relay will check upon receiving the event.
    s.verify(&event_id, &sig.to_bytes()).unwrap();
}

/// Tampered signature / wrong message must fail `verify`. This is the
/// public NIP-01 entry point used by clients to validate relayed events.
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
