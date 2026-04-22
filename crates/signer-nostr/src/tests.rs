//! Unit tests for the Nostr signer.
//!
//! Key-derivation test vectors are sourced from
//! [NIP-06](https://nips.nostr.com/6). BIP-340 signing is validated by
//! round-tripping `sign` through `verify`, and by comparing against k256's
//! own published test vectors indirectly (the library is the source of truth
//! for the primitive).

#![allow(
    clippy::indexing_slicing,
    reason = "tests index into fixed-size signature/key buffers with known lengths"
)]

use sha2::{Digest as _, Sha256};

use super::*;

#[cfg(feature = "kobe")]
mod kobe_integration {
    use zeroize::Zeroizing;

    use super::Signer;

    /// Hand-built `DerivedAccount` using NIP-06 test vector 1 material.
    fn tv1_derived_account() -> kobe_nostr::DerivedAccount {
        kobe_nostr::DerivedAccount::new(
            String::from("m/44'/1237'/0'/0/0"),
            Zeroizing::new(String::from(
                "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
            )),
            String::from("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"),
            String::from("npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu"),
        )
    }

    #[test]
    fn from_derived_matches_from_hex() {
        let acct = tv1_derived_account();
        let via_bytes = Signer::from_derived(&acct).unwrap();
        let via_hex = Signer::from_hex(&acct.private_key).unwrap();
        assert_eq!(via_bytes.address(), via_hex.address());
        assert_eq!(
            via_bytes.address(),
            "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu"
        );
    }
}

/// NIP-06 test vector 1: private key hex.
const TV1_PRIV_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
/// NIP-06 test vector 1: x-only public key hex.
const TV1_PUB_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
/// NIP-06 test vector 1: NIP-19 nsec encoding.
const TV1_NSEC: &str = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
/// NIP-06 test vector 1: NIP-19 npub encoding.
const TV1_NPUB: &str = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";

/// NIP-06 test vector 2: private key hex.
const TV2_PRIV_HEX: &str = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
/// NIP-06 test vector 2: NIP-19 npub encoding.
const TV2_NPUB: &str = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";

fn tv1_signer() -> Signer {
    Signer::from_hex(TV1_PRIV_HEX).unwrap()
}

#[test]
fn from_hex_and_from_bytes_agree() {
    let from_hex = Signer::from_hex(TV1_PRIV_HEX).unwrap();

    let raw = hex::decode(TV1_PRIV_HEX).unwrap();
    let bytes: [u8; 32] = raw.try_into().unwrap();
    let from_bytes = Signer::from_bytes(&bytes).unwrap();

    assert_eq!(from_hex.public_key_hex(), from_bytes.public_key_hex());
}

#[test]
fn from_hex_accepts_0x_prefix() {
    let with_prefix = Signer::from_hex(&alloc::format!("0x{TV1_PRIV_HEX}")).unwrap();
    let without_prefix = Signer::from_hex(TV1_PRIV_HEX).unwrap();
    assert_eq!(
        with_prefix.public_key_hex(),
        without_prefix.public_key_hex(),
    );
}

#[test]
fn from_hex_rejects_wrong_length() {
    assert!(Signer::from_hex("deadbeef").is_err(), "short key rejected");
    assert!(
        Signer::from_hex(&"aa".repeat(33)).is_err(),
        "long key rejected",
    );
}

#[test]
fn from_hex_rejects_invalid_scalar() {
    // Zero is not a valid secp256k1 scalar.
    assert!(Signer::from_hex(&"00".repeat(32)).is_err());
}

#[test]
fn public_key_is_xonly_32_bytes() {
    let s = tv1_signer();
    assert_eq!(s.public_key_bytes().len(), 32);
    assert_eq!(s.public_key_hex().len(), 64);
    assert_eq!(s.public_key_hex(), TV1_PUB_HEX);
}

#[test]
fn nip19_npub_kat_vector1() {
    assert_eq!(tv1_signer().address(), TV1_NPUB);
}

#[test]
fn nip19_nsec_kat_vector1() {
    assert_eq!(tv1_signer().nsec().as_str(), TV1_NSEC);
}

#[test]
fn nip19_nsec_roundtrip_vector1() {
    let s = tv1_signer();
    let reloaded = Signer::from_nsec(s.nsec().as_str()).unwrap();
    assert_eq!(s.public_key_hex(), reloaded.public_key_hex());
}

#[test]
fn nip19_npub_kat_vector2() {
    let s = Signer::from_hex(TV2_PRIV_HEX).unwrap();
    assert_eq!(s.address(), TV2_NPUB);
}

#[test]
fn from_nsec_rejects_wrong_hrp() {
    // A valid `npub` should be rejected when we ask for `nsec`.
    let err = Signer::from_nsec(TV1_NPUB).expect_err("npub is not an nsec");
    assert!(
        matches!(err, SignError::Bech32(_)),
        "expected Bech32 variant, got {err:?}",
    );
}

#[test]
fn from_nsec_rejects_malformed() {
    let err = Signer::from_nsec("nsec1notvalid").expect_err("malformed bech32");
    assert!(matches!(err, SignError::Bech32(_)));
}

#[test]
fn sign_hash_roundtrip() {
    let s = tv1_signer();
    let event_id = [0x42u8; 32];
    let out = s.sign_hash(&event_id).unwrap();

    assert_eq!(out.signature.len(), 64, "BIP-340 signature is 64 bytes");
    assert!(out.recovery_id.is_none(), "Schnorr has no recovery id");
    assert_eq!(
        out.public_key.as_deref().map(<[u8]>::len),
        Some(32),
        "x-only public key is 32 bytes",
    );
    assert_eq!(out.public_key.as_deref(), Some(&s.public_key_bytes()[..]));

    // Signature must verify against the same 32-byte message.
    s.verify(&event_id, &out.signature).unwrap();
}

#[test]
fn sign_hash_is_deterministic() {
    let s = tv1_signer();
    let event_id = [0u8; 32];
    let a = s.sign_hash(&event_id).unwrap();
    let b = s.sign_hash(&event_id).unwrap();
    assert_eq!(a.signature, b.signature, "deterministic signing");
}

#[test]
fn sign_hash_rejects_non_32_byte_input() {
    let s = tv1_signer();
    assert!(s.sign_hash(&[0u8; 31]).is_err());
    assert!(s.sign_hash(&[0u8; 33]).is_err());
}

#[test]
fn sign_message_roundtrip() {
    let s = tv1_signer();
    let msg = b"a Nostr message";
    let out = s.sign_message(msg).unwrap();
    assert_eq!(out.signature.len(), 64);
    s.verify(msg, &out.signature).unwrap();
}

#[test]
fn sign_transaction_matches_sign_hash_of_sha256() {
    let s = tv1_signer();
    let event_json =
        br#"[0,"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",1700000000,1,[],"hi"]"#;

    let via_transaction = s.sign_transaction(event_json).unwrap();
    let digest = Sha256::digest(event_json);
    let via_hash = s.sign_hash(&digest).unwrap();

    assert_eq!(via_transaction.signature, via_hash.signature);
}

#[test]
fn verify_rejects_wrong_signature() {
    let s = tv1_signer();
    let msg = b"authentic message";
    let out = s.sign_message(msg).unwrap();

    let mut tampered = out.signature.clone();
    tampered[0] ^= 0x01;
    assert!(
        s.verify(msg, &tampered).is_err(),
        "tampered signature must not verify",
    );
    assert!(
        s.verify(b"different message", &out.signature).is_err(),
        "original signature must not verify for a different message",
    );
}

#[test]
fn sign_output_public_key_is_xonly() {
    let s = tv1_signer();
    let out = s.sign_hash(&[0u8; 32]).unwrap();
    let pk = out
        .public_key
        .expect("schnorr output carries x-only pubkey");
    assert_eq!(pk.len(), 32);
    assert_eq!(hex::encode(&pk), TV1_PUB_HEX);
}

#[cfg(feature = "getrandom")]
#[test]
fn random_signer_produces_valid_signatures() {
    let s = Signer::random();
    assert_eq!(s.public_key_bytes().len(), 32);
    assert!(s.address().starts_with("npub1"));
    let msg = b"random-key message";
    let out = s.sign_message(msg).unwrap();
    s.verify(msg, &out.signature).unwrap();
}

mod sign_trait {
    use signer_primitives::Sign;

    use super::*;

    #[test]
    fn delegate_impl_matches_inherent() {
        let s = tv1_signer();
        let msg = b"delegate";
        let via_trait = <Signer as Sign>::sign_message(&s, msg).unwrap();
        let via_inherent = s.sign_message(msg).unwrap();
        assert_eq!(via_trait.signature, via_inherent.signature);
    }
}
