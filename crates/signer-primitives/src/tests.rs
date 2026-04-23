//! Contract tests for the primitive wrappers (`Secp256k1Signer`,
//! `Ed25519Signer`, `SchnorrSigner`) and the `Sign` / `SignMessage` trait
//! surface.
//!
//! These tests cover behaviour that belongs to this crate *alone* — key
//! validation, wire-layout invariants of [`SignOutput`], cross-method
//! consistency of the `verify_prehash*` helpers, and Debug redaction.
//! Chain-specific tests deliberately skip these same checks to avoid a
//! thirteen-fold duplication.
//!
//! What this file does **not** test:
//!
//! - RFC 6979 / RFC 8032 / BIP-340 signing determinism itself — that is the
//!   responsibility of `k256` and `ed25519-dalek`, which already exercise
//!   their own KATs. We trust those crates and only sanity-check that our
//!   wrapper plumbing does not accidentally invalidate the signatures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use alloc::format;

use crate::{Sign, SignError, SignExt, SignMessage, SignMessageExt, SignOutput};

/// Deterministic secp256k1 test key (also reused by every ECDSA chain crate).
const SECP_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

/// RFC 8032 Test Vector 1 secret key.
const ED25519_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// RFC 8032 Test Vector 1 public key.
const ED25519_PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// NIP-06 Test Vector 1 secret key (valid BIP-340 scalar).
const SCHNORR_KEY_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
/// NIP-06 Test Vector 1 x-only public key.
const SCHNORR_XONLY_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";

const TEST_DIGEST: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

#[test]
fn sign_error_is_standard_error() {
    // `core::error::Error` is the new `Sign::Error` bound; make sure
    // the canonical `SignError` satisfies it.
    fn assert_std_error<E: core::error::Error>() {}
    assert_std_error::<SignError>();
}

#[cfg(feature = "secp256k1")]
mod secp256k1 {
    use super::*;
    use crate::Secp256k1Signer;

    fn fix() -> Secp256k1Signer {
        Secp256k1Signer::from_hex(SECP_KEY_HEX).unwrap()
    }

    #[test]
    fn from_hex_accepts_0x_prefix_and_rejects_wrong_length() {
        // Canonical form.
        let a = Secp256k1Signer::from_hex(SECP_KEY_HEX).unwrap();
        // `0x`-prefixed form must resolve to the same key material.
        let b = Secp256k1Signer::from_hex(&format!("0x{SECP_KEY_HEX}")).unwrap();
        assert_eq!(a.compressed_public_key(), b.compressed_public_key());

        assert!(matches!(
            Secp256k1Signer::from_hex("deadbeef"),
            Err(SignError::InvalidKey(_))
        ));
        assert!(matches!(
            Secp256k1Signer::from_hex(&"aa".repeat(33)),
            Err(SignError::InvalidKey(_))
        ));
        assert!(matches!(
            Secp256k1Signer::from_hex("not-hex!!"),
            Err(SignError::InvalidKey(_))
        ));
    }

    #[test]
    fn from_bytes_rejects_zero_and_curve_order() {
        // Zero is forbidden by the secp256k1 scalar field.
        assert!(matches!(
            Secp256k1Signer::from_bytes(&[0u8; 32]),
            Err(SignError::InvalidKey(_))
        ));

        // `n` (the curve order) is also forbidden — k256 rejects `>= n`.
        let n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(matches!(
            Secp256k1Signer::from_bytes(&n),
            Err(SignError::InvalidKey(_))
        ));
    }

    #[test]
    fn public_key_widths() {
        let s = fix();
        let compressed = s.compressed_public_key();
        let uncompressed = s.uncompressed_public_key();
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
        assert_eq!(uncompressed[0], 0x04);
        // The leading 32 bytes after the uncompressed 0x04 prefix are the
        // same `x`-coordinate carried by the compressed form.
        assert_eq!(&compressed[1..33], &uncompressed[1..33]);
    }

    #[test]
    fn sign_prehash_recoverable_output_is_65_bytes_with_raw_parity() {
        let s = fix();
        let out = s.sign_prehash_recoverable(&TEST_DIGEST).unwrap();
        let bytes = out.to_bytes();
        assert_eq!(bytes.len(), 65, "r || s || v");
        let v = out.v().expect("Ecdsa variant must expose v");
        assert!(v == 0 || v == 1, "raw parity, not wire-format header");
        // Low-S by default (k256 enforces it); high bit of `s` must be 0.
        assert_eq!(bytes[32] >> 7, 0, "k256 returns low-S scalars");
    }

    #[test]
    fn sign_prehash_der_output_is_asn1_der() {
        let s = fix();
        let out = s.sign_prehash_der(&TEST_DIGEST).unwrap();
        match out {
            SignOutput::EcdsaDer(der) => {
                assert_eq!(der[0], 0x30, "DER SEQUENCE tag");
                assert!(
                    (8..=72).contains(&der.len()),
                    "DER ECDSA is typically 70-72 bytes, got {}",
                    der.len(),
                );
            }
            other => panic!("expected EcdsaDer, got {other:?}"),
        }
    }

    #[test]
    fn verify_prehash_accepts_strict_compact_only() {
        let s = fix();
        let out = s.sign_prehash_recoverable(&TEST_DIGEST).unwrap();
        let bytes = out.to_bytes();
        let mut compact = [0u8; 64];
        compact.copy_from_slice(&bytes[..64]);
        let mut recoverable = [0u8; 65];
        recoverable.copy_from_slice(&bytes);

        // Strict compact path accepts the 64-byte form.
        s.verify_prehash(&TEST_DIGEST, &compact).unwrap();
        // Strict recoverable path accepts the 65-byte form.
        s.verify_prehash_recoverable(&TEST_DIGEST, &recoverable)
            .unwrap();
        // `verify_prehash_any` dispatches on length.
        s.verify_prehash_any(&TEST_DIGEST, &compact[..]).unwrap();
        s.verify_prehash_any(&TEST_DIGEST, &recoverable[..])
            .unwrap();

        // Any other length is rejected as a wire-format error.
        assert!(matches!(
            s.verify_prehash_any(&TEST_DIGEST, &[0u8; 63]),
            Err(SignError::InvalidSignature(_))
        ));
        assert!(matches!(
            s.verify_prehash_any(&TEST_DIGEST, &[0u8; 66]),
            Err(SignError::InvalidSignature(_))
        ));
    }

    #[test]
    fn verify_rejects_wrong_digest_and_tampered_signature() {
        let s = fix();
        let out = s.sign_prehash_recoverable(&TEST_DIGEST).unwrap();
        let bytes = out.to_bytes();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[..64]);

        // Wrong digest (flip one bit) must fail.
        let mut wrong = TEST_DIGEST;
        wrong[0] ^= 1;
        assert!(s.verify_prehash(&wrong, &sig).is_err());

        // Tampered `s` scalar must fail verification.
        let mut tampered = sig;
        tampered[32] ^= 1;
        assert!(s.verify_prehash(&TEST_DIGEST, &tampered).is_err());
    }

    #[test]
    fn verify_prehash_der_round_trip() {
        let s = fix();
        let out = s.sign_prehash_der(&TEST_DIGEST).unwrap();
        let SignOutput::EcdsaDer(der) = out else {
            panic!("expected EcdsaDer");
        };
        s.verify_prehash_der(&TEST_DIGEST, &der).unwrap();
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn try_random_generates_distinct_usable_signers() {
        let a = Secp256k1Signer::try_random().unwrap();
        let b = Secp256k1Signer::try_random().unwrap();
        assert_ne!(a.compressed_public_key(), b.compressed_public_key());
        // Signs and verifies with its own key.
        let out = a.sign_prehash_recoverable(&TEST_DIGEST).unwrap();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&out.to_bytes()[..64]);
        a.verify_prehash(&TEST_DIGEST, &sig).unwrap();
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let s = fix();
        let debug = format!("{s:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&SECP_KEY_HEX[..8]));
    }
}

#[cfg(feature = "ed25519")]
mod ed25519 {
    use super::*;
    use crate::Ed25519Signer;

    fn fix() -> Ed25519Signer {
        Ed25519Signer::from_hex(ED25519_KEY_HEX).unwrap()
    }

    #[test]
    fn rfc8032_tv1_public_key() {
        assert_eq!(fix().public_key_hex(), ED25519_PUBKEY_HEX);
    }

    #[test]
    fn from_bytes_is_infallible_but_from_hex_rejects_bad_length() {
        let bytes = [0u8; 32]; // Any 32 bytes is a valid Ed25519 secret.
        assert!(Ed25519Signer::from_bytes(&bytes).is_ok());

        assert!(matches!(
            Ed25519Signer::from_hex("aabb"),
            Err(SignError::InvalidKey(_))
        ));
        assert!(matches!(
            Ed25519Signer::from_hex(&"aa".repeat(33)),
            Err(SignError::InvalidKey(_))
        ));
    }

    #[test]
    fn sign_output_is_64_bytes_with_no_v() {
        let s = fix();
        let out = s.sign_output(b"msg");
        let bytes = out.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert!(out.v().is_none());
        assert!(out.public_key().is_none(), "plain Ed25519 carries no pk");
    }

    #[test]
    fn sign_output_with_pubkey_attaches_32_byte_key() {
        let s = fix();
        let out = s.sign_output_with_pubkey(b"msg");
        let bytes = out.to_bytes();
        assert_eq!(bytes.len(), 64);
        let pk = out.public_key().expect("Ed25519WithPubkey carries pk");
        assert_eq!(pk.len(), 32);
        assert_eq!(hex::encode(pk), ED25519_PUBKEY_HEX);
    }

    #[test]
    fn verify_rejects_tampered_and_wrong_message() {
        let s = fix();
        let msg = b"authentic";
        let out = s.sign_output(msg);
        let bytes = out.to_bytes();

        s.verify(msg, &bytes).unwrap();
        assert!(s.verify(b"different", &bytes).is_err());

        let mut tampered = bytes;
        tampered[0] ^= 1;
        assert!(s.verify(msg, &tampered).is_err());

        // Wrong length is a dedicated error.
        assert!(matches!(
            s.verify(msg, &[0u8; 63]),
            Err(SignError::InvalidSignature(_))
        ));
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn try_random_generates_distinct_usable_signers() {
        let a = Ed25519Signer::try_random().unwrap();
        let b = Ed25519Signer::try_random().unwrap();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
        let out = a.sign_output(b"smoke");
        a.verify(b"smoke", &out.to_bytes()).unwrap();
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let s = fix();
        let debug = format!("{s:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&ED25519_KEY_HEX[..8]));
    }
}

#[cfg(feature = "schnorr")]
mod schnorr {
    use super::*;
    use crate::SchnorrSigner;

    fn fix() -> SchnorrSigner {
        SchnorrSigner::from_hex(SCHNORR_KEY_HEX).unwrap()
    }

    #[test]
    fn nip06_tv1_xonly_public_key() {
        assert_eq!(fix().xonly_public_key_hex(), SCHNORR_XONLY_HEX);
    }

    #[test]
    fn to_bytes_returns_original_scalar_not_negated() {
        // BIP-340 internally negates the scalar when y is odd; to_bytes
        // must return the *original* bytes so NIP-06 nsec round-trips.
        let s = fix();
        let raw = s.to_bytes();
        assert_eq!(hex::encode(raw), SCHNORR_KEY_HEX);
    }

    #[test]
    fn from_bytes_rejects_zero_scalar() {
        assert!(matches!(
            SchnorrSigner::from_bytes(&[0u8; 32]),
            Err(SignError::InvalidKey(_))
        ));
    }

    #[test]
    fn sign_is_deterministic_and_verifies() {
        let s = fix();
        let msg = b"BIP-340 deterministic";
        let a = s.sign(msg).unwrap();
        let b = s.sign(msg).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes(), "aux_rand = 0 is deterministic");
        s.verify(msg, &a.to_bytes()).unwrap();
    }

    #[test]
    fn sign_prehash_rejects_non_32_byte_input() {
        let s = fix();
        assert!(matches!(
            s.sign_prehash(&[0u8; 31]),
            Err(SignError::InvalidMessage(_))
        ));
        assert!(matches!(
            s.sign_prehash(&[0u8; 33]),
            Err(SignError::InvalidMessage(_))
        ));
        assert!(s.sign_prehash(&[0u8; 32]).is_ok());
    }

    #[test]
    fn sign_output_layout_matches_schnorr_variant() {
        let s = fix();
        let out = s.sign(b"layout").unwrap();
        match out {
            SignOutput::Schnorr {
                signature,
                xonly_public_key,
            } => {
                assert_eq!(signature.len(), 64);
                assert_eq!(hex::encode(xonly_public_key), SCHNORR_XONLY_HEX);
            }
            other => panic!("expected Schnorr variant, got {other:?}"),
        }
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn try_random_generates_distinct_usable_signers() {
        let a = SchnorrSigner::try_random().unwrap();
        let b = SchnorrSigner::try_random().unwrap();
        assert_ne!(a.xonly_public_key(), b.xonly_public_key());
        let out = a.sign(b"smoke").unwrap();
        a.verify(b"smoke", &out.to_bytes()).unwrap();
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let s = fix();
        let debug = format!("{s:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&SCHNORR_KEY_HEX[..8]));
    }
}

mod sign_output {
    use super::*;

    #[test]
    fn ecdsa_to_bytes_is_r_s_v_65() {
        let out = SignOutput::Ecdsa {
            signature: [0xAB; 64],
            v: 0x1B,
        };
        let b = out.to_bytes();
        assert_eq!(b.len(), 65);
        assert!(b[..64].iter().all(|&x| x == 0xAB));
        assert_eq!(b[64], 0x1B);
        assert_eq!(out.v(), Some(0x1B));
        assert!(out.public_key().is_none());
    }

    #[test]
    fn ecdsa_der_to_bytes_passes_through_der() {
        let der: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x42];
        let out = SignOutput::EcdsaDer(der.to_vec());
        assert_eq!(out.to_bytes(), der);
        assert!(out.v().is_none());
    }

    #[test]
    fn ed25519_to_bytes_is_64_bytes() {
        let out = SignOutput::Ed25519([0xCD; 64]);
        assert_eq!(out.to_bytes().len(), 64);
        assert!(out.v().is_none());
        assert!(out.public_key().is_none());
    }

    #[test]
    fn ed25519_with_pubkey_exposes_only_pubkey() {
        let out = SignOutput::Ed25519WithPubkey {
            signature: [0xEF; 64],
            public_key: [0x12; 32],
        };
        assert_eq!(out.to_bytes().len(), 64, "to_bytes returns the sig only");
        assert!(out.v().is_none());
        assert_eq!(out.public_key(), Some(&[0x12u8; 32][..]));
    }

    #[test]
    fn schnorr_exposes_only_xonly_pubkey() {
        let out = SignOutput::Schnorr {
            signature: [0xAA; 64],
            xonly_public_key: [0x99; 32],
        };
        assert_eq!(out.to_bytes().len(), 64);
        assert!(out.v().is_none());
        assert_eq!(out.public_key(), Some(&[0x99u8; 32][..]));
    }

    #[test]
    fn to_hex_matches_to_bytes() {
        let out = SignOutput::Ecdsa {
            signature: [0xFF; 64],
            v: 0x80,
        };
        assert_eq!(out.to_hex(), hex::encode(out.to_bytes()));
    }
}

#[cfg(feature = "secp256k1")]
mod ext_traits {
    use super::*;

    // Minimal `Sign + SignMessage` impl that produces known outputs so we can
    // prove the `SignExt` / `SignMessageExt` pass-throughs equal `to_bytes()`
    // exactly — without leaking into chain-specific semantics.
    #[derive(Debug, Default)]
    struct FakeSigner;

    impl Sign for FakeSigner {
        type Error = SignError;

        fn sign_hash(&self, _hash: &[u8; 32]) -> Result<SignOutput, SignError> {
            Ok(SignOutput::Ed25519([0xAA; 64]))
        }

        fn sign_transaction(&self, _tx: &[u8]) -> Result<SignOutput, SignError> {
            Ok(SignOutput::Ed25519([0xBB; 64]))
        }
    }

    impl SignMessage for FakeSigner {
        fn sign_message(&self, _msg: &[u8]) -> Result<SignOutput, SignError> {
            Ok(SignOutput::Ed25519([0xCC; 64]))
        }
    }

    #[test]
    fn sign_ext_returns_same_bytes_as_to_bytes() {
        let s = FakeSigner;
        assert_eq!(
            s.sign_hash_bytes(&[0u8; 32]).unwrap(),
            s.sign_hash(&[0u8; 32]).unwrap().to_bytes(),
        );
        assert_eq!(
            s.sign_transaction_bytes(b"tx").unwrap(),
            s.sign_transaction(b"tx").unwrap().to_bytes(),
        );
    }

    #[test]
    fn sign_message_ext_returns_same_bytes_as_to_bytes() {
        let s = FakeSigner;
        assert_eq!(
            s.sign_message_bytes(b"m").unwrap(),
            s.sign_message(b"m").unwrap().to_bytes(),
        );
    }
}
