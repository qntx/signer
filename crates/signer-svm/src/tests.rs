//! Solana signer Known Answer Tests.
//!
//! Focus: Solana-specific wire format (Base58 address, compact-u16
//! signature splicing, Phantom keypair format). Core Ed25519
//! determinism lives in `signer_primitives::tests` — including the
//! three full RFC 8032 reference vectors.
//!
//! Solana's `sign_*` entry points are raw Ed25519 over the input bytes,
//! matching `@solana/web3.js`' `nacl.sign.detached`. We therefore do not
//! re-run Ed25519 KATs here: the `verify` round-trip below proves our
//! wrappers do not mutate the payload before reaching the primitive.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{EncodeSignedTransaction, Sign, SignError, SignMessage, SignOutput, Signer};

/// RFC 8032 Test Vector 1.
const PRIV_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `base58(public_key_bytes)`.
const ADDRESS: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

/// Solana-specific: `base58(public_key_bytes)`. RFC 8032 pubkey
/// derivation is already covered in `signer_primitives::tests`, so this
/// only pins the Base58 encoding step.
#[test]
fn address_base58_matches_scure_base_kat() {
    let s = signer_fixture();
    assert_eq!(s.public_key_hex(), PUBKEY_HEX);
    assert_eq!(s.address(), ADDRESS);
}

/// `sign_message`, `sign_transaction`, and `sign_hash` are all raw
/// Ed25519 over their byte inputs. Rather than pin three identical KATs
/// (which would duplicate the RFC 8032 coverage in primitives), we
/// assert that each path's output round-trips back through `verify`
/// against the exact bytes we handed in.
#[test]
fn every_entry_point_self_verifies() {
    let s = signer_fixture();
    let tx = hex::decode(TX_HEX).unwrap();
    let digest_bytes: [u8; 32] =
        hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
            .unwrap()
            .try_into()
            .unwrap();

    for (label, payload, sig) in [
        (
            "sign_hash",
            &digest_bytes[..],
            s.sign_hash(&digest_bytes).unwrap(),
        ),
        (
            "sign_message",
            MESSAGE.as_bytes(),
            s.sign_message(MESSAGE.as_bytes()).unwrap(),
        ),
        (
            "sign_transaction",
            &tx[..],
            s.sign_transaction(&tx).unwrap(),
        ),
    ] {
        assert_eq!(sig.to_bytes().len(), 64, "{label}: raw Ed25519 is 64 bytes");
        assert!(sig.v().is_none(), "{label}: no `v` on raw Ed25519");
        s.verify(payload, &sig.to_bytes())
            .unwrap_or_else(|e| panic!("{label} must round-trip: {e}"));
    }
}

/// The Phantom / Backpack / Solflare 64-byte keypair (secret || public)
/// round-trips through `keypair_base58` → `from_keypair_base58`.
#[test]
fn keypair_base58_round_trip_preserves_identity() {
    let s = signer_fixture();
    let b58 = s.keypair_base58();
    let restored = Signer::from_keypair_base58(&b58).unwrap();
    assert_eq!(restored.address(), s.address());
    assert_eq!(restored.public_key_hex(), s.public_key_hex());
}

/// Malformed Base58 / wrong-length keypair payloads must not be accepted.
#[test]
fn from_keypair_base58_rejects_invalid_inputs() {
    assert!(matches!(
        Signer::from_keypair_base58("invalid!!!"),
        Err(SignError::InvalidKeypair(_))
    ));
    // Valid Base58 but wrong length (< 64 bytes decoded).
    assert!(matches!(
        Signer::from_keypair_base58("3J98t1"),
        Err(SignError::InvalidKeypair(_))
    ));
}

/// Compact-u16 header stripping: the single-signature envelope is
/// `0x01 || zeros(64) || message_body`; the stripped body must equal the
/// signable payload verbatim.
#[test]
fn extract_signable_bytes_strips_compact_u16_header_and_signature_slots() {
    let mut tx = vec![1u8]; // compact-u16 `num_sigs = 1`
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(b"message_body");
    let body = Signer::extract_signable_bytes(&tx).unwrap();
    assert_eq!(body, b"message_body");

    assert!(matches!(
        Signer::extract_signable_bytes(&[]),
        Err(SignError::Core(_))
    ));
}

/// Splicing: both the low-level `splice_signature` and the
/// `SignOutput`-accepting `encode_signed_transaction` must produce the
/// same bytes — same 64-byte signature in the first slot, identical tail.
#[test]
fn encode_signed_transaction_matches_splice_signature() {
    let s = signer_fixture();
    let msg_body = b"message_body";
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(msg_body);

    let raw_sig = s.sign_raw(msg_body).to_bytes();
    let spliced_low = Signer::splice_signature(&tx, &raw_sig).unwrap();
    assert_eq!(&spliced_low[1..65], &raw_sig);
    assert_eq!(&spliced_low[65..], msg_body);

    let spliced_high =
        Signer::encode_signed_transaction(&tx, &SignOutput::Ed25519(raw_sig)).unwrap();
    assert_eq!(spliced_low, spliced_high);
}

/// `encode_signed_transaction` must refuse non-Ed25519 variants — this is
/// the type-level contract behind the `EncodeSignedTransaction` trait.
#[test]
fn encode_signed_transaction_rejects_non_ed25519_variant() {
    let s = signer_fixture();
    let mut tx = vec![1u8];
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(b"body");
    let wrong = SignOutput::Ecdsa {
        signature: [0u8; 64],
        v: 0,
    };
    assert!(matches!(
        EncodeSignedTransaction::encode_signed_transaction(&s, &tx, &wrong),
        Err(SignError::Core(_))
    ));
}
