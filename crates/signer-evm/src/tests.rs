//! Unit tests for the EVM signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::redundant_clone,
    clippy::missing_assert_message,
    reason = "test module: panics are acceptable and assertions are self-describing"
)]

use sha3::{Digest, Keccak256};
use signer_primitives::testing::verify_secp256k1_recoverable;

use super::Signer;

const TEST_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TEST_ADDR: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";

fn test_signer() -> Signer {
    Signer::from_hex(TEST_KEY).unwrap()
}

#[test]
fn known_address_from_hex() {
    assert_eq!(test_signer().address(), TEST_ADDR);
}

#[test]
fn known_address_0x_prefix() {
    let s = Signer::from_hex(&format!("0x{TEST_KEY}")).unwrap();
    assert_eq!(s.address(), TEST_ADDR);
}

#[test]
fn known_address_from_bytes() {
    let bytes: [u8; 32] = hex::decode(TEST_KEY).unwrap().try_into().unwrap();
    let s = Signer::from_bytes(&bytes).unwrap();
    assert_eq!(s.address(), TEST_ADDR);
}

#[test]
fn sign_hash_verify() {
    let s = test_signer();
    let digest: [u8; 32] = Keccak256::digest(b"test message").into();
    let out = s.sign_hash(&digest).unwrap();

    let sig_bytes = out.to_bytes();
    assert_eq!(sig_bytes.len(), 65);
    let rid = out.v().expect("recovery id must be present");
    assert!(rid == 0 || rid == 1, "raw v byte must be 0 or 1, got {rid}");

    verify_secp256k1_recoverable(&s.public_key_bytes(), &digest, &sig_bytes);
}

#[test]
fn sign_message_eip191_verify() {
    let s = test_signer();
    let msg = b"Hello World";
    let out = s.sign_message(msg).unwrap();

    let sig_bytes = out.to_bytes();
    assert_eq!(sig_bytes.len(), 65);
    let v = sig_bytes[64];
    assert!(v == 27 || v == 28, "EIP-191 v must be 27 or 28, got {v}");

    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut prefixed = Vec::new();
    prefixed.extend_from_slice(prefix.as_bytes());
    prefixed.extend_from_slice(msg);
    let digest: [u8; 32] = Keccak256::digest(&prefixed).into();

    // EIP-191 signatures carry v = 27 | 28, but the underlying ECDSA verifier
    // wants the raw parity byte (0 | 1). Subtract 27 before verifying.
    let mut recoverable = sig_bytes.clone();
    recoverable[64] -= 27;
    verify_secp256k1_recoverable(&s.public_key_bytes(), &digest, &recoverable);
}

#[test]
fn sign_message_v_matches_recovered_parity() {
    let s = test_signer();
    let out = s.sign_message(b"recovery test").unwrap();
    let sig_bytes = out.to_bytes();
    let v = sig_bytes[64];
    let rid = out.v().unwrap();
    assert_eq!(v, rid, "v byte in signature must equal SignOutput::v()");
    assert!(rid == 27 || rid == 28);
}

#[test]
fn deterministic_signature() {
    let s = test_signer();
    let digest: [u8; 32] = Keccak256::digest(b"deterministic").into();
    let out1 = s.sign_hash(&digest).unwrap();
    let out2 = s.sign_hash(&digest).unwrap();
    assert_eq!(out1.to_bytes(), out2.to_bytes());
}

#[test]
fn rejects_invalid_input() {
    assert!(Signer::from_hex("not-hex").is_err());
    assert!(Signer::from_hex("abcd").is_err());
    assert!(Signer::from_bytes(&[0u8; 32]).is_err());
}

#[test]
fn debug_does_not_leak_key() {
    let debug = format!("{:?}", test_signer());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("4c0883"));
    assert!(!debug.contains("362318"));
}

#[cfg(feature = "kobe")]
mod kobe_integration {
    use zeroize::Zeroizing;

    use super::Signer;

    /// BIP-39 seed "abandon abandon ... about" at `m/44'/60'/0'/0/0`,
    /// cross-verified with Python coincurve + keccak256 + EIP-55 (KAT from kobe-evm).
    fn kat_derived_account() -> kobe_evm::DerivedAccount {
        let mut sk = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
            sk.as_mut_slice(),
        )
        .unwrap();
        let pk = hex::decode("0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299")
            .unwrap();
        kobe_evm::DerivedAccount::new(
            String::from("m/44'/60'/0'/0/0"),
            sk,
            pk,
            String::from("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        )
    }

    #[test]
    fn from_derived_matches_from_hex() {
        let acct = kat_derived_account();
        let via_bytes = Signer::from_derived(&acct).unwrap();
        let via_hex = Signer::from_hex(&acct.private_key_hex()).unwrap();
        assert_eq!(via_bytes.address(), via_hex.address());
    }

    #[test]
    fn from_derived_produces_expected_address() {
        let acct = kat_derived_account();
        let s = Signer::from_derived(&acct).unwrap();
        assert_eq!(s.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }
}
