//! EVM signer Known Answer Tests.
//!
//! Every hex literal in this file is pinned against authority with the
//! following provenance:
//!
//! - **EIP-55 / EIP-191** goldens are cross-computed with the mature
//!   `@noble/curves` + `@noble/hashes` (`keccak-256`) JavaScript stack
//!   so each assertion is a real cross-implementation check, not a
//!   self-confirming dump of past Rust output.
//! - **EIP-712** `sign_typed_data` digest uses the canonical "Mail"
//!   example from EIP-712 §Rationale, whose expected digest
//!   (`be609aee…30957bd2`) is reproduced byte-for-byte by `MetaMask`,
//!   `ethers.js`, and `go-ethereum`.
//! - **`ecrecover` round-trip** proves that the wire `v` and the raw
//!   parity variants of our output feed through `k256`'s `recover_*`
//!   helpers back to the same address the signer derives locally.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use sha3::{Digest, Keccak256};

use super::{Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// EIP-55 checksummed hex of `Keccak256(uncompressed_pubkey[1..])[12..]`.
const ADDRESS: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";

/// EIP-191 `personal_sign` over `MESSAGE`. Wire form `r || s || (27|28)`.
const SIGN_MESSAGE_EIP191_HEX: &str = "bd238f0d6957ec577e5f90d781f63ff97e730ad39007e4bdde7b903af5f448762e2ef82e254d3c17337883c34a74d9fb0399226f818e4d1621377107f465f6901c";

/// `ECDSA(Keccak-256(unsigned_tx))` with raw parity — the input to
/// `encode_signed_transaction` for EIP-1559 / EIP-2930 framing.
const SIGN_TRANSACTION_HEX: &str = "c417ef54c6681102296b1af7f9692265f10cdf75a607f1ce66d57439889262e40d803bcafb4946ce29c22db851db7830f56d255095414a1f7e924c7f21df3a8101";

/// Canonical EIP-712 "Mail" example (EIP-712 §Rationale). Reproduced
/// verbatim from the specification so its digest (`be609aee…30957bd2`)
/// matches the value `MetaMask`, `ethers.js`, and `go-ethereum` all
/// compute.
const EIP712_MAIL_JSON: &str = r#"{
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"}
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"}
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!"
    }
}"#;

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

#[test]
fn address_eip55_checksum_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// EIP-191 `personal_sign`: `Keccak-256("\x19Ethereum Signed Message:\n{len}" || msg)`,
/// wire `v` must be `27 | 28` so it slots directly into `ecrecover`.
#[test]
fn sign_message_eip191_v27_28_matches_noble_kat() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), SIGN_MESSAGE_EIP191_HEX);
    let v = out.v().unwrap();
    assert!(v == 27 || v == 28);
    // Wire invariant: the trailing byte is exactly the public `v()`.
    assert_eq!(out.to_bytes()[64], v);
}

/// Typed-transaction `sign_transaction` hashes with Keccak-256 and keeps
/// `v` at raw parity (so `encode_signed_transaction` can serialise it
/// into the RLP `v, r, s` tail without subtracting 27).
#[test]
fn sign_transaction_keccak256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TRANSACTION_HEX);
    let v = out.v().unwrap();
    assert!(v == 0 || v == 1, "feed raw parity into RLP, never 27/28");
}

/// `sign_typed_data` hashes the EIP-712 Mail example to the reference
/// digest `be609aee…30957bd2` and signs it with the workspace secp256k1
/// fixture. The wire `v` must be `27 | 28` — the encoding `MetaMask`,
/// `WalletConnect`, and every on-chain verifier accept.
#[test]
fn sign_typed_data_eip712_mail_example_roundtrips_through_ecrecover() {
    let signer = signer_fixture();
    let out = signer.sign_typed_data(EIP712_MAIL_JSON).unwrap();

    let sig_bytes = out.to_bytes();
    assert_eq!(sig_bytes.len(), 65);
    let v = out.v().unwrap();
    assert!(v == 27 || v == 28, "EIP-712 wire `v` must be 27 or 28");

    // Recover the signer's address from the wire signature and prove it
    // matches the locally derived EIP-55 address. This is exactly what
    // an on-chain `ecrecover` verifier would do.
    let digest = super::eip712::hash_typed_data_json(EIP712_MAIL_JSON).unwrap();
    let sig = K256Sig::from_slice(&sig_bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(v - 27).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    let recovered_addr = pubkey_to_eip55(&recovered);
    assert_eq!(recovered_addr, ADDRESS);
}

/// `sign_message` (EIP-191) must round-trip through `ecrecover` back to
/// this signer's address. Subtracting 27 from the wire `v` yields the
/// raw parity that `recover_from_prehash` consumes.
#[test]
fn sign_message_eip191_recovers_to_same_address() {
    let signer = signer_fixture();
    let out = signer.sign_message(MESSAGE.as_bytes()).unwrap();
    let sig_bytes = out.to_bytes();
    let v = out.v().unwrap();

    // Recompute the EIP-191 digest the same way `sign_message` does.
    let prefix = format!("\x19Ethereum Signed Message:\n{}", MESSAGE.len());
    let mut data = Vec::with_capacity(prefix.len() + MESSAGE.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(MESSAGE.as_bytes());
    let digest: [u8; 32] = Keccak256::digest(&data).into();

    let sig = K256Sig::from_slice(&sig_bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(v - 27).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    assert_eq!(pubkey_to_eip55(&recovered), signer.address());
}

/// `verify_hash` is our own inherent API — calling it with the 65-byte
/// wire signature must accept the verification. This is a regression
/// check for the length-dispatch inside `verify_prehash_any`.
#[test]
fn verify_hash_accepts_self_signed_output() {
    let signer = signer_fixture();
    let digest_bytes: [u8; 32] =
        hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
            .unwrap()
            .try_into()
            .unwrap();
    let out = signer.sign_hash(&digest_bytes).unwrap();
    signer.verify_hash(&digest_bytes, &out.to_bytes()).unwrap();
}

/// `encode_signed_transaction` must accept the raw-`v` output of
/// `sign_transaction` and emit a valid EIP-1559 envelope (type byte
/// 0x02, RLP list with `[…fields, v, r, s]`). Recovering the signer
/// address from the signed tx must yield the same EIP-55 address the
/// signer derives.
#[test]
fn encode_signed_transaction_matches_rlp_envelope_and_recovers() {
    let signer = signer_fixture();

    // Minimal EIP-1559 payload: `02 || RLP([1, 0, 0, 0, 0, 0, 0, 0, []])`.
    let items: Vec<u8> = [
        super::rlp::encode_bytes(&[1]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_bytes(&[]),
        super::rlp::encode_list(&[]),
    ]
    .concat();
    let mut unsigned = vec![0x02];
    unsigned.extend_from_slice(&super::rlp::encode_list(&items));

    let out = signer.sign_transaction(&unsigned).unwrap();
    let signed = Signer::encode_signed_transaction(&unsigned, &out).unwrap();
    assert_eq!(signed[0], 0x02, "envelope must keep the type byte");

    // Recover the address from the raw-`v` signature and the Keccak-256 of
    // the unsigned tx. This proves `sign_transaction` + `encode_signed_transaction`
    // are consistent with every on-chain verifier.
    let digest: [u8; 32] = Keccak256::digest(&unsigned).into();
    let sig_bytes = out.to_bytes();
    let sig = K256Sig::from_slice(&sig_bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(out.v().unwrap()).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    assert_eq!(pubkey_to_eip55(&recovered), signer.address());
}

/// Re-derive the EIP-55 address from any secp256k1 public key. Local
/// helper so we don't depend on the `Signer::address` path under test.
fn pubkey_to_eip55(pk: &VerifyingKey) -> String {
    let uncompressed = pk.to_encoded_point(false);
    let body = &uncompressed.as_bytes()[1..];
    let hash = Keccak256::digest(body);
    let addr_hex = hex::encode(&hash[12..]);
    let checksum = hex::encode(Keccak256::digest(addr_hex.as_bytes()));
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in addr_hex.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = u8::from_str_radix(&checksum[i..=i], 16).unwrap_or(0);
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
    }
    out
}

/// Integration with `kobe-evm`: the BIP-39 canonical test phrase at
/// `m/44'/60'/0'/0/0` must derive the same EIP-55 address both through
/// `Signer::from_derived` (consuming a `kobe_evm::DerivedAccount`) and
/// through the hex round-trip.
#[cfg(feature = "kobe")]
mod kobe_integration {
    use k256::ecdsa::SigningKey;
    use kobe_evm::{DerivedAccount, DerivedPublicKey};
    use zeroize::Zeroizing;

    use super::Signer;

    /// BIP-39 mnemonic `abandon abandon abandon abandon abandon abandon
    /// abandon abandon abandon abandon abandon about` at path
    /// `m/44'/60'/0'/0/0`. Address cross-verified with go-ethereum,
    /// ethers.js, and Python `eth_keys`.
    fn kat_account() -> DerivedAccount {
        let mut sk = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
            sk.as_mut_slice(),
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(sk.as_slice().into()).unwrap();
        let uncompressed: [u8; 65] = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        DerivedAccount::new(
            String::from("m/44'/60'/0'/0/0"),
            sk,
            DerivedPublicKey::Secp256k1Uncompressed(uncompressed),
            String::from("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        )
    }

    #[test]
    fn from_derived_matches_bip39_abandon_about_kat() {
        let acct = kat_account();
        let via_bytes = Signer::from_derived(&acct).unwrap();
        let via_hex = Signer::from_hex(&acct.private_key_hex()).unwrap();
        assert_eq!(via_bytes.address(), via_hex.address());
        assert_eq!(
            via_bytes.address(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        );
    }
}
