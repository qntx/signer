//! EVM signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` +
//! `@noble/hashes` (keccak-256) run. The KATs pin EIP-55 address
//! derivation, EIP-191 `personal_sign` output (`v = 27 | 28`), typed-tx
//! signing (raw `v = 0 | 1`), and a separate kobe-integration KAT that
//! checks the BIP-39 "abandon abandon … about" derivation chain.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const DIGEST_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// EIP-55 checksummed hex of `Keccak256(uncompressed_pubkey[1..])[12..]`.
const ADDRESS: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";

/// Raw ECDSA over `DIGEST_HEX` (`v = 0 | 1`).
const SIGN_HASH_HEX: &str = "68597f9553ac0acc453b5a75af2c731e3ca14dbfeae2231123fd202765b12738247bc920ef3e3ceebbc865651f98dc26a25a0d63240c5da091863fe0296e389b00";

/// EIP-191 `personal_sign` over `MESSAGE`. Wire form `r || s || (27|28)`.
const SIGN_MESSAGE_EIP191_HEX: &str = "bd238f0d6957ec577e5f90d781f63ff97e730ad39007e4bdde7b903af5f448762e2ef82e254d3c17337883c34a74d9fb0399226f818e4d1621377107f465f6901c";

/// `ECDSA(Keccak-256(unsigned_tx))` with raw parity — the input to
/// `encode_signed_transaction` for EIP-1559 / EIP-2930 framing.
const SIGN_TRANSACTION_HEX: &str = "c417ef54c6681102296b1af7f9692265f10cdf75a607f1ce66d57439889262e40d803bcafb4946ce29c22db851db7830f56d255095414a1f7e924c7f21df3a8101";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

fn digest() -> [u8; 32] {
    hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
}

#[test]
fn address_eip55_checksum_matches_noble_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

#[test]
fn sign_hash_matches_noble_rfc6979_kat() {
    let out = signer_fixture().sign_hash(&digest()).unwrap();
    assert_eq!(out.to_hex(), SIGN_HASH_HEX);
    let v = out.v().unwrap();
    assert!(v == 0 || v == 1, "sign_hash returns raw parity");
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

/// Integration with `kobe-evm`: the BIP-39 canonical test phrase at
/// `m/44'/60'/0'/0/0` must derive the same EIP-55 address both through
/// `Signer::from_derived` (consuming a `kobe_evm::DerivedAccount`) and
/// through the hex round-trip.
#[cfg(feature = "kobe")]
mod kobe_integration {
    use zeroize::Zeroizing;

    use super::Signer;

    /// BIP-39 mnemonic `abandon abandon abandon abandon abandon abandon
    /// abandon abandon abandon abandon abandon about` at path
    /// `m/44'/60'/0'/0/0`. Address cross-verified with go-ethereum,
    /// ethers.js, and Python `eth_keys`.
    fn kat_account() -> kobe_evm::DerivedAccount {
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
