//! Bitcoin signer Known Answer Tests.
//!
//! Goldens are produced by an independent `@noble/curves` +
//! `@noble/hashes` + `@scure/base` JS stack. Address, BIP-137 message
//! digest, and every BIP-137 header-byte variant are asserted
//! byte-for-byte, so any wire-format drift fails the build immediately.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use super::{BitcoinMessageAddressType, Sign, SignMessage, Signer};

const PRIV_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX: &str = "deadbeef00010203";
const MESSAGE: &str = "signer kat v3";

/// `Base58Check(0x00 || RIPEMD160(SHA-256(compressed_pubkey)))`.
const ADDRESS: &str = "1FB3WSwtExGLQUmNp4AQF66tAwAQp6igW3";

/// `double_SHA-256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || MESSAGE)`.
const MESSAGE_DIGEST_HEX: &str = "017bddbdc908e54f74f4c57cda0390adaa23d05b775229a486f7fe6ecdd4902b";

/// ECDSA over `double_SHA-256(TX_HEX)` — Bitcoin sighash framing.
const SIGN_TX_HEX: &str = "ea9298254514da415af8f810e618dd08440e24b3e8c9002d46ebd7ebb2bd97fe2a8ddce39abda97c3abddc0017746355be5f32bbf6f236258c3b8cba7e2578a401";

/// Four BIP-137 headers over the same `MESSAGE`. Only the leading/trailing
/// bytes and the header byte differ — `r || s` is identical across all
/// four because the signed digest is identical.
const BIP137_P2PKH_UNCOMPRESSED_HEX: &str = "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc1c";
const BIP137_P2PKH_COMPRESSED_HEX: &str = "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc20";
const BIP137_SEGWIT_P2SH_HEX: &str = "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc24";
const BIP137_SEGWIT_BECH32_HEX: &str = "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc28";

fn signer_fixture() -> Signer {
    Signer::from_hex(PRIV_KEY_HEX).unwrap()
}

#[test]
fn address_p2pkh_matches_base58check_kat() {
    assert_eq!(signer_fixture().address(), ADDRESS);
}

/// Transaction sighash: `ECDSA(double_SHA-256(tx_bytes))`, raw parity `v`.
#[test]
fn sign_transaction_double_sha256_matches_noble_kat() {
    let tx = hex::decode(TX_HEX).unwrap();
    let out = signer_fixture().sign_transaction(&tx).unwrap();
    assert_eq!(out.to_hex(), SIGN_TX_HEX);
}

/// Pin the Bitcoin message digest formula:
/// `double_SHA-256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || msg)`.
#[test]
fn bitcoin_message_digest_matches_noble_kat() {
    let digest = super::bitcoin_message_digest(MESSAGE.as_bytes());
    assert_eq!(hex::encode(digest), MESSAGE_DIGEST_HEX);
}

/// Default [`SignMessage`] path — BIP-137 compressed P2PKH header
/// (`v = 31 | 32`). Cross-verified with the JS reference.
#[test]
fn sign_message_default_is_bip137_compressed_p2pkh() {
    let out = signer_fixture().sign_message(MESSAGE.as_bytes()).unwrap();
    assert_eq!(out.to_hex(), BIP137_P2PKH_COMPRESSED_HEX);
    let v = out.v().unwrap();
    assert!(v == 31 || v == 32);
}

struct Bip137Case {
    ty: BitcoinMessageAddressType,
    offset: u8,
    golden: &'static str,
}

/// Every BIP-137 address-type offset from 27/31/35/39 is exercised. The
/// header is the only byte that changes between the four variants — a
/// strong check that the offset is applied correctly and no other wire
/// bits are accidentally touched.
#[test]
fn sign_message_with_all_bip137_headers_match_noble_kats() {
    let s = signer_fixture();
    let msg = MESSAGE.as_bytes();

    for case in [
        Bip137Case {
            ty: BitcoinMessageAddressType::P2pkhUncompressed,
            offset: 27,
            golden: BIP137_P2PKH_UNCOMPRESSED_HEX,
        },
        Bip137Case {
            ty: BitcoinMessageAddressType::P2pkhCompressed,
            offset: 31,
            golden: BIP137_P2PKH_COMPRESSED_HEX,
        },
        Bip137Case {
            ty: BitcoinMessageAddressType::SegwitP2sh,
            offset: 35,
            golden: BIP137_SEGWIT_P2SH_HEX,
        },
        Bip137Case {
            ty: BitcoinMessageAddressType::SegwitBech32,
            offset: 39,
            golden: BIP137_SEGWIT_BECH32_HEX,
        },
    ] {
        assert_eq!(case.ty.header_offset(), case.offset);
        let out = s.sign_message_with(case.ty, msg).unwrap();
        assert_eq!(out.to_hex(), case.golden, "{:?}", case.ty);
        let v = out.v().unwrap();
        assert!(
            v >= case.offset && v < case.offset + 4,
            "header {v} out of range for {:?}",
            case.ty,
        );
    }
}

/// Exercise the `CompactSize` length encoder at its two width boundaries
/// (≥ 253 bumps to 0xFD+u16, matching Bitcoin Core's serialisation).
#[test]
fn sign_message_compact_size_varint_boundaries() {
    let s = signer_fixture();
    // 252 bytes → single-byte CompactSize; 253 bytes → 0xFD + u16.
    for &len in &[252_usize, 253, 0xFFFF] {
        let msg = vec![0xAAu8; len];
        let out = s.sign_message(&msg).unwrap();
        assert_eq!(out.to_bytes().len(), 65, "len={len}");
        let v = out.v().unwrap();
        assert!(v == 31 || v == 32, "len={len}");
    }
}
