//! Bitcoin signer Known Answer Tests.
//!
//! Focus: Bitcoin-specific wire format. Core ECDSA determinism and key
//! validation live in `signer_primitives::tests`.
//!
//! What this file pins:
//!
//! - **Address**: legacy P2PKH `Base58Check(0x00 || RIPEMD160(SHA-256(pk)))`.
//! - **Tx sighash**: `ECDSA(double_SHA-256(preimage))`.
//! - **BIP-137 digest formula**: `double_SHA-256("\x18Bitcoin Signed Message:\n"
//!   || CompactSize(len) || msg)` — pinned against an independently
//!   computed hash from `@noble/hashes`.
//! - **All four BIP-137 header variants**: `v` offsets `27 | 31 | 35 | 39`
//!   across uncompressed-P2PKH, compressed-P2PKH, `SegWit-P2SH`, and
//!   native-`SegWit`-bech32 address types (spec: `bips.dev/137`).
//! - **`CompactSize` boundaries**: 252 (single-byte) and 253/65535
//!   (`0xFD` + `u16`) branches.
//! - **BIP-137 recovery round-trip**: the wire signature recovers to a
//!   pubkey whose P2PKH address matches the signer's own address —
//!   exactly what Bitcoin Core's `verifymessage` RPC does.

#![allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::indexing_slicing,
    reason = "test module: panics are acceptable and assertions self-describe"
)]

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

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

/// Tx sighash verify round-trip: `verify_hash` accepts the wire signature
/// against `double_SHA-256(preimage)` and rejects tampered bytes.
#[test]
fn sign_transaction_verify_hash_roundtrip() {
    let signer = signer_fixture();
    let tx = hex::decode(TX_HEX).unwrap();
    let digest: [u8; 32] = Sha256::digest(Sha256::digest(&tx)).into();
    let out = signer.sign_transaction(&tx).unwrap();

    signer.verify_hash(&digest, &out.to_bytes()).unwrap();
    let mut tampered = out.to_bytes();
    tampered[32] ^= 0x01;
    assert!(signer.verify_hash(&digest, &tampered).is_err());
}

/// `verifymessage`-style BIP-137 round-trip: strip the header byte,
/// recover the pubkey from the compact `r || s` against the Bitcoin
/// message digest, and derive the compressed-P2PKH address. The result
/// must equal the signer's own address — which is exactly how Bitcoin
/// Core and Electrum verify a BIP-137 signature.
#[test]
fn sign_message_bip137_recovers_to_same_p2pkh_address() {
    let signer = signer_fixture();
    let out = signer.sign_message(MESSAGE.as_bytes()).unwrap();
    let sig_bytes = out.to_bytes();
    let header = out.v().unwrap();

    // Strip the BIP-137 compressed-P2PKH offset (31) to recover the raw parity.
    assert!((31..=34).contains(&header));
    let parity = header - 31;

    let digest = super::bitcoin_message_digest(MESSAGE.as_bytes());
    let sig = K256Sig::from_slice(&sig_bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(parity).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();

    // Derive the compressed-P2PKH address from the recovered pubkey.
    let compressed = recovered.to_encoded_point(true);
    let sha = Sha256::digest(compressed.as_bytes());
    let hash160 = Ripemd160::digest(sha);
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(&hash160);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    let recovered_addr = bs58::encode(&payload).into_string();

    assert_eq!(recovered_addr, signer.address());
}
