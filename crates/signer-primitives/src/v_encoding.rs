//! Canonical recovery-id / message-header offsets for secp256k1 ECDSA.
//!
//! Raw ECDSA recoverable signatures use `v ∈ {0, 1}` (parity). Chains that
//! publish a message-signing header add a fixed offset; see BIP-137, EIP-191,
//! and TRON's personal-message convention.
//!
//! Chain crates **must** use these constants instead of magic numbers.

/// Conceptual: raw recovery id lives in `{0, 1}` (no offset applied).
pub const RAW_PARITY_BASE: u8 = 0;

/// EIP-191 `personal_sign` / EIP-712 wire header: `v = 27 | 28`.
pub const EIP191_OFFSET: u8 = 27;

/// TRON signed-message header (same numeric offset as EIP-191): `v = 27 | 28`.
pub const TRON_MESSAGE_OFFSET: u8 = 27;

/// BIP-137: legacy P2PKH from an **uncompressed** public key (`27..=30`).
pub const BIP137_P2PKH_UNCOMPRESSED: u8 = 27;

/// BIP-137: legacy P2PKH from a **compressed** public key (`31..=34`).
///
/// Bitcoin Core `signmessage` / Electrum default.
pub const BIP137_P2PKH_COMPRESSED: u8 = 31;

/// BIP-137: P2SH-P2WPKH (`35..=38`).
pub const BIP137_SEGWIT_P2SH: u8 = 35;

/// BIP-137: native `SegWit` P2WPKH bech32 (`39..=42`).
pub const BIP137_SEGWIT_BECH32: u8 = 39;
