//! Bitcoin transaction signer built on secp256k1 ECDSA.
//!
//! Provides sighash signing, [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)
//! message signing with the `\x18Bitcoin Signed Message:\n` prefix and
//! `CompactSize` length encoding, and `P2PKH` address derivation.
//!
//! **Address derivation is handled by `kobe-btc` — this crate is signing only.**
//!
//! # Message signing (BIP-137)
//!
//! The default [`SignMessage::sign_message`] implementation targets the
//! canonical P2PKH-compressed address type used by Bitcoin Core's legacy
//! `signmessage` RPC, Electrum, and every major hardware wallet — the
//! recovery `v` byte is encoded as `31 | 32` (`27 + recid + 4`) so the
//! resulting signature round-trips through `verifymessage`. Callers that
//! need to sign for SegWit-P2SH, native `SegWit` (bech32), or an uncompressed
//! P2PKH address select the header explicitly through
//! [`Signer::sign_message_with`] and [`BitcoinMessageAddressType`].
//!
//! # Examples
//!
//! ```
//! use signer_btc::{Sign as _, Signer};
//!
//! let signer = Signer::random();
//! let out = signer.sign_hash(&[0u8; 32]).unwrap();
//! assert_eq!(out.to_bytes().len(), 65); // r(32) + s(32) + v(1)
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
pub use signer_primitives::{self, Sign, SignError, SignMessage, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// Bitcoin address type selector for [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)
/// message signing.
///
/// Controls the `v` byte offset prepended to the 64-byte compact ECDSA
/// signature. Every variant adds `recid + offset` onto the recovery id
/// `0 | 1` that [`Secp256k1Signer::sign_prehash_recoverable`] produces,
/// yielding the on-wire headers specified by BIP-137.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum BitcoinMessageAddressType {
    /// Legacy P2PKH address derived from an **uncompressed** public key.
    /// Header bytes: `27 | 28 | 29 | 30`.
    P2pkhUncompressed,
    /// Legacy P2PKH address derived from a **compressed** public key
    /// (Bitcoin Core's `signmessage` default, Electrum, most hardware wallets).
    /// Header bytes: `31 | 32 | 33 | 34`.
    #[default]
    P2pkhCompressed,
    /// `SegWit` wrapped P2SH-P2WPKH. Header bytes: `35 | 36 | 37 | 38`.
    SegwitP2sh,
    /// Native `SegWit` (bech32 / P2WPKH). Header bytes: `39 | 40 | 41 | 42`.
    SegwitBech32,
}

impl BitcoinMessageAddressType {
    /// BIP-137 base offset added to the recovery id.
    #[must_use]
    pub const fn header_offset(self) -> u8 {
        match self {
            Self::P2pkhUncompressed => 27,
            Self::P2pkhCompressed => 31,
            Self::SegwitP2sh => 35,
            Self::SegwitBech32 => 39,
        }
    }
}

/// Bitcoin transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Bitcoin P2PKH address (legacy, starts with `1`).
    ///
    /// Computed as `Base58Check(0x00 || RIPEMD160(SHA256(compressed_pubkey)))`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "SHA-256 output is always 32 bytes, slicing first 4 is safe"
    )]
    pub fn address(&self) -> String {
        let pubkey = self.0.compressed_public_key();
        let sha = Sha256::digest(&pubkey);
        let hash160 = Ripemd160::digest(sha);
        let mut payload = Vec::with_capacity(25);
        payload.push(0x00);
        payload.extend_from_slice(&hash160);
        let checksum = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(&payload).into_string()
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.compressed_public_key())
    }

    /// Verify a recoverable or compact ECDSA signature against a 32-byte
    /// pre-hashed sighash.
    ///
    /// Accepts 64-byte (`r || s`) or 65-byte (`r || s || v`) input; the
    /// `v` byte is ignored for verification.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on malformed input or
    /// failed verification.
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8]) -> Result<(), SignError> {
        self.0.verify_prehash_any(hash, signature)
    }

    /// Sign `message` as a BIP-137 Bitcoin signed message, selecting the
    /// header byte for the given [`BitcoinMessageAddressType`].
    ///
    /// The digest is `double_SHA256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message)`
    /// and the returned [`SignOutput::Ecdsa`] carries a `v` byte of
    /// `header_offset + recid`, which is exactly what Bitcoin Core's
    /// `verifymessage` RPC (and compatible wallets) expect on the wire.
    ///
    /// [`SignMessage::sign_message`] is a convenience wrapper that fixes the
    /// address type to [`BitcoinMessageAddressType::P2pkhCompressed`], matching
    /// the canonical legacy behaviour.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ECDSA primitive fails.
    pub fn sign_message_with(
        &self,
        address_type: BitcoinMessageAddressType,
        message: &[u8],
    ) -> Result<SignOutput, SignError> {
        let digest = bitcoin_message_digest(message);
        Ok(self
            .0
            .sign_prehash_recoverable(&digest)?
            .with_v_offset(address_type.header_offset()))
    }

    /// Sign a Bitcoin transaction sighash preimage.
    ///
    /// Hashes the input with `double_SHA256` (`SHA256(SHA256(preimage))`) and
    /// signs the resulting sighash. The caller is responsible for
    /// constructing the canonical BIP-143 / legacy sighash preimage
    /// (script code, amount, sequence, …).
    ///
    /// Returns a [`SignOutput::Ecdsa`] with raw `v` (`0 | 1`).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, sighash_preimage: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(Sha256::digest(sighash_preimage)).into();
        self.0.sign_prehash_recoverable(&digest)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(hash)
    }
}

impl SignMessage for Signer {
    /// **Framing**: BIP-137 Bitcoin signed message for the **compressed
    /// P2PKH** address type — `double_SHA256("\x18Bitcoin Signed Message:\n"
    /// || CompactSize(len) || message)`.
    ///
    /// Returns a 65-byte [`SignOutput::Ecdsa`] with `v = 31 | 32`, directly
    /// consumable by Bitcoin Core's `verifymessage` and equivalent wallets.
    /// For other address types see [`Signer::sign_message_with`].
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        self.sign_message_with(BitcoinMessageAddressType::P2pkhCompressed, message)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_btc::BtcAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_btc::BtcAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are range-checked before each cast"
)]
fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

/// Compute `double_SHA256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message)`.
///
/// This is the BIP-137 signed-message digest reused verbatim by any
/// Bitcoin-descended chain whose off-chain message scheme delegates to
/// Bitcoin Core's `signmessage` — currently this crate and `signer-spark`.
/// Exposing the digest function (instead of duplicating it in every
/// consumer) keeps the `CompactSize` encoding and prefix bytes defined in
/// a single location.
#[must_use]
pub fn bitcoin_message_digest(message: &[u8]) -> [u8; 32] {
    const PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";
    let mut data = Vec::with_capacity(PREFIX.len() + 9 + message.len());
    data.extend_from_slice(PREFIX);
    encode_compact_size(&mut data, message.len());
    data.extend_from_slice(message);
    Sha256::digest(Sha256::digest(&data)).into()
}

#[cfg(test)]
mod tests;
