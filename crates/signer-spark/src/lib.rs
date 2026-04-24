//! Spark (Bitcoin L2) transaction signer built on secp256k1 ECDSA.
//!
//! Shares Bitcoin's cryptographic primitives (double-SHA256 sighash and
//! [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)
//! message signing) but derives its own `spark1…` bech32m address via the
//! hash160 of the compressed public key.
//!
//! # Address derivation
//!
//! `Signer::address` emits the canonical `spark1…` bech32m address:
//! `bech32m(hrp="spark", RIPEMD160(SHA256(compressed_pubkey)))`. This matches
//! the address format expected by Spark L2 nodes and produced by
//! `kobe-spark`.
//!
//! # Message signing
//!
//! [`SignMessage::sign_message`] signs with the BIP-137 header byte for a
//! **compressed P2PKH** address (`v = 31 | 32`), matching the on-wire format
//! of Bitcoin Core's `signmessage` so the resulting signature round-trips
//! through any BIP-137 verifier.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use bech32::{Bech32m, Hrp};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use signer_btc::bitcoin_message_digest;
pub use signer_primitives::{self, Sign, SignError, SignMessage, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// BIP-137 header offset for a compressed P2PKH address (`27 + 4`).
const BIP137_COMPRESSED_P2PKH_OFFSET: u8 = 31;

/// Spark bech32m address HRP.
const SPARK_HRP: &str = "spark";

/// Spark transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Spark bech32m address (`spark1…`).
    ///
    /// Derivation: `bech32m(hrp="spark", RIPEMD160(SHA256(compressed_pubkey)))`.
    ///
    /// # Panics
    ///
    /// Panics only if bech32m encoding of a fixed 20-byte payload fails,
    /// which is impossible given the hard-coded HRP and payload length.
    #[must_use]
    pub fn address(&self) -> String {
        let pubkey = self.0.compressed_public_key();
        let hash160 = Ripemd160::digest(Sha256::digest(&pubkey));
        let hrp = Hrp::parse_unchecked(SPARK_HRP);
        #[allow(
            clippy::expect_used,
            reason = "HRP and 20-byte hash160 are always valid bech32m inputs"
        )]
        bech32::encode::<Bech32m>(hrp, &hash160).expect("valid bech32m")
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

    /// Verify an ECDSA signature against a 32-byte pre-hashed digest.
    ///
    /// Accepts 64-byte (`r || s`) or 65-byte (`r || s || v`) input;
    /// the `v` byte is ignored for verification.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on malformed input or
    /// failed verification.
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8]) -> Result<(), SignError> {
        self.0.verify_prehash_any(hash, signature)
    }

    /// Sign a Spark transaction sighash preimage (Bitcoin-compatible).
    ///
    /// Hashes the input with `double_SHA256` and signs the digest. Returns a
    /// [`SignOutput::Ecdsa`] with raw `v` (`0 | 1`).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(Sha256::digest(tx_bytes)).into();
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
    /// consumable by any BIP-137 verifier.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        let digest = bitcoin_message_digest(message);
        Ok(self
            .0
            .sign_prehash_recoverable(&digest)?
            .with_v_offset(BIP137_COMPRESSED_P2PKH_OFFSET))
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_spark::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_spark::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

#[cfg(test)]
mod tests;
