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

use alloc::string::String;

use bech32::{Bech32m, Hrp};
#[cfg(feature = "kobe")]
use kobe_spark as _;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use signer_btc::bitcoin_message_digest;
pub use signer_primitives::{self, SignDigest, SignError, SignMessage, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// Spark bech32m address HRP.
const SPARK_HRP: &str = "spark";

/// Spark transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// **Identity (not HD):** pure function of this private key only.
    /// Multi-path / multi-network addresses → [`kobe`](https://github.com/qntx/kobe).
    ///
    /// # Panics
    ///
    /// Never panics in practice: HRP and 20-byte hash160 are always valid bech32m inputs.
    #[must_use]
    pub fn address(&self) -> String {
        let pubkey = self.0.compressed_public_key();
        let hash160 = Ripemd160::digest(Sha256::digest(pubkey));
        let hrp = Hrp::parse_unchecked(SPARK_HRP);
        #[allow(
            clippy::expect_used,
            reason = "HRP and 20-byte hash160 are always valid bech32m inputs"
        )]
        bech32::encode::<Bech32m>(hrp, &hash160).expect("valid bech32m")
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 33] {
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

impl SignDigest for Signer {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(digest)
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
            .with_v_offset(signer_primitives::v_encoding::BIP137_P2PKH_COMPRESSED))
    }
}

#[cfg(feature = "kobe")]
pub use signer_primitives::FromDerived;

signer_primitives::impl_from_secret_key!();

#[cfg(test)]
mod tests;
