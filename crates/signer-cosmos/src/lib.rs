//! Cosmos transaction signer built on secp256k1 ECDSA.
//!
//! Provides signing for Cosmos SDK transactions (SHA-256 + ECDSA) and
//! bech32 `cosmos1…` address derivation.
//!
//! # Off-chain message signing
//!
//! This crate deliberately does **not** implement the
//! [`SignMessage`](signer_primitives::SignMessage) capability trait: the
//! Cosmos ecosystem signs arbitrary data through
//! [ADR-036](https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-036-arbitrary-signature.md),
//! which requires the caller to serialise a full `StdSignDoc` wrapping a
//! `MsgSignData { signer, data }` with chain-specific fields. Because the
//! HRP (`cosmos`, `osmo`, `juno`, …) and the sign-doc format live outside
//! the cryptographic primitive, callers build the canonical bytes and pass
//! them to [`Signer::sign_transaction`] — the SHA-256 + ECDSA that Cosmos
//! wallets (Keplr, Leap, Cosmostation) all verify over the sign doc is
//! exactly what this signer produces.
//!
//! # Examples
//!
//! ```
//! use signer_cosmos::Signer;
//!
//! let signer = Signer::random();
//! let addr = signer.address();
//! assert!(addr.starts_with("cosmos1"));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use bech32::{Bech32, Hrp};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
pub use signer_primitives::{self, Sign, SignError, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// Cosmos transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Cosmos Hub address (`cosmos1…`).
    ///
    /// Computed as `bech32(hrp="cosmos", RIPEMD160(SHA256(compressed_pubkey)))`.
    /// Convenience alias for [`address_with_hrp`](Self::address_with_hrp)
    /// with `"cosmos"` as the HRP; for other Cosmos-SDK chains
    /// (`osmo`, `juno`, `terra`, `secret`, `kava`, …) use `address_with_hrp`.
    ///
    /// # Panics
    ///
    /// Never panics in practice — `"cosmos"` is a valid HRP and the 20-byte
    /// hash160 payload is always encodable as bech32.
    #[must_use]
    pub fn address(&self) -> String {
        #[allow(
            clippy::expect_used,
            reason = "built-in `cosmos` HRP is statically valid"
        )]
        {
            self.address_with_hrp("cosmos").expect("valid cosmos HRP")
        }
    }

    /// Derive a Cosmos-SDK bech32 address with a caller-chosen HRP.
    ///
    /// Returns `bech32(hrp, RIPEMD160(SHA256(compressed_pubkey)))`.
    ///
    /// # Examples
    ///
    /// ```
    /// use signer_cosmos::Signer;
    ///
    /// let s = Signer::from_hex(
    ///     "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
    /// ).unwrap();
    /// assert!(s.address_with_hrp("osmo").unwrap().starts_with("osmo1"));
    /// assert!(s.address_with_hrp("juno").unwrap().starts_with("juno1"));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidMessage`] if `hrp` is not a valid bech32
    /// human-readable part (empty, too long, or contains invalid characters).
    pub fn address_with_hrp(&self, hrp: &str) -> Result<String, SignError> {
        let pubkey = self.0.compressed_public_key();
        let sha = Sha256::digest(&pubkey);
        let hash160 = Ripemd160::digest(sha);
        let parsed = Hrp::parse(hrp).map_err(|e| SignError::InvalidMessage(format!("hrp: {e}")))?;
        bech32::encode::<Bech32>(parsed, &hash160)
            .map_err(|e| SignError::InvalidMessage(format!("bech32 encode: {e}")))
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

    /// Sign a Cosmos SDK `SignDoc` (SHA-256 + secp256k1 ECDSA).
    ///
    /// Accepts the canonical byte form produced upstream by the caller —
    /// either the proto-encoded `SignDoc` (direct sign mode) or the amino
    /// JSON `StdSignDoc` (legacy mode, also used by ADR-036).
    ///
    /// Returns a [`SignOutput::Ecdsa`] with raw `v` (`0 | 1`).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ECDSA primitive fails.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        let digest: [u8; 32] = Sha256::digest(tx_bytes).into();
        self.0.sign_prehash_recoverable(&digest)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_recoverable(hash)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_cosmos::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_cosmos::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

#[cfg(test)]
mod tests;
