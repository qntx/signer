//! Nostr transaction signer built on BIP-340 Schnorr over secp256k1.
//!
//! Implements the signing side of the Nostr protocol
//! ([NIP-01](https://nips.nostr.com/1)) with
//! [NIP-19](https://nips.nostr.com/19) bech32 key encoding (`nsec` for
//! private keys, `npub` for x-only public keys).
//!
//! **Key derivation from a mnemonic is handled by `kobe-nostr`
//! ([NIP-06](https://nips.nostr.com/6)) — this crate is signing only.**
//!
//! # Examples
//!
//! ```
//! use signer_nostr::Signer;
//!
//! // NIP-06 test vector 1.
//! let signer = Signer::from_hex(
//!     "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
//! )
//! .unwrap();
//! assert!(signer.address().starts_with("npub1"));
//!
//! // Sign a NIP-01 event id (32-byte SHA-256 of the canonical serialization).
//! let event_id = [0u8; 32];
//! let out = signer.sign_hash(&event_id).unwrap();
//! assert_eq!(out.to_bytes().len(), 64); // BIP-340 Schnorr
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use bech32::{Bech32, Hrp};
use sha2::{Digest as _, Sha256};
use signer_primitives::SchnorrSigner;
pub use signer_primitives::{self, Sign, SignExt, SignOutput};
use zeroize::Zeroizing;

mod error;

pub use error::SignError;

/// NIP-19 human-readable part for private keys.
pub const NSEC_HRP: &str = "nsec";
/// NIP-19 human-readable part for public keys.
pub const NPUB_HRP: &str = "npub";
/// NIP-19 human-readable part for event ids.
pub const NOTE_HRP: &str = "note";

/// Nostr transaction signer.
///
/// Wraps a BIP-340 [`SchnorrSigner`]. The inner key is zeroized on drop.
pub struct Signer {
    inner: SchnorrSigner,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Signer {
    /// Create from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the bytes are not a valid
    /// secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Ok(Self {
            inner: SchnorrSigner::from_bytes(bytes)?,
        })
    }

    /// Create from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the hex is invalid or the key is
    /// out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        Ok(Self {
            inner: SchnorrSigner::from_hex(hex_str)?,
        })
    }

    /// Create from a NIP-19 `nsec1…` bech32-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Bech32`] if the string is malformed or has the
    /// wrong human-readable part, or [`SignError::InvalidKey`] if the decoded
    /// bytes are not a valid secp256k1 scalar.
    pub fn from_nsec(nsec: &str) -> Result<Self, SignError> {
        let bytes = decode_bech32_32(nsec, NSEC_HRP)?;
        Self::from_bytes(&bytes)
    }

    /// Generate a random signer using OS-provided entropy.
    ///
    /// # Panics
    ///
    /// Panics if the OS random number generator fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn random() -> Self {
        Self {
            inner: SchnorrSigner::random(),
        }
    }

    /// NIP-19 `npub1…` bech32-encoded x-only public key.
    ///
    /// This is the canonical on-wire address format for a Nostr account.
    #[must_use]
    pub fn address(&self) -> String {
        encode_bech32(NPUB_HRP, &self.inner.xonly_public_key())
    }

    /// Alias for [`address`](Self::address).
    #[must_use]
    pub fn npub(&self) -> String {
        self.address()
    }

    /// NIP-19 `nsec1…` bech32-encoded private key (zeroized on drop).
    ///
    /// Handle with the same care as the raw private key.
    #[must_use]
    pub fn nsec(&self) -> Zeroizing<String> {
        Zeroizing::new(encode_bech32(NSEC_HRP, &self.inner.to_bytes()))
    }

    /// 32-byte x-only public key (NIP-01 wire format).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.xonly_public_key().to_vec()
    }

    /// Hex-encoded 32-byte x-only public key (64 lowercase characters).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.inner.xonly_public_key_hex()
    }

    /// Sign a NIP-01 event id (32-byte SHA-256 of the canonical serialization).
    ///
    /// This is the canonical Nostr signing entry point: callers serialize the
    /// event per NIP-01 §"Events and signatures", compute its SHA-256, and
    /// pass the resulting 32 bytes here.
    ///
    /// Returns a 64-byte BIP-340 Schnorr signature with the signer's
    /// x-only public key attached.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidMessage`] if `event_id` is not 32 bytes,
    /// or [`SignError::SigningFailed`] if the primitive fails.
    pub fn sign_hash(&self, event_id: &[u8; 32]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign_prehash(event_id)?)
    }

    /// Sign arbitrary bytes with BIP-340 Schnorr (deterministic).
    ///
    /// # Semantic warning
    ///
    /// Unlike EVM (`EIP-191`), Bitcoin (`Bitcoin Signed Message`), or Tron
    /// (`\x19TRON Signed Message:\n`) flavours, **Nostr has no canonical
    /// "signed message" standard**. This method passes `message` straight
    /// into BIP-340 Schnorr **without prefixing or hashing**.
    ///
    /// For on-protocol Nostr events, always prefer:
    ///
    /// - [`sign_hash`](Self::sign_hash) with the NIP-01 `event.id`
    ///   (32-byte SHA-256 of the canonical serialization), or
    /// - [`sign_transaction`](Self::sign_transaction) with the
    ///   serialized event JSON — it computes `sha256(event)` for you.
    ///
    /// Use this method only for bespoke off-protocol challenges where both
    /// signer and verifier agree on the exact input bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if the primitive fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        Ok(self.inner.sign(message)?)
    }

    /// Sign a serialized NIP-01 event: computes SHA-256 then Schnorr-signs.
    ///
    /// `serialized_event` is the UTF-8 JSON-serialized form of
    /// `[0, pubkey, created_at, kind, tags, content]` as specified in
    /// NIP-01. The returned 64-byte signature is valid for the event whose
    /// id equals `sha256(serialized_event)`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if the primitive fails.
    pub fn sign_transaction(&self, serialized_event: &[u8]) -> Result<SignOutput, SignError> {
        let event_id: [u8; 32] = Sha256::digest(serialized_event).into();
        self.sign_hash(&event_id)
    }

    /// Verify a signature against a message with this signer's public key.
    ///
    /// Primarily intended for round-trip testing.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on verification failure.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignError> {
        Ok(self.inner.verify(message, signature)?)
    }
}

impl Sign for Signer {
    type Error = SignError;

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, Self::Error> {
        Self::sign_hash(self, hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error> {
        Self::sign_message(self, message)
    }

    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Self::Error> {
        Self::sign_transaction(self, tx_bytes)
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_nostr::DerivedAccount`].
    ///
    /// Uses the raw 32-byte private key directly (no hex or bech32
    /// round-trip).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the derived bytes are not a
    /// valid secp256k1 scalar.
    pub fn from_derived(account: &kobe_nostr::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

fn encode_bech32(hrp: &str, data: &[u8]) -> String {
    let hrp = Hrp::parse_unchecked(hrp);
    #[allow(
        clippy::expect_used,
        reason = "HRP is a validated compile-time constant and data length is bounded"
    )]
    {
        bech32::encode::<Bech32>(hrp, data).expect("bech32 encoding over known-good input")
    }
}

fn decode_bech32_32(s: &str, expected_hrp: &str) -> Result<[u8; 32], SignError> {
    let (hrp, data) = bech32::decode(s).map_err(|e| SignError::Bech32(alloc::format!("{e}")))?;
    if hrp.as_str() != expected_hrp {
        return Err(SignError::Bech32(alloc::format!(
            "expected HRP `{expected_hrp}`, got `{}`",
            hrp.as_str()
        )));
    }
    data.try_into().map_err(|v: Vec<u8>| {
        SignError::Bech32(alloc::format!("expected 32 bytes, got {}", v.len()))
    })
}

#[cfg(test)]
mod tests;
