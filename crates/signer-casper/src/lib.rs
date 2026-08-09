//! Casper Network offline signing.
//!
//! Dual-curve support matching [`kobe-casper`](https://docs.rs/kobe-casper):
//!
//! | Algo | Default | Primitive |
//! | --- | --- | --- |
//! | [`KeyAlgo::Secp256k1`] | yes | `ECDSA` prehash recoverable |
//! | [`KeyAlgo::Ed25519`] | no | `RFC 8032` over message bytes |
//!
//! **v1 scope:** sign digests / raw bytes only. Full Deploy serialization is
//! caller-owned (casper-types / casper-client). Feed the `BLAKE2b`-256 deploy
//! hash into [`SignDigest::sign_digest`] (secp) or [`Signer::sign_bytes`] (either).
//!
//! Address / `AccountHash` derivation lives in kobe; this crate is signing only.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use signer_primitives::{Ed25519Signer, FromSecretKey, Secp256k1Signer};
pub use signer_primitives::{SignDigest, SignError, SignOutput};

/// Signature algorithm for Casper keys (mirrors kobe-casper `KeyAlgo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum KeyAlgo {
    /// secp256k1 `ECDSA` (Ledger default path interop).
    #[default]
    Secp256k1,
    /// Ed25519 (casper-client default keygen algorithm).
    Ed25519,
}

impl fmt::Display for KeyAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Secp256k1 => "secp256k1",
            Self::Ed25519 => "ed25519",
        })
    }
}

impl FromStr for KeyAlgo {
    type Err = SignError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "secp256k1" | "secp" | "ecdsa" => Ok(Self::Secp256k1),
            "ed25519" | "ed" | "eddsa" => Ok(Self::Ed25519),
            other => Err(SignError::InvalidKey(format!(
                "unknown casper key algo `{other}` (expected secp256k1|ed25519)"
            ))),
        }
    }
}

/// Casper dual-curve signer.
#[derive(Debug)]
pub struct Signer {
    algo: KeyAlgo,
    secp: Option<Secp256k1Signer>,
    ed: Option<Ed25519Signer>,
}

impl FromSecretKey for Signer {
    /// Defaults to [`KeyAlgo::Secp256k1`].
    fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Self::from_bytes_with_algo(bytes, KeyAlgo::Secp256k1)
    }
}

impl Signer {
    /// Create from 32-byte secret with explicit algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the scalar is invalid for secp.
    pub fn from_bytes_with_algo(bytes: &[u8; 32], algo: KeyAlgo) -> Result<Self, SignError> {
        match algo {
            KeyAlgo::Secp256k1 => Ok(Self {
                algo,
                secp: Some(Secp256k1Signer::from_bytes(bytes)?),
                ed: None,
            }),
            KeyAlgo::Ed25519 => Ok(Self {
                algo,
                secp: None,
                ed: Some(Ed25519Signer::from_bytes(bytes)?),
            }),
        }
    }

    /// Create from hex with default secp256k1.
    ///
    /// # Errors
    ///
    /// See [`FromSecretKey::from_secret_hex`].
    pub fn from_hex(hex_str: &str) -> Result<Self, SignError> {
        Self::from_secret_hex(hex_str)
    }

    /// Create from hex with explicit algorithm.
    ///
    /// # Errors
    ///
    /// Hex/curve validation errors.
    pub fn from_hex_with_algo(hex_str: &str, algo: KeyAlgo) -> Result<Self, SignError> {
        let bytes = signer_primitives::parse_secret_hex(hex_str)?;
        Self::from_bytes_with_algo(&bytes, algo)
    }

    /// Create from raw bytes (default secp256k1).
    ///
    /// # Errors
    ///
    /// Invalid secp scalar when using the default algo.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        Self::from_bytes_with_algo(bytes, KeyAlgo::Secp256k1)
    }

    /// Algorithm used by this signer.
    #[must_use]
    pub const fn algo(&self) -> KeyAlgo {
        self.algo
    }

    /// Compressed secp (33 B) or raw ed25519 (32 B) public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self.algo {
            KeyAlgo::Secp256k1 => self
                .secp
                .as_ref()
                .map(Secp256k1Signer::compressed_public_key)
                .map(|b| b.to_vec())
                .unwrap_or_default(),
            KeyAlgo::Ed25519 => self
                .ed
                .as_ref()
                .map(Ed25519Signer::public_key_bytes)
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        }
    }

    /// Casper tagged public-key hex (`02‖secp` or `01‖ed`), no `0x`.
    #[must_use]
    pub fn tagged_public_key_hex(&self) -> String {
        let tag = match self.algo {
            KeyAlgo::Ed25519 => 0x01_u8,
            KeyAlgo::Secp256k1 => 0x02_u8,
        };
        let mut buf = Vec::with_capacity(1 + 33);
        buf.push(tag);
        buf.extend_from_slice(&self.public_key_bytes());
        hex::encode(buf)
    }

    /// Sign arbitrary bytes for the active curve.
    ///
    /// - secp: Keccak is **not** applied — pass a 32-byte digest (`BLAKE2b` deploy
    ///   hash, etc.) via [`SignDigest::sign_digest`] for `ECDSA` prehash.
    /// - ed25519: signs `message` with `RFC 8032` (full message, not prehash).
    ///
    /// # Errors
    ///
    /// Signing primitive failures; secp path rejects non-32-byte messages
    /// (use [`SignDigest::sign_digest`] for digests).
    pub fn sign_bytes(&self, message: &[u8]) -> Result<SignOutput, SignError> {
        match self.algo {
            KeyAlgo::Secp256k1 => {
                let hash: &[u8; 32] = message.try_into().map_err(|_| {
                    SignError::InvalidMessage(format!(
                        "casper secp sign_bytes expects 32-byte digest, got {}",
                        message.len()
                    ))
                })?;
                self.sign_digest(hash)
            }
            KeyAlgo::Ed25519 => Ok(self
                .ed
                .as_ref()
                .ok_or_else(|| SignError::InvalidKey("missing ed25519 key".into()))?
                .sign_output(message)),
        }
    }

    /// Alias for signing a deploy digest (32-byte `BLAKE2b`).
    ///
    /// # Errors
    ///
    /// Same as [`SignDigest::sign_digest`] / [`Self::sign_bytes`].
    pub fn sign_deploy_hash(&self, digest: &[u8; 32]) -> Result<SignOutput, SignError> {
        match self.algo {
            KeyAlgo::Secp256k1 => self.sign_digest(digest),
            KeyAlgo::Ed25519 => self.sign_bytes(digest.as_slice()),
        }
    }
}

impl SignDigest for Signer {
    /// Secp: recoverable `ECDSA` over the 32-byte prehash (`v = 0|1`).
    /// Ed25519: signs the 32 bytes as the **entire message** (`RFC 8032`).
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<SignOutput, SignError> {
        match self.algo {
            KeyAlgo::Secp256k1 => self
                .secp
                .as_ref()
                .ok_or_else(|| SignError::InvalidKey("missing secp256k1 key".into()))?
                .sign_prehash_recoverable(digest),
            KeyAlgo::Ed25519 => Ok(self
                .ed
                .as_ref()
                .ok_or_else(|| SignError::InvalidKey("missing ed25519 key".into()))?
                .sign_output(digest)),
        }
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Build from a kobe [`CasperAccount`](kobe_casper::CasperAccount), using
    /// its [`algo`](kobe_casper::CasperAccount::algo) for curve selection.
    ///
    /// # Errors
    ///
    /// Invalid key material for the account's algorithm.
    pub fn from_derived(account: &kobe_casper::CasperAccount) -> Result<Self, SignError> {
        let algo = match account.algo() {
            kobe_casper::KeyAlgo::Secp256k1 => KeyAlgo::Secp256k1,
            kobe_casper::KeyAlgo::Ed25519 => KeyAlgo::Ed25519,
            _ => {
                return Err(SignError::InvalidKey(
                    "unsupported kobe casper KeyAlgo variant".into(),
                ));
            }
        };
        let sk = account.private_key_bytes();
        Self::from_bytes_with_algo(sk, algo)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "unit tests")]
mod tests {
    use super::*;
    const SECP_HEX: &str = "9c72144893c3ca5fa7299e65a7d7d6c41ab6a7add5f9860618324854d3c369d1";
    const ED_HEX: &str = "619386127005778f66a68fa91518c0841f59495790bb796fc781ecdd54fe329a";

    #[test]
    fn default_algo_is_secp() {
        let s = Signer::from_hex(SECP_HEX).unwrap();
        assert_eq!(s.algo(), KeyAlgo::Secp256k1);
        assert!(s.tagged_public_key_hex().starts_with("02"));
        let dig = [0x42u8; 32];
        let out = s.sign_digest(&dig).unwrap();
        assert!(matches!(out, SignOutput::Ecdsa { v: 0 | 1, .. }));
    }

    #[test]
    fn ed25519_signs_bytes() {
        let s = Signer::from_hex_with_algo(ED_HEX, KeyAlgo::Ed25519).unwrap();
        assert_eq!(s.algo(), KeyAlgo::Ed25519);
        assert!(s.tagged_public_key_hex().starts_with("01"));
        let out = s.sign_bytes(b"casper-test").unwrap();
        assert!(matches!(out, SignOutput::Ed25519(_)));
        assert_eq!(out.to_bytes().len(), 64);
    }

    #[test]
    fn from_secret_key_trait() {
        let s = Signer::from_secret_hex(SECP_HEX).unwrap();
        assert_eq!(s.public_key_bytes().len(), 33);
    }
}
