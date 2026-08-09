//! Unified signing traits and types for multi-chain transaction signers.
//!
//! # Layer map
//!
//! ```text
//! L0  signer-primitives   ← this crate (curves + shared types)
//! L1  signer-{chain}      protocol preimage + wire semantics
//! L2  signer-cli          ops UX
//! ──  kobe (external)     HD derivation only
//! ```
//!
//! # Schemes
//!
//! | Scheme | Key material | Engine |
//! | --- | --- | --- |
//! | secp256k1 ECDSA | 32-byte scalar | [`Secp256k1Signer`] |
//! | BIP-340 Schnorr | 32-byte scalar | [`SchnorrSigner`] |
//! | Ed25519 | 32-byte seed | [`Ed25519Signer`] |
//!
//! # Design principles
//!
//! - **Capability traits** — [`SignDigest`] is the mandatory 32-byte surface;
//!   optional [`SignMessage`] / [`EncodeSignedTransaction`] /
//!   [`ExtractSignableBytes`] never lie with runtime “unsupported”.
//! - **No `sign_transaction` trait** — transaction byte semantics differ
//!   irreconcilably; each chain uses an inherent method.
//! - **Discriminated [`SignOutput`]** — wire shapes, not optional metadata soup.
//! - **Secrets** — [`SecretKey32`] / `Zeroizing`; `Debug` redacts keys.
//! - **No HD / full address engines** — that lives in `kobe`.
//!
//! # Verification
//!
//! Verification is inherent on each chain `Signer` (chain-specific digests).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

mod digest;
#[cfg(feature = "ed25519")]
mod ed25519;
mod error;
#[doc(hidden)]
pub mod macros;
#[cfg(feature = "schnorr")]
mod schnorr;
#[cfg(feature = "secp256k1")]
mod secp256k1;
mod secret;
#[cfg(feature = "testing")]
pub mod testing;
pub mod v_encoding;

#[cfg(test)]
mod tests;

pub use digest::Digest32;
#[cfg(feature = "ed25519")]
pub use ed25519::Ed25519Signer;
pub use error::SignError;
#[cfg(feature = "kobe")]
use kobe_primitives as _;
#[cfg(feature = "schnorr")]
pub use schnorr::SchnorrSigner;
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Signer;
#[cfg(feature = "kobe")]
pub use secret::FromDerived;
pub use secret::{FromSecretKey, SecretKey32, parse_secret_hex, parse_secret_key};

/// Wire-level signature scheme discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureScheme {
    /// secp256k1 ECDSA compact + recovery byte.
    EcdsaRecoverable,
    /// secp256k1 ECDSA ASN.1 DER.
    EcdsaDer,
    /// Ed25519 (64-byte signature only).
    Ed25519,
    /// Ed25519 with attached public key.
    Ed25519WithPubkey,
    /// BIP-340 Schnorr with x-only public key.
    Schnorr,
}

impl SignatureScheme {
    /// Stable `snake_case` wire / JSON token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaRecoverable => "ecdsa_recoverable",
            Self::EcdsaDer => "ecdsa_der",
            Self::Ed25519 => "ed25519",
            Self::Ed25519WithPubkey => "ed25519_with_pubkey",
            Self::Schnorr => "schnorr",
        }
    }
}

impl core::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Signature output across every scheme the workspace supports.
///
/// Each variant mirrors a concrete wire format; callers pattern-match on the
/// variant rather than inspect optional metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignOutput {
    /// secp256k1 ECDSA with a single-byte tail (EVM, BTC, Cosmos, Filecoin, Tron, Spark).
    ///
    /// Flat bytes: `signature || v` (65 B total). The exact meaning of `v`
    /// depends on the producing call site and chain; every producer in the
    /// workspace documents its encoding explicitly:
    ///
    /// | Producer | `v` encoding |
    /// | --- | --- |
    /// | [`SignDigest::sign_digest`] / inherent `sign_transaction` | `0` or `1` (raw parity) |
    /// | EVM / Tron message (EIP-191 style) | [`v_encoding::EIP191_OFFSET`] + parity → `27\|28` |
    /// | BTC / Spark BIP-137 compressed P2PKH | [`v_encoding::BIP137_P2PKH_COMPRESSED`] + parity → `31\|32` |
    /// | BTC `sign_message_with` | full BIP-137 table |
    ///
    /// Encodings **collide across chains** (`27|28` is both EIP-191 and TRON).
    /// Verifiers must already know the scheme.
    Ecdsa {
        /// 64-byte compact `r || s`.
        signature: [u8; 64],
        /// `v` byte (raw parity or header-offset form).
        v: u8,
    },
    /// secp256k1 ECDSA encoded as ASN.1 DER (XRPL).
    EcdsaDer(Vec<u8>),
    /// Ed25519 signature (Solana, TON).
    Ed25519([u8; 64]),
    /// Ed25519 signature accompanied by the signer's public key (Sui, Aptos).
    Ed25519WithPubkey {
        /// 64-byte Ed25519 signature.
        signature: [u8; 64],
        /// 32-byte Ed25519 public key.
        public_key: [u8; 32],
    },
    /// BIP-340 Schnorr signature accompanied by the x-only public key (Nostr / Taproot).
    Schnorr {
        /// 64-byte BIP-340 Schnorr signature.
        signature: [u8; 64],
        /// 32-byte x-only public key.
        xonly_public_key: [u8; 32],
    },
}

impl SignOutput {
    /// Scheme discriminant for this output.
    #[must_use]
    pub const fn scheme(&self) -> SignatureScheme {
        match self {
            Self::Ecdsa { .. } => SignatureScheme::EcdsaRecoverable,
            Self::EcdsaDer(_) => SignatureScheme::EcdsaDer,
            Self::Ed25519(_) => SignatureScheme::Ed25519,
            Self::Ed25519WithPubkey { .. } => SignatureScheme::Ed25519WithPubkey,
            Self::Schnorr { .. } => SignatureScheme::Schnorr,
        }
    }

    /// Flat signature bytes in the chain's native wire layout.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Self::Ecdsa { signature, v } => {
                let mut out = Vec::with_capacity(65);
                out.extend_from_slice(&signature);
                out.push(v);
                out
            }
            Self::EcdsaDer(ref der) => der.clone(),
            Self::Ed25519(sig) | Self::Ed25519WithPubkey { signature: sig, .. } => sig.to_vec(),
            Self::Schnorr { signature, .. } => signature.to_vec(),
        }
    }

    /// Hex-encode the flat signature bytes returned by [`to_bytes`](Self::to_bytes).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// The public key attached to the signature, if any.
    #[must_use]
    pub const fn public_key(&self) -> Option<&[u8]> {
        match self {
            Self::Ed25519WithPubkey { public_key, .. } => Some(public_key.as_slice()),
            Self::Schnorr {
                xonly_public_key, ..
            } => Some(xonly_public_key.as_slice()),
            _ => None,
        }
    }

    /// `v` byte (secp256k1 ECDSA recoverable format only).
    #[must_use]
    pub const fn v(&self) -> Option<u8> {
        match self {
            Self::Ecdsa { v, .. } => Some(*v),
            _ => None,
        }
    }

    /// Add `offset` to the `v` byte of an [`Ecdsa`](Self::Ecdsa) variant.
    ///
    /// Prefer constants from [`v_encoding`].
    ///
    /// # Example
    ///
    /// ```
    /// use signer_primitives::{SignOutput, v_encoding};
    ///
    /// let raw = SignOutput::Ecdsa { signature: [0u8; 64], v: 1 };
    /// let eip191 = raw.with_v_offset(v_encoding::EIP191_OFFSET);
    /// assert_eq!(eip191.v(), Some(28));
    /// ```
    #[must_use]
    pub fn with_v_offset(self, offset: u8) -> Self {
        match self {
            Self::Ecdsa { signature, v } => Self::Ecdsa {
                signature,
                v: v.wrapping_add(offset),
            },
            other => other,
        }
    }
}

/// Mandatory 32-byte signing surface for every chain `Signer`.
///
/// # Contract (scheme-dependent)
///
/// | Scheme | [`sign_digest`](Self::sign_digest) means |
/// | --- | --- |
/// | secp256k1 ECDSA | RFC 6979 prehash over the digest; typically raw `v ∈ {0,1}` |
/// | BIP-340 Schnorr | BIP-340 over those 32 bytes as **message** (e.g. NIP-01 event id) |
/// | Ed25519 | RFC 8032 over those 32 bytes as the **entire message** (not ECDSA-style prehash) |
///
/// # On-chain applicability
///
/// Directly verifiable when the 32 bytes **are** the chain's native sighash
/// (EVM, BTC, Cosmos, Tron, Filecoin, Spark, XRPL, Nostr event ids, …).
/// For **Sui** / **Aptos**, use inherent `sign_transaction` (intent / domain
/// framing); bare `sign_digest` is not on-chain correct.
///
/// # Thread safety
///
/// Implementors are `Send + Sync`.
///
/// # Example
///
/// ```
/// use signer_primitives::{SignDigest, SignOutput};
///
/// fn sign_generic<S: SignDigest>(
///     signer: &S,
///     d: &[u8; 32],
/// ) -> Result<SignOutput, signer_primitives::SignError> {
///     signer.sign_digest(d)
/// }
/// ```
pub trait SignDigest: Send + Sync {
    /// Sign a 32-byte digest / fixed message with the chain's curve scheme.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if the underlying signing primitive fails.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<SignOutput, SignError>;
}

/// Opt-in capability: sign an off-chain message with the chain's convention.
///
/// Implemented only when a real standard exists (EVM, BTC, Spark, Tron, SVM,
/// Sui, Nostr). Absent on Cosmos, XRPL, Fil, TON, Aptos, …
///
/// | Chain | Transform | `v` on `Ecdsa` |
/// | --- | --- | --- |
/// | EVM | EIP-191 prefix + Keccak-256 | `27\|28` |
/// | Bitcoin / Spark | BIP-137 prefix + double-SHA256 | `31\|32` (compressed P2PKH default) |
/// | Tron | TRON message prefix + Keccak-256 | `27\|28` |
/// | Solana | raw Ed25519 (`nacl.sign.detached`) | — |
/// | Sui | PersonalMessage intent + BLAKE2b | — |
/// | Nostr | raw BIP-340 (no hash) | — |
pub trait SignMessage: SignDigest {
    /// Sign an arbitrary message with the chain's message-signing convention.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing fails.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, SignError>;
}

/// Optional: extract the signable portion from a fully serialized transaction.
pub trait ExtractSignableBytes: SignDigest {
    /// Return the portion of `tx_bytes` that the sighash is computed over.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if the transaction is malformed.
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignError>;
}

/// Optional: assemble signed wire bytes from `(unsigned_tx, SignOutput)`.
pub trait EncodeSignedTransaction: SignDigest {
    /// Encode `unsigned_tx + signature` into the chain's signed-wire form.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if the payload or signature variant is malformed.
    fn encode_signed_transaction(
        &self,
        unsigned_tx: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignError>;
}
