//! Unified signing traits and types for multi-chain transaction signers.
//!
//! This crate defines the capability traits that every chain-specific signer
//! crate implements — [`Sign`] for the mandatory signing surface,
//! [`SignMessage`] / [`EncodeSignedTransaction`] / [`ExtractSignableBytes`]
//! for opt-in capabilities — plus the discriminated [`SignOutput`] enum that
//! covers every wire format the workspace produces.
//!
//! # Design principles
//!
//! - **Single source of truth** — [`SignError`] is defined once here; chain
//!   crates re-export it directly and only introduce a wrapper enum when they
//!   carry additional failure modes.
//! - **Capability traits** — [`Sign`] is the mandatory primitive-level
//!   minimum ([`sign_hash`](Sign::sign_hash) over 32 bytes); optional
//!   capabilities live in separate traits so types never carry "not
//!   implemented" lies. Chains without a canonical message-signing standard
//!   (e.g. XRPL, Cosmos) simply do not implement [`SignMessage`]. Chain-
//!   specific `sign_transaction` is an inherent method on each chain's
//!   `Signer`, not part of a trait — transaction bytes semantics differ
//!   irreconcilably across chains, so a trait method would be a false
//!   abstraction.
//! - **Type-safe digests** — `sign_hash` accepts `&[u8; 32]`; ragged byte
//!   slices are rejected at compile time.
//! - **Discriminated output** — [`SignOutput`] variants mirror real wire
//!   formats; callers pattern-match instead of juggling `Option` metadata.
//! - **Fallible randomness** — every primitive exposes a `try_random`
//!   constructor that surfaces [`getrandom`] failures; the panicking
//!   `random()` helper is kept only as an ergonomic wrapper.
//! - **Thread-safe** — every signer is `Send + Sync` and ready to share
//!   across async tasks.
//! - **No address derivation** — that responsibility lives in `kobe`.
//!
//! # Verification
//!
//! Verification lives on each chain's inherent `Signer` (e.g.
//! [`signer_btc::Signer::verify_hash`](https://docs.rs/signer-btc)).
//! Because every chain derives its signable digest through a different
//! transform (EIP-191, Bitcoin message prefix, Sui intent, …), a single
//! generic `Verify` trait would have to replay chain logic, so the workspace
//! keeps verification inherent to avoid false abstraction.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "ed25519")]
mod ed25519;
mod error;
#[doc(hidden)]
pub mod macros;
#[cfg(feature = "schnorr")]
mod schnorr;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "testing")]
pub mod testing;

#[cfg(test)]
mod tests;

#[cfg(feature = "ed25519")]
pub use ed25519::Ed25519Signer;
pub use error::SignError;
#[cfg(feature = "schnorr")]
pub use schnorr::SchnorrSigner;
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Signer;

/// Signature output across every scheme the workspace supports.
///
/// Each variant mirrors a concrete wire format; callers pattern-match on the
/// variant rather than inspect optional metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutput {
    /// secp256k1 ECDSA with a single-byte tail (EVM, BTC, Cosmos, Filecoin, Tron, Spark).
    ///
    /// Flat bytes: `signature || v` (65 B total). The exact meaning of `v`
    /// depends on the producing call site and chain; every producer in the
    /// workspace documents its encoding explicitly:
    ///
    /// | Producer                                                              | `v` encoding              |
    /// |-----------------------------------------------------------------------|---------------------------|
    /// | [`Sign::sign_hash`] / each chain's inherent `sign_transaction`        | `0` or `1` (raw parity)   |
    /// | `signer_evm::Signer::{sign_message, sign_typed_data}` (EIP-191)       | `27` or `28`              |
    /// | `signer_tron::Signer::sign_message` (TRON message prefix)             | `27` or `28`              |
    /// | `signer_btc::Signer::sign_message` (BIP-137, compressed P2PKH)        | `31` or `32`              |
    /// | `signer_btc::Signer::sign_message_with` (BIP-137, caller-selected)    | `27..=42` per BIP-137     |
    /// | `signer_spark::Signer::sign_message` (same BIP-137 encoding as BTC)   | `31` or `32`              |
    Ecdsa {
        /// 64-byte compact `r || s`.
        signature: [u8; 64],
        /// `v` byte. The raw parity is always in the low bit; producers that
        /// need the chain's on-wire header (EIP-191, BIP-137, …) add the
        /// appropriate constant before constructing this variant.
        v: u8,
    },
    /// secp256k1 ECDSA encoded as ASN.1 DER (XRPL).
    ///
    /// Variable length (typically 70–72 B).
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
    /// Flat signature bytes in the chain's native wire layout.
    ///
    /// - `Ecdsa` → 65 bytes (`r || s || v`).
    /// - `EcdsaDer` → DER-encoded (variable length).
    /// - `Ed25519` → 64 bytes.
    /// - `Ed25519WithPubkey` → 64 bytes (the public key is carried separately).
    /// - `Schnorr` → 64 bytes (the x-only public key is carried separately).
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
    ///
    /// Only `Ed25519WithPubkey` and `Schnorr` carry a public key; other
    /// variants return `None`.
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
    ///
    /// See [`SignOutput::Ecdsa`] for the chain-specific meaning of this byte.
    #[must_use]
    pub const fn v(&self) -> Option<u8> {
        match self {
            Self::Ecdsa { v, .. } => Some(*v),
            _ => None,
        }
    }

    /// Add `offset` to the `v` byte of an [`Ecdsa`](Self::Ecdsa) variant.
    ///
    /// Used by chains whose on-wire `v` encoding is a fixed offset over the
    /// raw parity bit (EIP-191 adds `27`; BIP-137 adds `27`, `31`, `35`, or
    /// `39` depending on the address type; TRON adds `27`). Non-`Ecdsa`
    /// variants are returned unchanged.
    ///
    /// The offset is applied with wrapping arithmetic; callers choose the
    /// offset per their chain's encoding table.
    ///
    /// # Example
    ///
    /// ```
    /// use signer_primitives::SignOutput;
    ///
    /// let raw = SignOutput::Ecdsa { signature: [0u8; 64], v: 1 };
    /// let eip191 = raw.with_v_offset(27);
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

/// Primitive-level signing surface implemented by every chain-specific `Signer`.
///
/// # Contract (primitive-level, **not** protocol-level)
///
/// [`sign_hash`](Self::sign_hash) runs the underlying cryptographic primitive
/// over 32 bytes. The semantics of those 32 bytes differ by curve:
///
/// - **secp256k1 ECDSA / BIP-340 Schnorr**: the 32 bytes are treated as a
///   pre-computed digest (RFC 6979 / BIP-340 prehash semantics).
/// - **Ed25519**: the 32 bytes are signed as the **entire message** (`EdDSA` /
///   RFC 8032 does not accept pre-hashed input). Do not equate this with
///   signing a pre-computed digest on on-chain verifiers.
///
/// # On-chain applicability
///
/// [`sign_hash`](Self::sign_hash) output is directly on-chain verifiable
/// when the 32 bytes is the chain's native sighash — true for EVM, BTC,
/// Cosmos, Tron, Filecoin, Spark, XRPL, and Nostr event ids.
///
/// For **Sui** and **Aptos**, [`sign_hash`](Self::sign_hash) output is
/// **not on-chain verifiable** without intent / domain framing around the
/// 32 bytes. Use each
/// chain's inherent `Signer::sign_transaction` (not part of this trait) for
/// on-chain-correct output.
///
/// # Chain-specific transaction signing
///
/// `sign_transaction` is deliberately **not** part of this trait: every chain
/// interprets its `tx_bytes` argument under a different canonical format
/// (RLP, sighash preimage, `SignDoc`, BCS, …) and hashes with a different
/// algorithm, so the trait abstraction would provide no real constraint.
/// Each chain crate exposes `sign_transaction` as a documented inherent
/// method on its own `Signer` type.
///
/// Off-chain message signing lives on the opt-in [`SignMessage`] trait for
/// the same reason it is not universal: XRPL and Cosmos have no canonical
/// single-argument scheme.
///
/// # Thread safety
///
/// Implementors must be `Send + Sync` so signers can cross async task
/// boundaries and multi-threaded executors.
///
/// # Error contract
///
/// `Error` must be a real [`core::error::Error`] and losslessly liftable
/// from [`SignError`], so downstream code can attribute core failures
/// without string-matching while still participating in the standard
/// `?` / `Box<dyn Error>` ecosystem.
///
/// # Example
///
/// ```
/// use signer_primitives::{Sign, SignOutput};
///
/// fn sign_hash_generic<S: Sign>(signer: &S, hash: &[u8; 32]) -> Result<SignOutput, S::Error> {
///     signer.sign_hash(hash)
/// }
/// ```
pub trait Sign: Send + Sync {
    /// Error returned by signing.
    ///
    /// Implementations must honour the full [`core::error::Error`] contract
    /// (which implies [`core::fmt::Debug`] + [`core::fmt::Display`]) and
    /// losslessly accept [`SignError`] via [`From`].
    type Error: core::error::Error + From<SignError> + Send + Sync + 'static;

    /// Sign 32 bytes with the underlying cryptographic primitive.
    ///
    /// See the [trait-level docs](Sign#contract-primitive-level-not-protocol-level)
    /// for the per-curve semantics of the 32 bytes and on-chain applicability.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying signing primitive fails.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, Self::Error>;
}

/// Opt-in capability: sign an off-chain message with the chain's own
/// message-signing convention.
///
/// Implemented only by chains with a well-defined standard for signing
/// arbitrary messages. Chains without one (XRPL has no canonical scheme;
/// Cosmos defers to ADR-036 which requires a pre-built `SignDoc` and is
/// therefore best served through each chain's inherent `sign_transaction`)
/// simply do not implement this trait, making the capability visible in the
/// type system rather than hidden behind a runtime `Err`.
///
/// | Chain            | Transform                                                          | `v` on `Ecdsa`    |
/// |------------------|--------------------------------------------------------------------|-------------------|
/// | EVM              | Keccak-256 of `\x19Ethereum Signed Message:\n{len}` + message      | `27` or `28`      |
/// | Bitcoin / Spark  | double-SHA256 of `\x18Bitcoin Signed Message:\n` + CompactSize+msg | `31` or `32`      |
/// | Tron             | Keccak-256 of `\x19TRON Signed Message:\n{len}` + message          | `27` or `28`      |
/// | Filecoin         | BLAKE2b-256 of the raw message                                     | `0` or `1`        |
/// | Solana / TON     | Raw Ed25519 over the message (no prefix)                           | — (Ed25519)       |
/// | Sui              | BLAKE2b-256 of `PersonalMessage` intent + BCS-encoded message        | — (Ed25519)       |
/// | Aptos            | Raw Ed25519 over the message (no domain prefix)                    | — (Ed25519)       |
/// | Nostr            | Raw BIP-340 Schnorr over the message (no prefix)                   | — (Schnorr)       |
///
/// # Example
///
/// ```
/// use signer_primitives::{SignMessage, SignOutput};
///
/// fn personal_sign<S: SignMessage>(signer: &S, msg: &[u8]) -> Result<SignOutput, S::Error> {
///     signer.sign_message(msg)
/// }
/// ```
pub trait SignMessage: Sign {
    /// Sign an arbitrary message with the chain's message-signing convention.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying signing primitive fails.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error>;
}

/// Optional capability: extract the signable portion from a fully serialized
/// transaction.
///
/// Implemented by chains whose wire format interleaves signed payload and
/// unsigned metadata (e.g. Solana's compact-u16 header plus signature-slot
/// placeholders). The majority of chains sign the entire input verbatim and
/// therefore do not implement this trait.
///
/// ```
/// use signer_primitives::{ExtractSignableBytes, Sign};
///
/// fn strip<'a, S: Sign + ExtractSignableBytes>(
///     signer: &S,
///     tx: &'a [u8],
/// ) -> Result<&'a [u8], S::Error> {
///     signer.extract_signable_bytes(tx)
/// }
/// ```
pub trait ExtractSignableBytes: Sign {
    /// Return the portion of `tx_bytes` that the sighash is computed over.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is malformed.
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], Self::Error>;
}

/// Optional capability: assemble the final signed-transaction wire bytes from
/// the unsigned input plus a [`SignOutput`].
///
/// Implemented by chains whose wire format can be reconstructed from
/// `(unsigned_tx, signature)` without recomputing hashes (currently EVM's
/// typed transaction RLP and Solana's signature-slot splicing). Other chains
/// expect callers to splice the signature into their own domain-specific
/// envelope and therefore do not implement this trait.
///
/// ```
/// use signer_primitives::{EncodeSignedTransaction, Sign, SignOutput};
///
/// fn wrap<S: Sign + EncodeSignedTransaction>(
///     signer: &S,
///     unsigned: &[u8],
///     signature: &SignOutput,
/// ) -> Result<Vec<u8>, S::Error> {
///     signer.encode_signed_transaction(unsigned, signature)
/// }
/// ```
pub trait EncodeSignedTransaction: Sign {
    /// Encode `unsigned_tx + signature` into the chain's signed-wire form.
    ///
    /// # Errors
    ///
    /// Returns an error if the unsigned payload or signature variant is
    /// malformed for this chain.
    fn encode_signed_transaction(
        &self,
        unsigned_tx: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, Self::Error>;
}
