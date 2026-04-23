//! Unified signing trait and types for multi-chain transaction signers.
//!
//! This crate defines the [`Sign`] trait that every chain-specific signer
//! crate implements, the blanket [`SignExt`] extension for flat-byte
//! conversions, and a discriminated [`SignOutput`] enum covering every wire
//! format the workspace produces.
//!
//! # Design
//!
//! - **Stateful signers** — each `Signer` holds its private key internally.
//! - **Type-safe hashing** — `sign_hash` requires a `&[u8; 32]` digest; ragged
//!   byte slices are rejected at compile time rather than run time.
//! - **Discriminated output** — [`SignOutput`] is an enum; callers pattern-match
//!   on the variant to reach the exact bytes they need, with no `Option`
//!   boilerplate.
//! - **`Send + Sync`** — signers are safe to share across threads and async
//!   runtimes.
//! - **No address derivation** — that responsibility lives in `kobe`.
//! - **[`SignExt`]** — blanket extension trait that provides convenience
//!   conversions (hex / flat bytes).
//!
//! # Verification
//!
//! Verification is exposed as a chain-specific inherent method on each
//! `Signer` (e.g. `signer_btc::Signer::verify`). Because every chain derives
//! its signable digest from the message through a different transform
//! (EIP-191, Bitcoin message prefix, SUI intent, …), a single generic
//! `Verify` trait would have to replay chain logic, so the workspace keeps
//! verification inherent to avoid false abstraction.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "ed25519")]
mod ed25519;
mod error;
#[cfg(feature = "schnorr")]
mod schnorr;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "testing")]
pub mod testing;

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
    /// depends on the call site:
    ///
    /// | Producer                                                  | `v` encoding |
    /// |-----------------------------------------------------------|--------------|
    /// | `Signer::sign_hash` / `Signer::sign_transaction` (ECDSA)  | `0` or `1` (raw parity)   |
    /// | `signer_evm::Signer::sign_message` (EIP-191) / `sign_typed_data` | `27` or `28` |
    /// | `signer_tron::Signer::sign_message` (TRON message prefix) | `27` or `28` |
    Ecdsa {
        /// 64-byte compact `r || s`.
        signature: [u8; 64],
        /// `v` byte, with chain-specific meaning documented above.
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
}

/// Unified signing trait implemented by every chain signer.
///
/// Signers hold their private key internally and expose three signing entry
/// points. `sign_hash` is the type-safe low-level primitive (exactly 32 bytes
/// in, wire-format [`SignOutput`] out). `sign_message` and `sign_transaction`
/// are chain-aware wrappers that apply the appropriate prefix / hash /
/// serialization before signing.
///
/// **Thread-safety**: implementors must be `Send + Sync` to fit async
/// runtimes and multi-threaded applications.
///
/// # Example
///
/// ```
/// use signer_primitives::{Sign, SignOutput};
///
/// fn sign_with_any<S: Sign>(signer: &S, msg: &[u8]) -> Result<SignOutput, S::Error> {
///     signer.sign_message(msg)
/// }
/// ```
pub trait Sign: Send + Sync {
    /// The error type returned by signing operations.
    type Error: core::fmt::Debug + core::fmt::Display + From<SignError> + Send + Sync;

    /// Sign a pre-hashed 32-byte digest.
    ///
    /// All workspace chains use 32-byte digests (SHA-256 / SHA3-256 /
    /// BLAKE2b-256 / Keccak-256). Consumers that already hold a digest should
    /// call this directly; chains that need domain-specific prefixing go
    /// through [`sign_message`](Self::sign_message) or
    /// [`sign_transaction`](Self::sign_transaction) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying signing primitive fails.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, Self::Error>;

    /// Sign an arbitrary message with chain-specific prefixing / hashing.
    ///
    /// - EVM: EIP-191 `personal_sign` (`v = 27 | 28`).
    /// - Bitcoin: `\x18Bitcoin Signed Message:\n` prefix + compact-size length.
    /// - Tron: `\x19TRON Signed Message:\n` prefix.
    /// - Cosmos: SHA-256 of the raw message.
    /// - Solana / TON: raw Ed25519 sign (no prefix).
    /// - Sui: intent prefix + BCS + BLAKE2b-256.
    /// - Aptos: raw Ed25519 sign.
    /// - Nostr: raw BIP-340 Schnorr (off-protocol).
    /// - XRPL: SHA-512 half + DER.
    ///
    /// Each chain crate documents its exact semantics on its `Signer`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error>;

    /// Sign an unsigned transaction.
    ///
    /// Each chain crate documents the exact expected input format on its
    /// `Signer::sign_transaction` method (e.g. EVM expects an unsigned RLP
    /// payload, BTC a sighash preimage, Cosmos a `SignDoc`).
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is malformed or signing fails.
    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Self::Error>;

    /// Extract the signable portion from a full serialized transaction.
    ///
    /// Some wire formats include non-signed metadata (e.g. Solana prepends
    /// signature-slot placeholders). This method strips that metadata and
    /// returns only the bytes that must be signed. The default implementation
    /// returns the input unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is malformed.
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], Self::Error> {
        Ok(tx_bytes)
    }

    /// Encode a signed transaction from unsigned bytes + signature output.
    ///
    /// The default returns `Err` — chains that support encoding override it.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding is not supported or inputs are malformed.
    fn encode_signed_transaction(
        &self,
        _tx_bytes: &[u8],
        _signature: &SignOutput,
    ) -> Result<Vec<u8>, Self::Error> {
        Err(
            SignError::InvalidTransaction("encode_signed_transaction not implemented".into())
                .into(),
        )
    }
}

/// Extension trait providing additional operations for all [`Sign`] implementors.
///
/// Automatically implemented for any type implementing `Sign`.
pub trait SignExt: Sign {
    /// Sign a 32-byte digest and return the flat signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_hash_bytes(&self, hash: &[u8; 32]) -> Result<Vec<u8>, Self::Error> {
        self.sign_hash(hash).map(|out| out.to_bytes())
    }

    /// Sign a message and return the flat signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_message_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_message(message).map(|out| out.to_bytes())
    }

    /// Sign a transaction and return the flat signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign_transaction_bytes(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_transaction(tx_bytes).map(|out| out.to_bytes())
    }
}

impl<T: Sign> SignExt for T {}
