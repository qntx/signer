//! Unified signing traits and types for multi-chain transaction signers.
//!
//! This crate defines the capability traits that every chain-specific signer
//! crate implements — [`Sign`] for the core signing workflow,
//! [`EncodeSignedTransaction`] and [`ExtractSignableBytes`] for opt-in
//! transaction assembly — plus the discriminated [`SignOutput`] enum that
//! covers every wire format the workspace produces.
//!
//! # Design principles
//!
//! - **Single source of truth** — [`SignError`] is defined once here; chain
//!   crates re-export it directly and only introduce a wrapper enum when they
//!   carry additional failure modes.
//! - **Capability traits** — [`Sign`] is the mandatory surface; optional
//!   capabilities live in separate traits so types never carry "not
//!   implemented" lies.
//! - **Type-safe digests** — `sign_hash` accepts `&[u8; 32]`; ragged byte
//!   slices are rejected at compile time.
//! - **Discriminated output** — [`SignOutput`] variants mirror real wire
//!   formats; callers pattern-match instead of juggling `Option` metadata.
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

/// Mandatory signing surface implemented by every chain-specific `Signer`.
///
/// Signers hold their private key internally and expose three entry points
/// layered by abstraction level:
///
/// - [`sign_hash`](Self::sign_hash) — sign a pre-computed 32-byte digest.
///   Type-safe (`&[u8; 32]`) and chain-agnostic.
/// - [`sign_message`](Self::sign_message) — apply the chain's message prefix
///   / hash policy, then sign.
/// - [`sign_transaction`](Self::sign_transaction) — interpret the input as
///   the chain's unsigned transaction bytes, hash, and sign.
///
/// # Thread safety
///
/// Implementors must be `Send + Sync` so signers can cross async task
/// boundaries and multi-threaded executors.
///
/// # Error contract
///
/// `Error` must be convertible from the shared [`SignError`] so chain crates
/// can layer their own variants on top without losing the core failure modes.
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
    /// Error returned by every signing operation.
    ///
    /// Must lift [`SignError`] losslessly so downstream code can attribute
    /// core failures without string-matching.
    type Error: core::fmt::Debug + core::fmt::Display + From<SignError> + Send + Sync + 'static;

    /// Sign a pre-hashed 32-byte digest.
    ///
    /// All workspace chains sign 32-byte digests (SHA-256, SHA3-256,
    /// BLAKE2b-256, Keccak-256, SHA-512-half). Consumers that already hold a
    /// digest should call this directly; chains that need domain-specific
    /// prefixing go through [`sign_message`](Self::sign_message) or
    /// [`sign_transaction`](Self::sign_transaction) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying signing primitive fails.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, Self::Error>;

    /// Sign an arbitrary message with the chain's message-signing convention.
    ///
    /// | Chain        | Transform                                                  |
    /// |--------------|------------------------------------------------------------|
    /// | EVM          | Keccak-256 of `EIP-191` prefix + message (`v = 27 \| 28`)  |
    /// | Bitcoin      | double-SHA256 of `\x18Bitcoin Signed Message:\n` + varint  |
    /// | Tron         | Keccak-256 of `\x19TRON Signed Message:\n` + message       |
    /// | Cosmos       | SHA-256 of the raw message                                 |
    /// | Solana / TON | Raw Ed25519 (no prefix)                                    |
    /// | Sui          | BLAKE2b-256 of intent + BCS-encoded message                |
    /// | Aptos        | Raw Ed25519 (no domain prefix)                             |
    /// | Nostr        | Raw BIP-340 Schnorr (no prefix)                            |
    /// | XRPL         | Not supported (returns an error)                           |
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails, or if the chain does not define a
    /// canonical message-signing scheme.
    fn sign_message(&self, message: &[u8]) -> Result<SignOutput, Self::Error>;

    /// Sign an unsigned transaction using the chain's sighash convention.
    ///
    /// Each chain crate documents the exact expected input format on its
    /// `Signer::sign_transaction` method (e.g. EVM expects an unsigned RLP
    /// payload, BTC a sighash preimage, Cosmos a `SignDoc`, XRPL the
    /// transaction body *without* the `STX\0` prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is malformed or signing fails.
    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, Self::Error>;
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

/// Blanket extension trait that adds flat-byte convenience wrappers to every
/// [`Sign`] implementor.
pub trait SignExt: Sign {
    /// Sign a 32-byte digest and return the flat signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    #[inline]
    fn sign_hash_bytes(&self, hash: &[u8; 32]) -> Result<Vec<u8>, Self::Error> {
        self.sign_hash(hash).map(|out| out.to_bytes())
    }

    /// Sign a message and return the flat signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    #[inline]
    fn sign_message_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_message(message).map(|out| out.to_bytes())
    }

    /// Sign a transaction and return the flat signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    #[inline]
    fn sign_transaction_bytes(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_transaction(tx_bytes).map(|out| out.to_bytes())
    }
}

impl<T: Sign> SignExt for T {}
