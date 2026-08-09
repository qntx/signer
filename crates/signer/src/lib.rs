//! Multi-chain transaction signer (umbrella).
//!
//! # Layers
//!
//! ```text
//! L0  signer-primitives   curves + SignDigest / SignOutput
//! L1  signer-{chain}      protocol preimage + wire (this crate re-exports)
//! L2  signer-cli          ops UX
//! ──  kobe                HD only — use feature `kobe` + FromDerived
//! ```
//!
//! Schemes: secp256k1 ECDSA, BIP-340 Schnorr, Ed25519. Framing (EIP-191,
//! BIP-137, …) stays in chain crates — this is not a “hash-only” strip.
//!
//! # Usage
//!
//! ```rust,no_run
//! use signer::{SignMessage, evm};
//!
//! let s = evm::Signer::from_hex("0x...").unwrap();
//! let sig = s.sign_message(b"hello").unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "aptos")]
pub use signer_aptos as aptos;
#[cfg(feature = "btc")]
pub use signer_btc as btc;
#[cfg(feature = "casper")]
pub use signer_casper as casper;
#[cfg(feature = "cosmos")]
pub use signer_cosmos as cosmos;
#[cfg(feature = "evm")]
pub use signer_evm as evm;
#[cfg(feature = "fil")]
pub use signer_fil as fil;
#[cfg(feature = "nostr")]
pub use signer_nostr as nostr;
pub use signer_primitives as primitives;
#[cfg(feature = "kobe")]
pub use signer_primitives::FromDerived;
pub use signer_primitives::{
    Digest32, EncodeSignedTransaction, ExtractSignableBytes, FromSecretKey, SecretKey32,
    SignDigest, SignError, SignMessage, SignOutput, SignatureScheme, v_encoding,
};
#[cfg(feature = "spark")]
pub use signer_spark as spark;
#[cfg(feature = "sui")]
pub use signer_sui as sui;
#[cfg(feature = "svm")]
pub use signer_svm as svm;
#[cfg(feature = "ton")]
pub use signer_ton as ton;
#[cfg(feature = "tron")]
pub use signer_tron as tron;
#[cfg(feature = "xrpl")]
pub use signer_xrpl as xrpl;

/// Prelude that imports every capability trait plus [`SignOutput`] and
/// [`SignError`] in one glob.
///
/// ```rust,no_run
/// use signer::prelude::*;
/// ```
pub mod prelude {
    pub use signer_primitives::{
        Digest32, EncodeSignedTransaction, ExtractSignableBytes, SignDigest, SignError,
        SignMessage, SignOutput, SignatureScheme,
    };
}
