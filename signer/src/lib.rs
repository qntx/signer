//! Lightweight multi-chain cryptographic signer.
//!
//! A single crate covering key derivation, mnemonic generation, and
//! transaction signing for all major blockchain families — built from
//! pure cryptographic primitives with no heavy framework dependencies.
//!
//! # Features
//!
//! - **`no_std` compatible** (with `alloc`) — disable the default `std` feature.
//! - **Per-chain feature flags** — compile only the chains you need.
//! - **Unified [`ChainSigner`] trait** — consistent API across all chains.
//! - **Hand-written BIP-32 / BIP-39 / SLIP-10** — no `coins-bip32` / `coins-bip39`.
//! - **Security hardening** (std) — `mlock`, zeroize-on-drop, signal cleanup.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use signer::{chains, chain::Chain, hd::HdDeriver, mnemonic::Mnemonic, curve::Curve};
//!
//! let mnemonic = Mnemonic::from_phrase(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//! ).unwrap();
//!
//! let signer = chains::signer_for_chain(Chain::Evm);
//! let path = signer.default_derivation_path(0);
//! let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Secp256k1).unwrap();
//! let address = signer.derive_address(key.expose()).unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod chain;
pub mod chains;
pub mod curve;
pub mod eip712;
pub mod error;
pub mod hd;
pub mod mnemonic;
pub mod rlp;
pub mod secret;
pub mod traits;

#[cfg(feature = "std")]
pub mod hardening;

pub use chain::Chain;
pub use curve::Curve;
pub use error::{HdError, MnemonicError, SignerError};
pub use hd::HdDeriver;
pub use mnemonic::Mnemonic;
pub use secret::SecretBytes;
pub use traits::{ChainSigner, SignOutput};
