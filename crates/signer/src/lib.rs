//! Multi-chain transaction signer.
//!
//! Umbrella crate re-exporting chain-specific signer crates.
//! Each chain is feature-gated and enabled by default.
//!
//! Wallet creation and HD key derivation are handled by
//! [`kobe`](https://github.com/qntx/kobe). This crate is **signing only**.
//!
//! Enable the `kobe` feature to activate bridge constructors
//! (e.g. `signer::evm::Signer::from_derived(&kobe_evm_account)`).
//!
//! # Usage
//!
//! ```rust,no_run
//! // Direct usage with a hex private key
//! use signer::evm;
//! let s = evm::Signer::from_hex("0x...").unwrap();
//! let sig = s.sign_message(b"hello").unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "aptos")]
pub use signer_aptos as aptos;
#[cfg(feature = "btc")]
pub use signer_btc as btc;
#[cfg(feature = "cosmos")]
pub use signer_cosmos as cosmos;
#[cfg(feature = "evm")]
pub use signer_evm as evm;
#[cfg(feature = "fil")]
pub use signer_fil as fil;
pub use signer_primitives as core;
pub use signer_primitives::{Sign, SignError, SignExt, SignOutput};
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
