//! Multi-chain transaction signer.
//!
//! This is an umbrella crate that re-exports chain-specific signer crates:
//!
//! - [`btc`] — Bitcoin (ECDSA, Schnorr, PSBT, message signing)
//! - [`evm`] — Ethereum / EVM (EIP-191, EIP-712, transaction signing)
//! - [`svm`] — Solana / SVM (Ed25519 signing)
//!
//! Each chain crate is feature-gated and enabled by default. Enable the
//! `kobe` feature to activate wallet bridging with
//! [`kobe`](https://github.com/qntx/kobe) HD wallet.
//!
//! # Usage
//!
//! ```rust,no_run
//! // Via umbrella crate
//! use signer::evm;
//! let s = evm::Signer::random();
//!
//! // Or depend on a chain crate directly
//! // use signer_evm::Signer;
//! ```

#[cfg(feature = "btc")]
pub use signer_btc as btc;
#[cfg(feature = "evm")]
pub use signer_evm as evm;
#[cfg(feature = "svm")]
pub use signer_svm as svm;
