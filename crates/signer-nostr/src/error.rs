//! Error types for the Nostr signer.
//!
//! Follows the same pattern as `kobe` chain crates: a transparent
//! [`Core`](SignError::Core) wrapper around [`signer_primitives::SignError`]
//! plus Nostr-specific variants (currently [`Bech32`](SignError::Bech32) for
//! NIP-19 encoding failures).

use alloc::string::String;

/// Errors from Nostr signing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// Core signer error (key / message / signature / transaction).
    #[error(transparent)]
    Core(#[from] signer_primitives::SignError),

    /// NIP-19 bech32 decoding or encoding failed (or HRP mismatch).
    #[error("nip-19 bech32 error: {0}")]
    Bech32(String),
}
