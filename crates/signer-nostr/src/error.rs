//! Nostr-specific signing error type.

signer_primitives::define_sign_error! {
    "Errors from Nostr signing operations.";
    /// NIP-19 bech32 decoding or encoding failed (or HRP mismatch).
    #[error("nip-19 bech32 error: {0}")]
    Bech32(alloc::string::String),
}
