//! Error types for the Solana signer.

signer_primitives::define_sign_error! {
    "Errors from Solana signing operations.";
    /// Keypair bytes are malformed.
    #[error("invalid keypair: {0}")]
    InvalidKeypair(alloc::string::String),
    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerifyFailed(ed25519_dalek::SignatureError),
}

impl From<ed25519_dalek::SignatureError> for SignError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::VerifyFailed(e)
    }
}
