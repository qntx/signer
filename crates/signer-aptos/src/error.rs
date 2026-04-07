//! Error types for the Aptos signer.

signer_primitives::define_sign_error! {
    "Errors from Aptos signing operations.";
    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerifyFailed(ed25519_dalek::SignatureError),
}

impl From<ed25519_dalek::SignatureError> for SignError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::VerifyFailed(e)
    }
}
