//! Error types for Filecoin signing operations.

/// Errors that can occur during Filecoin signing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Invalid private key.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    Signing(String),
}
