//! Shared secret-key loading for all curve primitives and chain signers.

use alloc::format;
use alloc::string::ToString;

use crate::SignError;

/// Parse a 32-byte secret from hex (optional `0x` prefix).
///
/// # Errors
///
/// Returns [`SignError::InvalidKey`] if the hex is malformed or not exactly
/// 32 bytes after decoding.
pub fn parse_secret_hex(hex_str: &str) -> Result<[u8; 32], SignError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let decoded = hex::decode(stripped).map_err(|e| SignError::InvalidKey(e.to_string()))?;
    <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| {
        SignError::InvalidKey(format!(
            "expected 32-byte secret key, got {} bytes",
            decoded.len()
        ))
    })
}

/// Construct a signer from raw secret-key material.
///
/// Implemented by every chain `Signer` and by the three curve primitives.
/// Prefer this trait (or the `from_bytes` / `from_hex` methods the macros
/// generate) over ad-hoc hex decoding at call sites.
pub trait FromSecretKey: Sized {
    /// Build from a 32-byte secret key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the bytes are not a valid key for
    /// the underlying curve (e.g. secp256k1 scalar out of range). Ed25519
    /// accepts every 32-byte string.
    fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SignError>;

    /// Build from hex (optional `0x` prefix).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] on hex/length/curve failures.
    fn from_secret_hex(hex_str: &str) -> Result<Self, SignError> {
        let bytes = parse_secret_hex(hex_str)?;
        Self::from_secret_bytes(&bytes)
    }
}

#[cfg(feature = "kobe")]
mod kobe_bridge {
    use kobe_primitives::DerivedAccount;

    use super::FromSecretKey;
    use crate::SignError;

    /// Construct a signer from a kobe-derived account.
    ///
    /// Accepts any type that can borrow a [`DerivedAccount`] (`DerivedAccount`
    /// itself, `BtcAccount`, `SvmAccount`, `NostrAccount`, `CasperAccount`, …).
    pub trait FromDerived: FromSecretKey {
        /// Build from a kobe HD account's 32-byte private key.
        ///
        /// # Errors
        ///
        /// Returns [`SignError::InvalidKey`] if the derived scalar is invalid
        /// for this signer's curve.
        fn from_derived(account: &impl AsRef<DerivedAccount>) -> Result<Self, SignError> {
            let sk = account.as_ref().private_key_bytes();
            Self::from_secret_bytes(sk)
        }
    }

    /// Blanket: every [`FromSecretKey`] type is automatically [`FromDerived`].
    impl<T: FromSecretKey> FromDerived for T {}
}

#[cfg(feature = "kobe")]
pub use kobe_bridge::FromDerived;
