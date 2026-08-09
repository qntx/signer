//! Shared secret-key loading for all curve primitives and chain signers.

use alloc::format;
use alloc::string::ToString;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::SignError;

/// Owned 32-byte secret key material (zeroized on drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32(Zeroizing<[u8; 32]>);

impl SecretKey32 {
    /// Wrap raw secret bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the inner 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy out a zeroizing clone of the secret.
    #[must_use]
    pub fn to_zeroizing(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }
}

impl core::fmt::Debug for SecretKey32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey32([REDACTED])")
    }
}

impl AsRef<[u8; 32]> for SecretKey32 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SecretKey32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

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

/// Parse hex into a [`SecretKey32`].
///
/// # Errors
///
/// See [`parse_secret_hex`].
pub fn parse_secret_key(hex_str: &str) -> Result<SecretKey32, SignError> {
    Ok(SecretKey32::new(parse_secret_hex(hex_str)?))
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

    /// Build from an owned [`SecretKey32`].
    ///
    /// # Errors
    ///
    /// See [`from_secret_bytes`](Self::from_secret_bytes).
    fn from_secret_key(key: &SecretKey32) -> Result<Self, SignError> {
        Self::from_secret_bytes(key.as_bytes())
    }

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
