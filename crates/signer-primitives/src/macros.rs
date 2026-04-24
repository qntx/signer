//! Declarative macros that remove boilerplate from chain-specific signer
//! wrappers.
//!
//! The workspace's chain signers are thin newtypes around
//! [`Secp256k1Signer`](crate::Secp256k1Signer),
//! [`Ed25519Signer`](crate::Ed25519Signer), or
//! [`SchnorrSigner`](crate::SchnorrSigner). Their constructors (`from_bytes`,
//! `from_hex`, `random`) are pure delegation, so each chain crate calls one
//! of the macros below instead of repeating the identical bodies thirteen
//! times.
//!
//! All constructors return [`crate::SignError`] directly: the v2.0
//! workspace unification folded every chain-specific error wrapper into a
//! single type, so there is no need for a per-crate error parameter.

/// Emit `from_bytes`, `from_hex`, `try_random`, and `random` for a tuple
/// newtype that wraps [`Secp256k1Signer`](crate::Secp256k1Signer).
///
/// Every constructor returns `Result<Self, signer_primitives::SignError>`.
///
/// # Example
///
/// ```ignore
/// pub struct Signer(signer_primitives::Secp256k1Signer);
///
/// impl Signer {
///     signer_primitives::delegate_secp256k1_ctors!();
/// }
/// ```
#[macro_export]
macro_rules! delegate_secp256k1_ctors {
    () => {
        /// Create from a raw 32-byte private key.
        ///
        /// # Errors
        ///
        /// Returns an error if the bytes are not a valid secp256k1 scalar
        /// (zero or ≥ curve order).
        pub fn from_bytes(bytes: &[u8; 32]) -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::Secp256k1Signer::from_bytes(bytes)?))
        }

        /// Create from a hex-encoded private key (with or without `0x`).
        ///
        /// # Errors
        ///
        /// Returns an error if the hex is invalid or the key is out of range.
        pub fn from_hex(hex_str: &str) -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::Secp256k1Signer::from_hex(hex_str)?))
        }

        /// Generate a random signer, returning an error on entropy failure.
        ///
        /// # Errors
        ///
        /// Returns an error if the OS RNG is unavailable or the sampled
        /// scalar is out of range (probability ≈ 2⁻¹²⁸).
        #[cfg(feature = "getrandom")]
        pub fn try_random() -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::Secp256k1Signer::try_random()?))
        }

        /// Generate a random signer using OS-provided entropy.
        ///
        /// Thin panicking wrapper over [`Self::try_random`]. Prefer
        /// [`Self::try_random`] in library code and on embedded / WASM
        /// targets.
        ///
        /// # Panics
        ///
        /// Panics if the OS random number generator fails.
        #[cfg(feature = "getrandom")]
        #[must_use]
        pub fn random() -> Self {
            Self($crate::Secp256k1Signer::random())
        }
    };
}

/// Emit `from_bytes`, `from_hex`, `try_random`, and `random` for a tuple
/// newtype that wraps [`Ed25519Signer`](crate::Ed25519Signer).
///
/// Every constructor returns `Result<Self, signer_primitives::SignError>`.
#[macro_export]
macro_rules! delegate_ed25519_ctors {
    () => {
        /// Create from raw 32-byte secret key bytes.
        ///
        /// Every 32-byte input is a valid Ed25519 secret key, so this
        /// constructor currently never fails; the [`Result`] is reserved for
        /// forward compatibility.
        ///
        /// # Errors
        ///
        /// Reserved for future compatibility.
        pub fn from_bytes(bytes: &[u8; 32]) -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::Ed25519Signer::from_bytes(bytes)?))
        }

        /// Create from a hex-encoded 32-byte private key (with or without `0x`).
        ///
        /// # Errors
        ///
        /// Returns an error if the hex is malformed or not exactly 32 bytes.
        pub fn from_hex(hex_str: &str) -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::Ed25519Signer::from_hex(hex_str)?))
        }

        /// Generate a random signer, returning an error on entropy failure.
        ///
        /// # Errors
        ///
        /// Returns an error if the OS RNG is unavailable.
        #[cfg(feature = "getrandom")]
        pub fn try_random() -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::Ed25519Signer::try_random()?))
        }

        /// Generate a random signer using OS-provided entropy.
        ///
        /// Thin panicking wrapper over [`Self::try_random`].
        ///
        /// # Panics
        ///
        /// Panics if the OS random number generator fails.
        #[cfg(feature = "getrandom")]
        #[must_use]
        pub fn random() -> Self {
            Self($crate::Ed25519Signer::random())
        }
    };
}

/// Emit `from_bytes`, `from_hex`, `try_random`, and `random` for a tuple
/// newtype that wraps [`SchnorrSigner`](crate::SchnorrSigner).
///
/// Every constructor returns `Result<Self, signer_primitives::SignError>`.
#[macro_export]
macro_rules! delegate_schnorr_ctors {
    () => {
        /// Create from a raw 32-byte private key.
        ///
        /// # Errors
        ///
        /// Returns an error if the bytes are not a valid secp256k1 scalar
        /// (zero or ≥ curve order).
        pub fn from_bytes(bytes: &[u8; 32]) -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::SchnorrSigner::from_bytes(bytes)?))
        }

        /// Create from a hex-encoded private key (with or without `0x`).
        ///
        /// # Errors
        ///
        /// Returns an error if the hex is invalid or the key is out of range.
        pub fn from_hex(hex_str: &str) -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::SchnorrSigner::from_hex(hex_str)?))
        }

        /// Generate a random signer, returning an error on entropy failure.
        ///
        /// # Errors
        ///
        /// Returns an error if the OS RNG is unavailable or the sampled
        /// scalar is out of range (probability ≈ 2⁻¹²⁸).
        #[cfg(feature = "getrandom")]
        pub fn try_random() -> ::core::result::Result<Self, $crate::SignError> {
            Ok(Self($crate::SchnorrSigner::try_random()?))
        }

        /// Generate a random signer using OS-provided entropy.
        ///
        /// Thin panicking wrapper over [`Self::try_random`].
        ///
        /// # Panics
        ///
        /// Panics if the OS random number generator fails.
        #[cfg(feature = "getrandom")]
        #[must_use]
        pub fn random() -> Self {
            Self($crate::SchnorrSigner::random())
        }
    };
}
