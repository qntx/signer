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
//! # Custom error types
//!
//! Every macro has two forms:
//!
//! - `delegate_X_ctors!()` — returns [`crate::SignError`] directly.
//! - `delegate_X_ctors!(MyError)` — returns a chain-specific wrapper that
//!   must implement `From<signer_primitives::SignError>` (e.g. the
//!   `Core(#[from])` pattern used by `signer-svm` and `signer-nostr`).

/// Emit `from_bytes`, `from_hex`, and `random` for a tuple newtype that wraps
/// [`Secp256k1Signer`](crate::Secp256k1Signer).
///
/// Produces methods returning `Result<Self, signer_primitives::SignError>`.
/// For chains that carry a wrapper error type, pass the wrapper as an
/// argument: `delegate_secp256k1_ctors!(crate::SignError)`.
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
        $crate::delegate_secp256k1_ctors!($crate::SignError);
    };
    ($err:ty) => {
        /// Create from a raw 32-byte private key.
        ///
        /// # Errors
        ///
        /// Returns an error if the bytes are not a valid secp256k1 scalar
        /// (zero or ≥ curve order).
        pub fn from_bytes(bytes: &[u8; 32]) -> ::core::result::Result<Self, $err> {
            Ok(Self($crate::Secp256k1Signer::from_bytes(bytes)?))
        }

        /// Create from a hex-encoded private key (with or without `0x`).
        ///
        /// # Errors
        ///
        /// Returns an error if the hex is invalid or the key is out of range.
        pub fn from_hex(hex_str: &str) -> ::core::result::Result<Self, $err> {
            Ok(Self($crate::Secp256k1Signer::from_hex(hex_str)?))
        }

        /// Generate a random signer using OS-provided entropy.
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

/// Emit `from_bytes`, `from_hex`, and `random` for a tuple newtype that wraps
/// [`Ed25519Signer`](crate::Ed25519Signer).
///
/// See [`delegate_secp256k1_ctors!`] for the two-arg form.
#[macro_export]
macro_rules! delegate_ed25519_ctors {
    () => {
        $crate::delegate_ed25519_ctors!($crate::SignError);
    };
    ($err:ty) => {
        /// Create from raw 32-byte secret key bytes.
        ///
        /// Every 32-byte input is a valid Ed25519 secret key, so this
        /// constructor currently never fails; the [`Result`] is reserved for
        /// forward compatibility.
        ///
        /// # Errors
        ///
        /// Reserved for future compatibility.
        pub fn from_bytes(bytes: &[u8; 32]) -> ::core::result::Result<Self, $err> {
            Ok(Self($crate::Ed25519Signer::from_bytes(bytes)?))
        }

        /// Create from a hex-encoded 32-byte private key (with or without `0x`).
        ///
        /// # Errors
        ///
        /// Returns an error if the hex is malformed or not exactly 32 bytes.
        pub fn from_hex(hex_str: &str) -> ::core::result::Result<Self, $err> {
            Ok(Self($crate::Ed25519Signer::from_hex(hex_str)?))
        }

        /// Generate a random signer using OS-provided entropy.
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

/// Emit `from_bytes`, `from_hex`, and `random` for a tuple newtype that wraps
/// [`SchnorrSigner`](crate::SchnorrSigner).
///
/// See [`delegate_secp256k1_ctors!`] for the two-arg form.
#[macro_export]
macro_rules! delegate_schnorr_ctors {
    () => {
        $crate::delegate_schnorr_ctors!($crate::SignError);
    };
    ($err:ty) => {
        /// Create from a raw 32-byte private key.
        ///
        /// # Errors
        ///
        /// Returns an error if the bytes are not a valid secp256k1 scalar
        /// (zero or ≥ curve order).
        pub fn from_bytes(bytes: &[u8; 32]) -> ::core::result::Result<Self, $err> {
            Ok(Self($crate::SchnorrSigner::from_bytes(bytes)?))
        }

        /// Create from a hex-encoded private key (with or without `0x`).
        ///
        /// # Errors
        ///
        /// Returns an error if the hex is invalid or the key is out of range.
        pub fn from_hex(hex_str: &str) -> ::core::result::Result<Self, $err> {
            Ok(Self($crate::SchnorrSigner::from_hex(hex_str)?))
        }

        /// Generate a random signer using OS-provided entropy.
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
