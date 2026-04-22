/// Defines a chain-specific `SignError` enum.
///
/// Generates the standard five signing error variants, a `Hex` variant for
/// hex-decoding errors, and `From` impls for both `hex::FromHexError` and
/// [`SignError`](crate::SignError). Extra chain-specific variants can be
/// appended after a `;` separator; additional `From` impls for those must
/// be written by the caller.
///
/// # Examples
///
/// ```ignore
/// // Secp256k1 chain (no extra variants):
/// signer_primitives::define_sign_error!("Errors from Bitcoin signing operations.");
///
/// // Ed25519 chain with verification error:
/// signer_primitives::define_sign_error! {
///     "Errors from Sui signing operations.";
///     /// Signature verification failed.
///     #[error("verification failed: {0}")]
///     VerifyFailed(ed25519_dalek::SignatureError),
/// }
/// ```
#[macro_export]
macro_rules! define_sign_error {
    ( $doc:expr ) => {
        $crate::define_sign_error!(@build $doc;);
    };
    ( $doc:expr; $( $(#[$vm:meta])* $v:ident($vt:ty) ),+ $(,)? ) => {
        $crate::define_sign_error!(@build $doc; $( $(#[$vm])* $v($vt) ),+);
    };
    ( @build $doc:expr; $( $(#[$vm:meta])* $v:ident($vt:ty) ),* ) => {
        #[doc = $doc]
        #[derive(Debug, thiserror::Error)]
        #[allow(unused_qualifications)]
        pub enum SignError {
            #[doc = "Private key is invalid."]
            #[error("invalid key: {0}")]
            InvalidKey($crate::__private::String),
            #[doc = "Message format is wrong."]
            #[error("invalid message: {0}")]
            InvalidMessage($crate::__private::String),
            #[doc = "Signing primitive failed."]
            #[error("signing failed: {0}")]
            SigningFailed($crate::__private::String),
            #[doc = "Signature bytes are malformed."]
            #[error("invalid signature: {0}")]
            InvalidSignature($crate::__private::String),
            #[doc = "Transaction bytes are malformed."]
            #[error("invalid transaction: {0}")]
            InvalidTransaction($crate::__private::String),
            #[doc = "Hex decoding failed."]
            #[error("hex error: {0}")]
            Hex($crate::__private::FromHexError),
            $(
                $(#[$vm])*
                $v($vt),
            )*
        }

        impl From<$crate::__private::FromHexError> for SignError {
            fn from(e: $crate::__private::FromHexError) -> Self {
                Self::Hex(e)
            }
        }

        impl From<$crate::SignError> for SignError {
            fn from(e: $crate::SignError) -> Self {
                match e {
                    $crate::SignError::InvalidKey(m) => Self::InvalidKey(m),
                    $crate::SignError::InvalidMessage(m) => Self::InvalidMessage(m),
                    $crate::SignError::SigningFailed(m) => Self::SigningFailed(m),
                    $crate::SignError::InvalidSignature(m) => Self::InvalidSignature(m),
                    $crate::SignError::InvalidTransaction(m) => Self::InvalidTransaction(m),
                }
            }
        }
    };
}

/// Implements [`Sign`](crate::Sign) for `Signer` via delegation.
///
/// Delegates `sign_hash`, `sign_message`, and `sign_transaction` to the
/// corresponding inherent methods. Additional overrides can be appended.
///
/// # Examples
///
/// ```ignore
/// // Basic delegation (most chains):
/// signer_primitives::impl_sign_delegate!();
///
/// // With extra overrides:
/// signer_primitives::impl_sign_delegate! {
///     fn encode_signed_transaction(
///         &self, tx_bytes: &[u8], signature: &SignOutput,
///     ) -> Result<alloc::vec::Vec<u8>, Self::Error> {
///         todo!()
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_sign_delegate {
    ( $($extra:tt)* ) => {
        impl $crate::Sign for Signer {
            type Error = SignError;

            fn sign_hash(&self, hash: &[u8]) -> Result<$crate::SignOutput, SignError> {
                Self::sign_hash(self, hash)
            }

            fn sign_message(&self, message: &[u8]) -> Result<$crate::SignOutput, SignError> {
                Self::sign_message(self, message)
            }

            fn sign_transaction(
                &self,
                tx_bytes: &[u8],
            ) -> Result<$crate::SignOutput, SignError> {
                Self::sign_transaction(self, tx_bytes)
            }

            $($extra)*
        }
    };
}
