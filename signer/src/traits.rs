//! Unified signing trait for all chains.

use alloc::string::String;
use alloc::vec::Vec;

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;

/// Output of a signing operation.
#[derive(Debug, Clone)]
pub struct SignOutput {
    /// Raw signature bytes.
    pub signature: Vec<u8>,
    /// Recovery ID (secp256k1 only; `None` for Ed25519).
    pub recovery_id: Option<u8>,
    /// Public key bytes (needed by chains whose wire format includes the pubkey).
    pub public_key: Option<Vec<u8>>,
}

/// Chain-specific signer.
///
/// All methods accept raw `&[u8]` private keys — callers handle HD derivation
/// and zeroization of key material.
pub trait ChainSigner: Send + Sync {
    /// Which chain family this signer handles.
    fn chain(&self) -> Chain;

    /// Elliptic curve used by this chain.
    fn curve(&self) -> Curve;

    /// Derive an on-chain address from a private key.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::InvalidKey`] or [`SignerError::AddressFailed`].
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError>;

    /// Sign a pre-hashed message (32 bytes for secp256k1, raw bytes for Ed25519).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] on invalid key or message.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;

    /// Sign an arbitrary message with chain-specific prefixing / hashing
    /// (e.g. EIP-191 for EVM).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] on invalid key or message.
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;

    /// Sign an unsigned transaction.
    ///
    /// `tx_bytes` is the signable payload — the bytes that validators expect
    /// the signature to cover. Each chain hashes internally as needed.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] on invalid key or malformed transaction.
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError>;

    /// Extract the signable portion from a full serialized transaction.
    ///
    /// Some wire formats include non-signed metadata (e.g. Solana prepends
    /// signature-slot placeholders). The default returns the input unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::InvalidTransaction`] if the bytes are malformed.
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        Ok(tx_bytes)
    }

    /// Encode the signed transaction from unsigned bytes + signature.
    ///
    /// Returns bytes suitable for broadcasting.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::InvalidTransaction`] if not implemented or
    /// the inputs are malformed.
    fn encode_signed_transaction(
        &self,
        _tx_bytes: &[u8],
        _signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        Err(SignerError::InvalidTransaction(alloc::format!(
            "encode_signed_transaction not implemented for {}",
            self.chain()
        )))
    }

    /// Default BIP-44 derivation path for the given account index.
    fn default_derivation_path(&self, index: u32) -> String;
}
