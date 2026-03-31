//! Spark chain signer (Bitcoin L2, secp256k1).
//!
//! Shares Bitcoin's key derivation path and uses the same secp256k1 curve.
//! Address format: `spark:<hex_pubkey_hash>`.

use alloc::format;
use alloc::string::String;

use k256::ecdsa::SigningKey;
#[allow(unused_imports)]
use alloc::vec; // Vec used in sign method
use sha2::{Digest, Sha256};

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// Spark chain signer.
#[derive(Debug, Clone, Copy)]
pub struct SparkSigner;

impl SparkSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidKey(e.to_string()))
    }
}

impl ChainSigner for SparkSigner {
    fn chain(&self) -> Chain { Chain::Spark }
    fn curve(&self) -> Curve { Curve::Secp256k1 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(true);
        let hash = Sha256::digest(pk.as_bytes());
        Ok(format!("spark:{}", hex::encode(hash)))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes", message.len()
            )));
        }
        let sk = Self::signing_key(private_key)?;
        let (sig, rid) = sk
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.push(rid.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(rid.to_byte()),
            public_key: None,
        })
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(Sha256::digest(message));
        self.sign(private_key, &hash)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(Sha256::digest(tx_bytes));
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        // Shares Bitcoin's derivation path
        format!("m/84'/0'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_prefix() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = SparkSigner.derive_address(&pk).unwrap();
        assert!(addr.starts_with("spark:"), "got: {addr}");
    }

    #[test]
    fn shares_bitcoin_derivation_path() {
        assert_eq!(SparkSigner.default_derivation_path(0), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn chain_properties() {
        assert_eq!(SparkSigner.chain(), Chain::Spark);
        assert_eq!(SparkSigner.curve(), Curve::Secp256k1);
    }
}
