//! Cosmos SDK chain signer (secp256k1 + bech32).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// Cosmos SDK chain signer.
#[derive(Debug, Clone)]
pub struct CosmosSigner {
    /// Bech32 human-readable prefix (e.g. `"cosmos"`, `"osmo"`).
    prefix: String,
}

impl CosmosSigner {
    /// Create a signer with a custom bech32 prefix.
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self { prefix: prefix.into() }
    }

    /// Cosmos Hub signer (`cosmos1…`).
    #[must_use]
    pub fn cosmos_hub() -> Self { Self::new("cosmos") }

    /// Osmosis signer (`osmo1…`).
    #[must_use]
    pub fn osmosis() -> Self { Self::new("osmo") }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidKey(e.to_string()))
    }

    fn hash160(data: &[u8]) -> Vec<u8> {
        Ripemd160::digest(Sha256::digest(data)).to_vec()
    }
}

impl ChainSigner for CosmosSigner {
    fn chain(&self) -> Chain { Chain::Cosmos }
    fn curve(&self) -> Curve { Curve::Secp256k1 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(true);
        let hash = Self::hash160(pk.as_bytes());

        let hrp = bech32::Hrp::parse(&self.prefix)
            .map_err(|e| SignerError::AddressFailed(e.to_string()))?;
        bech32::encode::<bech32::Bech32>(hrp, &hash)
            .map_err(|e| SignerError::AddressFailed(e.to_string()))
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
        let hash = Sha256::digest(message);
        self.sign(private_key, &hash)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/118'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosmos_hub_address_prefix() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = CosmosSigner::cosmos_hub().derive_address(&pk).unwrap();
        assert!(addr.starts_with("cosmos1"));
    }

    #[test]
    fn osmosis_address_prefix() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = CosmosSigner::osmosis().derive_address(&pk).unwrap();
        assert!(addr.starts_with("osmo1"));
    }

    #[test]
    fn derivation_path() {
        assert_eq!(CosmosSigner::cosmos_hub().default_derivation_path(0), "m/44'/118'/0'/0/0");
    }

    #[test]
    fn chain_properties() {
        let s = CosmosSigner::cosmos_hub();
        assert_eq!(s.chain(), Chain::Cosmos);
        assert_eq!(s.curve(), Curve::Secp256k1);
    }
}
