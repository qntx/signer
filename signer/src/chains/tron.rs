//! TRON chain signer (secp256k1 + Keccak-256 + Base58Check).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// TRON chain signer.
#[derive(Debug, Clone, Copy)]
pub struct TronSigner;

impl TronSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidKey(e.to_string()))
    }

    /// Base58Check encode with a version byte prefix.
    fn base58check_encode(version: u8, payload: &[u8]) -> String {
        let mut data = Vec::with_capacity(1 + payload.len() + 4);
        data.push(version);
        data.extend_from_slice(payload);
        let checksum = Sha256::digest(Sha256::digest(&data));
        data.extend_from_slice(&checksum[..4]);
        bs58::encode(&data).into_string()
    }
}

impl ChainSigner for TronSigner {
    fn chain(&self) -> Chain { Chain::Tron }
    fn curve(&self) -> Curve { Curve::Secp256k1 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&pk.as_bytes()[1..]);
        // TRON address = 0x41 + last 20 bytes of keccak256 hash
        Ok(Self::base58check_encode(0x41, &hash[12..]))
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
        // TRON message signing: keccak256 of prefixed message (same as Ethereum)
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(message);
        let hash = Keccak256::digest(&prefixed);
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
        format!("m/44'/195'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_starts_with_t() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = TronSigner.derive_address(&pk).unwrap();
        assert!(addr.starts_with('T'));
        assert_eq!(addr.len(), 34);
    }

    #[test]
    fn derivation_path() {
        assert_eq!(TronSigner.default_derivation_path(0), "m/44'/195'/0'/0/0");
    }

    #[test]
    fn chain_properties() {
        assert_eq!(TronSigner.chain(), Chain::Tron);
        assert_eq!(TronSigner.curve(), Curve::Secp256k1);
    }
}
