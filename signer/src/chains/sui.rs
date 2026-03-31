//! Sui chain signer (Ed25519).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// Sui chain signer.
#[derive(Debug, Clone, Copy)]
pub struct SuiSigner;

impl SuiSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Sui address = `0x` + hex(SHA3-256(0x00 || pubkey))[..64]
    fn sui_address(vk: &VerifyingKey) -> String {
        let mut data = Vec::with_capacity(33);
        data.push(0x00); // Ed25519 scheme flag
        data.extend_from_slice(vk.as_bytes());
        let hash = Sha3_256::digest(&data);
        format!("0x{}", hex::encode(hash))
    }
}

impl ChainSigner for SuiSigner {
    fn chain(&self) -> Chain { Chain::Sui }
    fn curve(&self) -> Curve { Curve::Ed25519 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        Ok(Self::sui_address(&vk))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let sig = sk.sign(message);
        Ok(SignOutput {
            signature: sig.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(vk.as_bytes().to_vec()),
        })
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Sui uses intent-prefixed signing for messages
        // Intent prefix for personal message: [3, 0, 0]
        let mut prefixed = Vec::with_capacity(3 + message.len());
        prefixed.extend_from_slice(&[3, 0, 0]);
        prefixed.extend_from_slice(message);
        let hash = sha2::Sha256::digest(&prefixed);
        self.sign(private_key, &hash)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Sui transaction intent: [0, 0, 0] prefix then SHA256
        let mut prefixed = Vec::with_capacity(3 + tx_bytes.len());
        prefixed.extend_from_slice(&[0, 0, 0]);
        prefixed.extend_from_slice(tx_bytes);
        let hash = sha2::Sha256::digest(&prefixed);
        self.sign(private_key, &hash)
    }

    fn encode_signed_transaction(
        &self,
        _tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Sui serialized signature = scheme_flag(1) || sig(64) || pubkey(32)
        let pubkey = signature.public_key.as_ref().ok_or_else(|| {
            SignerError::InvalidTransaction("Sui requires public_key in SignOutput".into())
        })?;

        let mut out = Vec::with_capacity(1 + 64 + 32);
        out.push(0x00); // Ed25519 flag
        out.extend_from_slice(&signature.signature);
        out.extend_from_slice(pubkey);
        Ok(out)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/784'/{index}'/0'/0'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_format() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let addr = SuiSigner.derive_address(&pk).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn sign_includes_pubkey() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let result = SuiSigner.sign(&pk, b"test").unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.unwrap().len(), 32);
    }

    #[test]
    fn encode_signed_tx() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let result = SuiSigner.sign(&pk, b"test").unwrap();
        let encoded = SuiSigner.encode_signed_transaction(b"", &result).unwrap();
        assert_eq!(encoded.len(), 97); // 1 + 64 + 32
        assert_eq!(encoded[0], 0x00); // Ed25519 flag
    }

    #[test]
    fn derivation_path() {
        assert_eq!(SuiSigner.default_derivation_path(0), "m/44'/784'/0'/0'/0'");
    }

    #[test]
    fn chain_properties() {
        assert_eq!(SuiSigner.chain(), Chain::Sui);
        assert_eq!(SuiSigner.curve(), Curve::Ed25519);
    }
}
