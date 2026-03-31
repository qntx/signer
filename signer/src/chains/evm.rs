//! EVM (Ethereum-compatible) chain signer.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// EVM chain signer (secp256k1 + Keccak-256).
#[derive(Debug, Clone, Copy)]
pub struct EvmSigner;

impl EvmSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidKey(e.to_string()))
    }

    fn eip55_checksum(address_hex: &str) -> String {
        let lower = address_hex.to_lowercase();
        let hash = Keccak256::digest(lower.as_bytes());
        let hash_hex = hex::encode(hash);

        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in lower.chars().enumerate() {
            if c.is_ascii_digit() {
                out.push(c);
            } else {
                let nibble = u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap_or(0);
                out.push(if nibble >= 8 { c.to_ascii_uppercase() } else { c });
            }
        }
        out
    }

    /// Sign EIP-712 typed structured data.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] on invalid key or malformed typed data JSON.
    pub fn sign_typed_data(
        &self,
        private_key: &[u8],
        typed_data_json: &str,
    ) -> Result<SignOutput, SignerError> {
        let typed_data = crate::eip712::parse_typed_data(typed_data_json)?;
        let hash = crate::eip712::hash_typed_data(&typed_data)?;
        let mut output = self.sign(private_key, &hash)?;

        if let Some(rid) = output.recovery_id {
            let v = rid + 27;
            output.signature[64] = v;
            output.recovery_id = Some(v);
        }
        Ok(output)
    }
}

impl ChainSigner for EvmSigner {
    fn chain(&self) -> Chain { Chain::Evm }
    fn curve(&self) -> Curve { Curve::Secp256k1 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&pk.as_bytes()[1..]);
        let address_hex = hex::encode(&hash[12..]);
        Ok(Self::eip55_checksum(&address_hex))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte prehash, got {} bytes", message.len()
            )));
        }

        let sk = Self::signing_key(private_key)?;
        let (signature, recovery_id) = sk
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
            public_key: None,
        })
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(message);

        let hash = Keccak256::digest(&prefixed);
        let mut output = self.sign(private_key, &hash)?;

        if let Some(rid) = output.recovery_id {
            let v = rid + 27;
            output.signature[64] = v;
            output.recovery_id = Some(v);
        }
        Ok(output)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let hash = Keccak256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 65 {
            return Err(SignerError::InvalidTransaction(
                "expected 65-byte signature (r || s || v)".into(),
            ));
        }

        let v = signature.signature[64];
        let r: [u8; 32] = signature.signature[..32]
            .try_into()
            .map_err(|_| SignerError::InvalidTransaction("bad r".into()))?;
        let s: [u8; 32] = signature.signature[32..64]
            .try_into()
            .map_err(|_| SignerError::InvalidTransaction("bad s".into()))?;

        crate::rlp::encode_signed_typed_tx(tx_bytes, v, &r, &s)
            .map_err(|e| SignerError::InvalidTransaction(e.into()))
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/60'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    #[test]
    fn known_privkey_to_address() {
        let pk = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap();
        let addr = EvmSigner.derive_address(&pk).unwrap();
        assert_eq!(addr, "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
    }

    #[test]
    fn sign_and_verify() {
        let pk = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap();
        let hash = Keccak256::digest(b"test message");
        let result = EvmSigner.sign(&pk, &hash).unwrap();
        assert_eq!(result.signature.len(), 65);

        let sk = SigningKey::from_slice(&pk).unwrap();
        let vk = sk.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
        vk.verify_prehash(&hash, &sig).unwrap();
    }

    #[test]
    fn sign_message_v_byte() {
        let pk = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap();
        let result = EvmSigner.sign_message(&pk, b"Hello World").unwrap();
        let v = result.signature[64];
        assert!(v == 27 || v == 28);
    }

    #[test]
    fn derivation_path() {
        assert_eq!(EvmSigner.default_derivation_path(0), "m/44'/60'/0'/0/0");
        assert_eq!(EvmSigner.default_derivation_path(5), "m/44'/60'/0'/0/5");
    }

    #[test]
    fn rejects_invalid_key() {
        assert!(EvmSigner.derive_address(&[0u8; 16]).is_err());
    }

    #[test]
    fn rejects_non_32_byte_hash() {
        let pk = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap();
        assert!(EvmSigner.sign(&pk, b"short").is_err());
    }

    #[test]
    fn chain_properties() {
        assert_eq!(EvmSigner.chain(), Chain::Evm);
        assert_eq!(EvmSigner.curve(), Curve::Secp256k1);
    }
}
