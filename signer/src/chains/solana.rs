//! Solana chain signer (Ed25519).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// Solana chain signer.
#[derive(Debug, Clone, Copy)]
pub struct SolanaSigner;

impl SolanaSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

impl ChainSigner for SolanaSigner {
    fn chain(&self) -> Chain { Chain::Solana }
    fn curve(&self) -> Curve { Curve::Ed25519 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk: VerifyingKey = sk.verifying_key();
        Ok(bs58::encode(vk.as_bytes()).into_string())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let sig = sk.sign(message);
        Ok(SignOutput {
            signature: sig.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        self.sign(private_key, tx_bytes)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        let message_start = header_len + num_sigs * 64;
        if tx_bytes.len() <= message_start {
            return Err(SignerError::InvalidTransaction(
                "transaction too short for declared signature slots".into(),
            ));
        }
        Ok(&tx_bytes[message_start..])
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }

        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        if num_sigs == 0 {
            return Err(SignerError::InvalidTransaction(
                "transaction has no signature slots".into(),
            ));
        }
        let sigs_end = header_len + num_sigs * 64;
        if tx_bytes.len() < sigs_end {
            return Err(SignerError::InvalidTransaction(
                "transaction too short for declared signature slots".into(),
            ));
        }

        let mut signed = tx_bytes.to_vec();
        signed[header_len..header_len + 64].copy_from_slice(&signature.signature);
        Ok(signed)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/501'/{index}'/0'")
    }
}

/// Decode a Solana compact-u16 length prefix. Returns `(value, bytes_consumed)`.
fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), SignerError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 3 {
            return Err(SignerError::InvalidTransaction(
                "compact-u16 exceeds 3 bytes".into(),
            ));
        }
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(SignerError::InvalidTransaction("truncated compact-u16".into()))
}

#[cfg(test)]
fn encode_compact_u16(mut value: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn build_tx(num_sigs: u16, payload: &[u8]) -> Vec<u8> {
        let mut tx = encode_compact_u16(num_sigs);
        tx.extend(core::iter::repeat_n(0u8, num_sigs as usize * 64));
        let ns = if num_sigs == 0 { 1 } else { num_sigs as u8 };
        tx.extend_from_slice(&[ns, 0x00, 0x01]);
        tx.push(0x02);
        tx.extend_from_slice(&[0xAA; 32]);
        tx.extend_from_slice(&[0x00; 32]);
        tx.extend_from_slice(&[0xCC; 32]);
        tx.push(0x01);
        tx.push(0x01);
        tx.push(0x01);
        tx.push(0x00);
        tx.push(payload.len() as u8);
        tx.extend_from_slice(payload);
        tx
    }

    #[test]
    fn base58_address() {
        let pk = hex::decode(TEST_KEY).unwrap();
        let addr = SolanaSigner.derive_address(&pk).unwrap();
        assert!(!addr.is_empty());
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let pk = hex::decode(TEST_KEY).unwrap();
        let result = SolanaSigner.sign(&pk, b"test message").unwrap();
        assert_eq!(result.signature.len(), 64);

        let sk = SigningKey::from_bytes(&pk.try_into().unwrap());
        let vk = sk.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        vk.verify(b"test message", &sig).unwrap();
    }

    #[test]
    fn no_recovery_id() {
        let pk = hex::decode(TEST_KEY).unwrap();
        let result = SolanaSigner.sign(&pk, b"msg").unwrap();
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn extract_signable_bytes() {
        let tx = build_tx(1, b"payload");
        let signable = SolanaSigner.extract_signable_bytes(&tx).unwrap();
        assert!(signable.len() > 0);
    }

    #[test]
    fn full_sign_and_encode_pipeline() {
        let pk = hex::decode(TEST_KEY).unwrap();
        let tx = build_tx(1, b"pipeline");

        let signable = SolanaSigner.extract_signable_bytes(&tx).unwrap();
        let output = SolanaSigner.sign_transaction(&pk, signable).unwrap();
        let signed = SolanaSigner.encode_signed_transaction(&tx, &output).unwrap();

        assert_eq!(&signed[1..65], &output.signature[..]);
        assert_eq!(signed.len(), tx.len());
    }

    #[test]
    fn derivation_path() {
        assert_eq!(SolanaSigner.default_derivation_path(0), "m/44'/501'/0'/0'");
        assert_eq!(SolanaSigner.default_derivation_path(1), "m/44'/501'/1'/0'");
    }

    #[test]
    fn compact_u16_roundtrip() {
        for val in [0u16, 1, 127, 128, 255, 256, 16383, 16384, 65535] {
            let encoded = encode_compact_u16(val);
            let (decoded, len) = decode_compact_u16(&encoded).unwrap();
            assert_eq!(decoded, val as usize);
            assert_eq!(len, encoded.len());
        }
    }

    #[test]
    fn chain_properties() {
        assert_eq!(SolanaSigner.chain(), Chain::Solana);
        assert_eq!(SolanaSigner.curve(), Curve::Ed25519);
    }
}
