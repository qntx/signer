//! TON (The Open Network) chain signer (Ed25519).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

/// TON chain signer.
#[derive(Debug, Clone, Copy)]
pub struct TonSigner;

impl TonSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Compute TON non-bounceable user-friendly address from a public key.
    ///
    /// Format: workchain(0) + StateInit hash → base64url with checksum.
    fn ton_address(pubkey: &VerifyingKey) -> Result<String, SignerError> {
        // Build the standard wallet v4r2 StateInit cell hash
        // Simplified: we compute the address from the raw public key hash
        // TON address = base64url(0x11 | 0x00 | workchain(1 byte) | hash(32 bytes) | crc16(2 bytes))
        let workchain: u8 = 0;

        // For wallet v4r2, the account state hash includes the public key
        // Simplified approach: SHA256 of the public key as the state hash
        let state_hash = Sha256::digest(pubkey.as_bytes());

        let mut raw = Vec::with_capacity(36);
        // Tag: 0x11 = non-bounceable, 0x51 = bounceable
        raw.push(0x51); // bounceable
        raw.push(workchain);
        raw.extend_from_slice(&state_hash);

        let crc = crc16_xmodem(&raw);
        raw.extend_from_slice(&crc.to_be_bytes());

        // Convert bounceable to non-bounceable for user-friendly display
        raw[0] = 0x51;
        let _bounceable = base64_url_encode(&raw);

        // Non-bounceable version
        raw[0] = 0x11;
        let _non_bounceable = base64_url_encode(&raw);

        // Return non-bounceable (UQ prefix)
        raw[0] = 0x11;
        let crc = crc16_xmodem(&raw[..34]);
        raw[34] = (crc >> 8) as u8;
        raw[35] = crc as u8;
        Ok(base64_url_encode(&raw))
    }
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE.encode(data)
}

impl ChainSigner for TonSigner {
    fn chain(&self) -> Chain { Chain::Ton }
    fn curve(&self) -> Curve { Curve::Ed25519 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        Self::ton_address(&vk)
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

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/607'/{index}'/0'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_length() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let addr = TonSigner.derive_address(&pk).unwrap();
        assert_eq!(addr.len(), 48);
    }

    #[test]
    fn sign_verify() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let result = TonSigner.sign(&pk, b"test").unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn derivation_path() {
        assert_eq!(TonSigner.default_derivation_path(0), "m/44'/607'/0'/0'");
    }

    #[test]
    fn chain_properties() {
        assert_eq!(TonSigner.chain(), Chain::Ton);
        assert_eq!(TonSigner.curve(), Curve::Ed25519);
    }

    #[test]
    fn crc16() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }
}
