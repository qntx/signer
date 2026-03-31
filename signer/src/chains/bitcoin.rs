//! Bitcoin chain signer (BIP-84 native segwit / bech32).

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

/// Bitcoin chain signer.
#[derive(Debug, Clone)]
pub struct BitcoinSigner {
    hrp: String,
}

impl BitcoinSigner {
    /// Create a signer with a custom human-readable part.
    #[must_use]
    pub fn new(hrp: &str) -> Self {
        Self { hrp: hrp.into() }
    }

    /// Mainnet signer (`bc1…`).
    #[must_use]
    pub fn mainnet() -> Self { Self::new("bc") }

    /// Testnet signer (`tb1…`).
    #[must_use]
    pub fn testnet() -> Self { Self::new("tb") }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidKey(e.to_string()))
    }

    fn hash160(data: &[u8]) -> Vec<u8> {
        Ripemd160::digest(Sha256::digest(data)).to_vec()
    }
}

fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

impl ChainSigner for BitcoinSigner {
    fn chain(&self) -> Chain { Chain::Bitcoin }
    fn curve(&self) -> Curve { Curve::Secp256k1 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(true);
        let hash = Self::hash160(pk.as_bytes());

        let hrp = bech32::Hrp::parse(&self.hrp)
            .map_err(|e| SignerError::AddressFailed(e.to_string()))?;
        bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &hash)
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
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let mut data = Vec::new();
        data.extend_from_slice(prefix);
        encode_compact_size(&mut data, message.len());
        data.extend_from_slice(message);
        let hash = Sha256::digest(Sha256::digest(&data));
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
        format!("m/84'/0'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_address_generator_point() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = BitcoinSigner::mainnet().derive_address(&pk).unwrap();
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn testnet_prefix() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = BitcoinSigner::testnet().derive_address(&pk).unwrap();
        assert!(addr.starts_with("tb1"));
    }

    #[test]
    fn derivation_path() {
        let s = BitcoinSigner::mainnet();
        assert_eq!(s.default_derivation_path(0), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn chain_properties() {
        let s = BitcoinSigner::mainnet();
        assert_eq!(s.chain(), Chain::Bitcoin);
        assert_eq!(s.curve(), Curve::Secp256k1);
    }
}
