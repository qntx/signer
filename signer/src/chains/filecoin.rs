//! Filecoin chain signer (secp256k1 + blake2b-160).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use blake2::digest::consts::U20;
use blake2::{Blake2b, Digest as _};
use k256::ecdsa::SigningKey;

use crate::chain::Chain;
use crate::curve::Curve;
use crate::error::SignerError;
use crate::traits::{ChainSigner, SignOutput};

type Blake2b160 = Blake2b<U20>;

/// Filecoin chain signer.
#[derive(Debug, Clone, Copy)]
pub struct FilecoinSigner;

impl FilecoinSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidKey(e.to_string()))
    }

    /// Compute a Filecoin `f1` (secp256k1) address.
    ///
    /// Format: `f1` + base32-lower(payload || checksum)
    /// where payload = blake2b-160(uncompressed_pubkey)
    /// and checksum = blake2b-4(protocol_byte || payload)
    fn f1_address(pubkey_uncompressed: &[u8]) -> Result<String, SignerError> {
        let protocol: u8 = 1; // secp256k1
        let payload = Blake2b160::digest(pubkey_uncompressed);

        // Checksum = blake2b-4(protocol || payload)
        use blake2::digest::consts::U4;
        type Blake2b32 = Blake2b<U4>;
        let mut check_input = Vec::with_capacity(1 + 20);
        check_input.push(protocol);
        check_input.extend_from_slice(&payload);
        let checksum = Blake2b32::digest(&check_input);

        // Encode payload || checksum as base32-lower (RFC 4648, no padding)
        let mut to_encode = Vec::with_capacity(24);
        to_encode.extend_from_slice(&payload);
        to_encode.extend_from_slice(&checksum);

        let encoded = base32_lower_encode(&to_encode);
        Ok(format!("f{protocol}{encoded}"))
    }
}

/// Base32 lower-case encoding (RFC 4648 alphabet, no padding).
fn base32_lower_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

impl ChainSigner for FilecoinSigner {
    fn chain(&self) -> Chain { Chain::Filecoin }
    fn curve(&self) -> Curve { Curve::Secp256k1 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(false);
        Self::f1_address(pk.as_bytes())
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
        use blake2::digest::consts::U32;
        type Blake2b256 = Blake2b<U32>;
        let hash = Blake2b256::digest(message);
        self.sign(private_key, &hash)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        use blake2::digest::consts::U32;
        type Blake2b256 = Blake2b<U32>;
        let hash = Blake2b256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/461'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_prefix() {
        let mut pk = alloc::vec![0u8; 31];
        pk.push(1);
        let addr = FilecoinSigner.derive_address(&pk).unwrap();
        assert!(addr.starts_with("f1"), "got: {addr}");
    }

    #[test]
    fn derivation_path() {
        assert_eq!(FilecoinSigner.default_derivation_path(0), "m/44'/461'/0'/0/0");
    }

    #[test]
    fn chain_properties() {
        assert_eq!(FilecoinSigner.chain(), Chain::Filecoin);
        assert_eq!(FilecoinSigner.curve(), Curve::Secp256k1);
    }
}
