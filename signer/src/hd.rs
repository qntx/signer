//! Hierarchical deterministic key derivation.
//!
//! - **Secp256k1**: BIP-32 (HMAC-SHA512 chain, hand-written — no `coins-bip32`).
//! - **Ed25519**: SLIP-10 (hardened-only HMAC-SHA512 chain).

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::curve::Curve;
use crate::error::HdError;
use crate::mnemonic::Mnemonic;
use crate::secret::SecretBytes;

type HmacSha512 = Hmac<Sha512>;

const HARDENED_BIT: u32 = 0x8000_0000;

/// HD key deriver (stateless — all methods are associated functions).
#[derive(Debug, Clone, Copy)]
pub struct HdDeriver;

impl HdDeriver {
    /// Derive a child private key from a seed and derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`HdError`] on invalid path or derivation failure.
    pub fn derive(seed: &[u8], path: &str, curve: Curve) -> Result<SecretBytes, HdError> {
        Self::validate_path(path)?;
        match curve {
            Curve::Secp256k1 => Self::derive_secp256k1(seed, path),
            Curve::Ed25519 => Self::derive_ed25519(seed, path),
        }
    }

    /// Convenience: derive from mnemonic + passphrase + path + curve.
    ///
    /// # Errors
    ///
    /// Returns [`HdError`] on invalid path or derivation failure.
    pub fn derive_from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        let seed = mnemonic.to_seed(passphrase);
        Self::derive(seed.expose(), path, curve)
    }

    /// Validate a BIP-32 derivation path. Must start with `"m/"` or be `"m"`.
    ///
    /// # Errors
    ///
    /// Returns [`HdError::InvalidPath`] if the path syntax is wrong.
    pub fn validate_path(path: &str) -> Result<(), HdError> {
        if path == "m" {
            return Ok(());
        }
        if !path.starts_with("m/") {
            return Err(HdError::InvalidPath(format!(
                "path must start with 'm/', got '{path}'"
            )));
        }
        for component in path[2..].split('/') {
            let idx_str = component.trim_end_matches('\'');
            if idx_str.is_empty() {
                return Err(HdError::InvalidPath(format!(
                    "empty component in path '{path}'"
                )));
            }
            idx_str.parse::<u32>().map_err(|_| {
                HdError::InvalidPath(format!("invalid index '{component}' in path '{path}'"))
            })?;
        }
        Ok(())
    }

    /// Parse path components into `(index, hardened)` pairs.
    fn parse_components(path: &str) -> Result<Vec<u32>, HdError> {
        if path == "m" {
            return Ok(Vec::new());
        }
        path[2..]
            .split('/')
            .map(|c| {
                let hardened = c.ends_with('\'');
                let idx_str = c.trim_end_matches('\'');
                let idx: u32 = idx_str.parse().map_err(|_| {
                    HdError::InvalidPath(format!("invalid index: {c}"))
                })?;
                if hardened {
                    Ok(idx | HARDENED_BIT)
                } else {
                    Ok(idx)
                }
            })
            .collect()
    }

    /// BIP-32 derivation for secp256k1 (hand-written, no external crate).
    fn derive_secp256k1(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::SecretKey;

        let components = Self::parse_components(path)?;

        // Master key: HMAC-SHA512("Bitcoin seed", seed)
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .expect("HMAC accepts any key size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key_bytes = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key_bytes.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        let mut data = vec![0u8; 37]; // max: 1 + 32 + 4

        for child_index in components {
            let is_hardened = child_index & HARDENED_BIT != 0;

            if is_hardened {
                // data = 0x00 || key || index
                data[0] = 0x00;
                data[1..33].copy_from_slice(&key_bytes);
            } else {
                // data = compressed_pubkey || index
                let sk = SecretKey::from_slice(&key_bytes)
                    .map_err(|e| HdError::DerivationFailed(e.to_string()))?;
                let pk = sk.public_key().to_encoded_point(true);
                let pk_bytes = pk.as_bytes();
                data[..33].copy_from_slice(pk_bytes);
            }
            data[33..37].copy_from_slice(&child_index.to_be_bytes());

            let mut mac = HmacSha512::new_from_slice(&chain_code)
                .expect("HMAC accepts any key size");
            mac.update(&data[..37]);
            let result = mac.finalize().into_bytes();

            // child_key = parse256(IL) + parent_key (mod n)
            let il = &result[..32];
            let parent = k256::NonZeroScalar::try_from(&key_bytes[..])
                .map_err(|e| HdError::DerivationFailed(format!("invalid parent key: {e}")))?;
            let tweak = k256::NonZeroScalar::try_from(il)
                .map_err(|_| HdError::DerivationFailed("derived key is zero".into()))?;

            let child_scalar = parent.as_ref() + tweak.as_ref();
            let child_key = Option::<k256::NonZeroScalar>::from(
                k256::NonZeroScalar::new(child_scalar),
            )
            .ok_or_else(|| HdError::DerivationFailed("child key is zero".into()))?;

            key_bytes.copy_from_slice(&child_key.to_bytes());
            chain_code.copy_from_slice(&result[32..]);
        }

        data.zeroize();
        chain_code.zeroize();
        let secret = SecretBytes::new(key_bytes.to_vec());
        key_bytes.zeroize();
        Ok(secret)
    }

    /// SLIP-10 derivation for Ed25519 (hardened-only).
    fn derive_ed25519(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        let components_raw = Self::parse_components(path)?;

        // Validate all hardened
        for &idx in &components_raw {
            if idx & HARDENED_BIT == 0 {
                return Err(HdError::Ed25519NonHardened);
            }
        }

        // Master key: HMAC-SHA512("ed25519 seed", seed)
        let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
            .expect("HMAC accepts any key size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = result[..32].to_vec();
        let mut chain_code = result[32..].to_vec();
        let mut data = Vec::new();

        for index in components_raw {
            data.zeroize();
            data.clear();
            data.push(0u8);
            data.extend_from_slice(&key);
            data.extend_from_slice(&index.to_be_bytes());

            let mut mac = HmacSha512::new_from_slice(&chain_code)
                .expect("HMAC accepts any key size");
            mac.update(&data);
            let result = mac.finalize().into_bytes();

            key.zeroize();
            chain_code.zeroize();
            key = result[..32].to_vec();
            chain_code = result[32..].to_vec();
        }

        data.zeroize();
        chain_code.zeroize();
        Ok(SecretBytes::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_seed() -> SecretBytes {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        m.to_seed("")
    }

    #[test]
    fn derive_evm_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_solana_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/501'/0'/0'", Curve::Ed25519).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_bitcoin_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/84'/0'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn convenience_matches_two_step() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = m.to_seed("");
        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 = HdDeriver::derive_from_mnemonic(&m, "", "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn path_validation_valid() {
        assert!(HdDeriver::validate_path("m/44'/60'/0'/0/0").is_ok());
        assert!(HdDeriver::validate_path("m/44'/501'/0'/0'").is_ok());
        assert!(HdDeriver::validate_path("m").is_ok());
    }

    #[test]
    fn path_validation_invalid() {
        assert!(HdDeriver::validate_path("44'/60'/0'/0/0").is_err());
        assert!(HdDeriver::validate_path("").is_err());
        assert!(HdDeriver::validate_path("x/44'/60'").is_err());
    }

    #[test]
    fn slip10_rejects_non_hardened() {
        let seed = test_seed();
        let result = HdDeriver::derive(seed.expose(), "m/44'/501'/0'/0", Curve::Ed25519);
        assert!(matches!(result, Err(HdError::Ed25519NonHardened)));
    }

    #[test]
    fn deterministic() {
        let seed = test_seed();
        let k1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let k2 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(k1.expose(), k2.expose());
    }

    #[test]
    fn different_indices_different_keys() {
        let seed = test_seed();
        let k0 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let k1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/1", Curve::Secp256k1).unwrap();
        assert_ne!(k0.expose(), k1.expose());
    }

    #[test]
    fn known_evm_address_from_abandon_mnemonic() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = HdDeriver::derive_from_mnemonic(&m, "", "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();

        // Derive address to verify against known test vector
        use k256::ecdsa::SigningKey;
        use sha3::{Digest, Keccak256};

        let sk = SigningKey::from_slice(key.expose()).unwrap();
        let vk = sk.verifying_key();
        let pk = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&pk.as_bytes()[1..]);
        let addr = format!("0x{}", hex::encode(&hash[12..]));

        // Known test vector for "abandon..." mnemonic
        assert_eq!(
            addr.to_lowercase(),
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        );
    }
}
