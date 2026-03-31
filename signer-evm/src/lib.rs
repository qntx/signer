//! EVM transaction signer built on [`k256`] and [`sha3`].
//!
//! Provides EIP-191 personal signing, EIP-712 typed data signing,
//! and typed transaction signing with RLP encoding.
//!
//! **No alloy dependency.** Pure cryptographic primitives only.
//!
//! # Examples
//!
//! ```
//! use signer_evm::Signer;
//!
//! let signer = Signer::random();
//! let sig = signer.sign_message(b"hello").unwrap();
//! assert_eq!(sig.len(), 65); // r(32) + s(32) + v(1)
//! ```

mod eip712;
mod error;
mod rlp;

pub use error::Error;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use zeroize::ZeroizeOnDrop;

/// EVM transaction signer.
///
/// Wraps a secp256k1 signing key. The inner key is zeroized on drop.
#[derive(Debug, Clone)]
pub struct Signer {
    key: SigningKey,
}

impl Signer {
    /// Create a signer from a raw 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Create a signer from a hex-encoded private key (with or without `0x`).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or the key is out of range.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)
            .map_err(|e| Error::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|v: Vec<u8>| {
                Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
            })?;
        Self::from_bytes(&bytes)
    }

    /// Generate a random signer.
    #[must_use]
    pub fn random() -> Self {
        Self {
            key: SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng),
        }
    }

    /// Ethereum address derived from this signing key (EIP-55 checksummed).
    #[must_use]
    pub fn address(&self) -> String {
        let vk = self.key.verifying_key();
        let pk = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&pk.as_bytes()[1..]);
        eip55_checksum(&hex::encode(&hash[12..]))
    }

    /// Sign a 32-byte hash. Returns 65 bytes: `r(32) || s(32) || v(1)`.
    ///
    /// `v` is the raw recovery ID (0 or 1).
    ///
    /// # Errors
    ///
    /// Returns an error if `hash` is not exactly 32 bytes.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<Vec<u8>, Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidMessage(format!(
                "expected 32-byte hash, got {}",
                hash.len()
            )));
        }
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(hash)
            .map_err(|e| Error::SigningFailed(e.to_string()))?;

        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.r().to_bytes());
        out.extend_from_slice(&sig.s().to_bytes());
        out.push(rid.to_byte());
        Ok(out)
    }

    /// EIP-191 `personal_sign`. Returns 65 bytes with `v = 27 | 28`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let hash = Keccak256::digest(&data);

        let mut sig = self.sign_hash(&hash)?;
        sig[64] += 27; // v = 27 + recovery_id
        Ok(sig)
    }

    /// Sign EIP-712 typed structured data (JSON input).
    /// Returns 65 bytes with `v = 27 | 28`.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or signing fails.
    pub fn sign_typed_data(&self, typed_data_json: &str) -> Result<Vec<u8>, Error> {
        let hash = eip712::hash_typed_data_json(typed_data_json)?;
        let mut sig = self.sign_hash(&hash)?;
        sig[64] += 27;
        Ok(sig)
    }

    /// Sign an unsigned typed transaction (EIP-1559 / EIP-2930).
    /// Returns 65 bytes: `r(32) || s(32) || v(1)` where `v` is raw recovery ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction bytes are malformed.
    pub fn sign_transaction(&self, unsigned_tx: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = Keccak256::digest(unsigned_tx);
        self.sign_hash(&hash)
    }

    /// Encode a signed typed transaction: `type || RLP([…fields, v, r, s])`.
    ///
    /// # Errors
    ///
    /// Returns an error if the unsigned tx or signature is malformed.
    pub fn encode_signed_transaction(
        unsigned_tx: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if signature.len() != 65 {
            return Err(Error::InvalidSignature("expected 65-byte signature".into()));
        }
        let v = signature[64];
        let r: [u8; 32] = signature[..32].try_into().expect("checked length");
        let s: [u8; 32] = signature[32..64].try_into().expect("checked length");
        rlp::encode_signed_typed_tx(unsigned_tx, v, &r, &s)
            .map_err(|e| Error::InvalidTransaction(e.into()))
    }

    /// Expose the inner [`SigningKey`] reference.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

/// Wrapper to ensure zeroization of the signing key on drop.
impl ZeroizeOnDrop for Signer {}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_evm::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_evm::DerivedAccount) -> Result<Self, Error> {
        Self::from_hex(&account.private_key)
    }
}

fn eip55_checksum(addr_hex: &str) -> String {
    let lower = addr_hex.to_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());
    let hash_hex = hex::encode(hash);

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = u8::from_str_radix(&hash_hex[i..=i], 16).unwrap_or(0);
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    use super::*;

    #[test]
    fn from_hex_and_address() {
        let s =
            Signer::from_hex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        assert_eq!(s.address(), "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
    }

    #[test]
    fn from_hex_with_0x_prefix() {
        let s =
            Signer::from_hex("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        assert_eq!(s.address(), "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
    }

    #[test]
    fn random_signer() {
        let s = Signer::random();
        let addr = s.address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn sign_hash_and_verify() {
        let s =
            Signer::from_hex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let hash = Keccak256::digest(b"test");
        let sig_bytes = s.sign_hash(&hash).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        let r: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let s_arr: [u8; 32] = sig_bytes[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s_arr).unwrap();
        s.signing_key()
            .verifying_key()
            .verify_prehash(&hash, &sig)
            .unwrap();
    }

    #[test]
    fn sign_message_v_byte() {
        let s = Signer::random();
        let sig = s.sign_message(b"Hello").unwrap();
        let v = sig[64];
        assert!(v == 27 || v == 28);
    }

    #[test]
    fn clone_preserves_address() {
        let s = Signer::random();
        let s2 = s.clone();
        assert_eq!(s.address(), s2.address());
    }

    #[test]
    fn rejects_wrong_hash_length() {
        let s = Signer::random();
        assert!(s.sign_hash(b"short").is_err());
    }
}
