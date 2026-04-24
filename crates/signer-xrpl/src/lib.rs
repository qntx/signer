//! XRP Ledger transaction signer built on `k256` and [`sha2`].
//!
//! Provides secp256k1 ECDSA signing for XRPL transactions using the
//! SHA-512-half hash algorithm and DER-encoded signatures.
//!
//! Address derivation is handled by `kobe-xrpl`.
//!
//! ## Signing algorithm
//!
//! XRPL single-signing uses a unique hash-then-sign scheme:
//!
//! 1. Prepend the `STX\0` prefix (`0x53545800`) to the serialized transaction
//! 2. Compute SHA-512 and take the first 32 bytes ("SHA-512-half")
//! 3. Sign the 32-byte digest with secp256k1 ECDSA
//! 4. Encode the signature in DER format (variable length, typically 70-72 bytes)
//!
//! ## Message signing
//!
//! XRPL has no canonical off-chain message signing standard (no EIP-191
//! equivalent), so this crate deliberately does **not** implement
//! [`SignMessage`](signer_primitives::SignMessage). Users who need a custom
//! scheme should hash their own preimage and call [`Sign::sign_hash`]
//! directly.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
pub use signer_primitives::{self, Sign, SignError, SignOutput};
use signer_primitives::{Secp256k1Signer, delegate_secp256k1_ctors};

/// XRPL single-signing hash prefix: `STX\0` (`0x53545800`).
const STX_PREFIX: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

/// XRP Ledger transaction signer.
///
/// Newtype over [`Secp256k1Signer`]. Produces DER-encoded ECDSA signatures
/// over SHA-512-half digests, matching the XRPL signing specification.
/// The inner key is zeroized on drop.
#[derive(Debug)]
pub struct Signer(Secp256k1Signer);

impl Signer {
    delegate_secp256k1_ctors!();

    /// Derive the XRPL classic `r`-address from the signing key.
    #[must_use]
    pub fn address(&self) -> String {
        let pubkey = self.0.compressed_public_key();
        encode_classic_address(&pubkey)
    }

    /// Compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.compressed_public_key()
    }

    /// Compressed public key as hex (66 chars, no `0x` prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.compressed_public_key())
    }

    /// Verify a DER-encoded ECDSA signature against a 32-byte pre-hashed
    /// digest.
    ///
    /// Matches the DER output of [`Sign::sign_hash`] and
    /// [`Signer::sign_transaction`]. Callers that produced a signature via
    /// this signer can round-trip it through `verify_hash_der` unchanged.
    ///
    /// This method is named `verify_hash_der` (rather than `verify_hash`) to
    /// distinguish it from the compact-signature `verify_hash` on other
    /// secp256k1 chains: XRPL's on-wire format is DER, so the expected
    /// signature input here is always DER-encoded.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] on malformed DER or failed
    /// verification.
    pub fn verify_hash_der(&self, hash: &[u8; 32], signature_der: &[u8]) -> Result<(), SignError> {
        self.0.verify_prehash_der(hash, signature_der)
    }

    /// Sign an unsigned XRPL transaction.
    ///
    /// `tx_bytes` must be the raw binary-encoded unsigned transaction fields
    /// (output of the XRPL binary codec, **without** the `STX\0` prefix).
    /// This method prepends `STX\0`, computes SHA-512-half, then signs with
    /// secp256k1 ECDSA DER.
    ///
    /// Returns a [`SignOutput::EcdsaDer`] (variable length, typically 70–72
    /// bytes).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidTransaction`] if `tx_bytes` is empty, or
    /// propagates signing failures from the underlying primitive.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<SignOutput, SignError> {
        if tx_bytes.is_empty() {
            return Err(SignError::InvalidTransaction(
                "transaction bytes must not be empty".into(),
            ));
        }
        let hash = sha512_half_prefixed(&STX_PREFIX, tx_bytes);
        self.0.sign_prehash_der(&hash)
    }
}

impl Sign for Signer {
    type Error = SignError;

    /// Sign a 32-byte pre-hashed digest with secp256k1.
    ///
    /// Returns a [`SignOutput::EcdsaDer`] (variable length, typically 70–72
    /// bytes). Recovery id is not included — XRPL does not use it.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<SignOutput, SignError> {
        self.0.sign_prehash_der(hash)
    }
}

// XRPL intentionally does **not** implement `SignMessage`: the ledger has no
// canonical off-chain message-signing standard (no EIP-191 equivalent), so a
// runtime `Err` would be a type-system lie. Users who need a custom scheme
// hash their own preimage and call `Sign::sign_hash`.

#[cfg(feature = "kobe")]
impl Signer {
    /// Create from a [`kobe_xrpl::DerivedAccount`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(account: &kobe_xrpl::DerivedAccount) -> Result<Self, SignError> {
        Self::from_bytes(account.private_key_bytes())
    }
}

/// XRPL base58 alphabet.
const XRPL_ALPHABET: bs58::Alphabet = *bs58::Alphabet::RIPPLE;

/// XRPL account address version byte.
const ACCOUNT_VERSION: u8 = 0x00;

/// Hash160: SHA-256 then RIPEMD-160.
fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

/// Double SHA-256 (used for checksum).
fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Encode a compressed public key as an XRPL classic `r`-address.
#[allow(
    clippy::indexing_slicing,
    reason = "double_sha256 returns [u8; 32], slicing first 4 is safe"
)]
fn encode_classic_address(compressed_pubkey: &[u8]) -> String {
    let account_id = hash160(compressed_pubkey);
    let mut payload = Vec::with_capacity(25);
    payload.push(ACCOUNT_VERSION);
    payload.extend_from_slice(&account_id);
    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(&payload)
        .with_alphabet(&XRPL_ALPHABET)
        .into_string()
}

/// SHA-512-half: SHA-512 of `prefix || data`, taking the first 32 bytes.
#[allow(
    clippy::indexing_slicing,
    reason = "SHA-512 output is always 64 bytes, slicing first 32 is safe"
)]
fn sha512_half_prefixed(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(data);
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

#[cfg(test)]
mod tests;
