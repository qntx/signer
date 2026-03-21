//! Bitcoin transaction signer built on the [`bitcoin`] crate.
//!
//! [`Signer`] wraps a [`PrivateKey`] and uses the global [`secp256k1`] context
//! for all cryptographic operations — ECDSA, Schnorr, PSBT, and BIP-137
//! message signing.
//!
//! **Zero hand-rolled cryptography.**
//!
//! # Signing methods
//!
//! | Method | Description |
//! |---|---|
//! | [`Signer::sign_ecdsa`] | secp256k1 ECDSA signature |
//! | [`Signer::sign_schnorr`] | BIP-340 Schnorr signature (Taproot) |
//! | [`Signer::sign_message`] | BIP-137 Bitcoin Signed Message |
//! | [`Signer::verify_message`] | Verify a BIP-137 message |
//! | [`Signer::sign_psbt`] | Sign all applicable PSBT inputs |
//!
//! # `Deref`
//!
//! `Signer` implements `Deref<Target = PrivateKey>`, giving direct access
//! to all [`PrivateKey`] methods (e.g. `to_wif()`, `public_key()`).

mod error;

use core::ops::Deref;
use std::sync::LazyLock;

pub use bitcoin;
use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::hashes::{Hash, HashEngine, sha256d};
pub use bitcoin::psbt::Psbt;
pub use bitcoin::secp256k1;
use bitcoin::secp256k1::{All, Message, Secp256k1, Signing};
pub use bitcoin::{
    Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey, Transaction,
};
pub use error::Error;

static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// BIP-137 address type for message signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// P2PKH (Legacy).
    P2pkh,
    /// P2SH-P2WPKH (Nested Segwit).
    P2shP2wpkh,
    /// P2WPKH (Native Segwit).
    P2wpkh,
}

/// Bitcoin transaction signer.
///
/// Wraps a [`PrivateKey`] and uses the global [`secp256k1`] context for all
/// operations. Implements [`Deref`] to [`PrivateKey`] for full upstream access.
///
/// Private key bytes are erased from memory on [`Drop`].
///
/// # Examples
///
/// ```
/// use signer_btc::{Signer, Network, Address};
///
/// let signer = Signer::random(Network::Bitcoin);
/// let sig = signer.sign_message("hello").unwrap();
/// let addr = signer.p2wpkh_address(Network::Bitcoin);
/// ```
#[derive(Debug, Clone)]
pub struct Signer {
    key: PrivateKey,
}

impl Deref for Signer {
    type Target = PrivateKey;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.key.inner.non_secure_erase();
    }
}

impl Signer {
    /// Create a signer from a WIF-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the WIF string is invalid.
    pub fn from_wif(wif: &str) -> Result<Self, Error> {
        let key: PrivateKey = wif.parse()?;
        Ok(Self { key })
    }

    /// Create a signer from a hex-encoded 32-byte private key.
    ///
    /// Accepts keys with or without `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the key is not a valid
    /// secp256k1 secret key.
    pub fn from_hex(hex_str: &str, network: Network) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidKey(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Self::from_bytes(&bytes, network)
    }

    /// Create a signer from raw 32-byte secret key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid secp256k1 secret key.
    pub fn from_bytes(bytes: &[u8; 32], network: Network) -> Result<Self, Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes)?;
        Ok(Self {
            key: PrivateKey::new(secret_key, network),
        })
    }

    /// Generate a random signer for the given network.
    #[must_use]
    pub fn random(network: Network) -> Self {
        let (secret_key, _) = SECP.generate_keypair(&mut secp256k1::rand::thread_rng());
        Self {
            key: PrivateKey::new(secret_key, network),
        }
    }

    /// Sign a 32-byte message digest with ECDSA (secp256k1).
    #[must_use]
    pub fn sign_ecdsa(&self, msg: &Message) -> secp256k1::ecdsa::Signature {
        SECP.sign_ecdsa(msg, &self.key.inner)
    }

    /// Sign a 32-byte message with BIP-340 Schnorr (Taproot).
    #[must_use]
    pub fn sign_schnorr(&self, msg: &Message) -> secp256k1::schnorr::Signature {
        let keypair = secp256k1::Keypair::from_secret_key(&*SECP, &self.key.inner);
        SECP.sign_schnorr(msg, &keypair)
    }

    /// Create a BIP-137 Bitcoin Signed Message (defaults to [`AddressType::P2wpkh`]).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_message(&self, msg: &str) -> Result<String, Error> {
        self.sign_message_with_type(msg, AddressType::P2wpkh)
    }

    /// Create a BIP-137 Bitcoin Signed Message with a specific address type.
    ///
    /// The flag byte encodes which address type was used:
    /// - 27–30: P2PKH uncompressed
    /// - 31–34: P2PKH compressed
    /// - 35–38: P2SH-P2WPKH
    /// - 39–42: P2WPKH (native segwit)
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn sign_message_with_type(
        &self,
        msg: &str,
        addr_type: AddressType,
    ) -> Result<String, Error> {
        let secp_msg = Message::from_digest(Self::signed_msg_hash(msg));
        let sig = SECP.sign_ecdsa_recoverable(&secp_msg, &self.key.inner);
        let (recovery_id, sig_bytes) = sig.serialize_compact();

        let flag_base: u8 = match addr_type {
            AddressType::P2pkh if self.key.compressed => 31,
            AddressType::P2pkh => 27,
            AddressType::P2shP2wpkh => 35,
            AddressType::P2wpkh => 39,
        };

        let mut buf = [0u8; 65];
        buf[0] = flag_base + recovery_id.to_i32() as u8;
        buf[1..].copy_from_slice(&sig_bytes);
        Ok(STANDARD.encode(buf))
    }

    /// Verify a BIP-137 Bitcoin Signed Message.
    ///
    /// Supports all standard flag byte ranges (P2PKH, P2SH-P2WPKH, P2WPKH).
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is malformed or recovery fails.
    pub fn verify_message(
        msg: &str,
        signature_base64: &str,
        expected_address: &Address,
        network: Network,
    ) -> Result<bool, Error> {
        let raw = STANDARD
            .decode(signature_base64)
            .map_err(|e| Error::Signature(format!("invalid base64: {e}")))?;

        if raw.len() != 65 {
            return Err(Error::Signature(format!(
                "expected 65 bytes, got {}",
                raw.len()
            )));
        }

        let flag = raw[0];
        let recovery_id_raw = match flag {
            27..=30 => flag - 27,
            31..=34 => flag - 31,
            35..=38 => flag - 35,
            39..=42 => flag - 39,
            _ => return Err(Error::Signature(format!("invalid flag byte: {flag}"))),
        };

        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(i32::from(recovery_id_raw))?;
        let recoverable =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&raw[1..], recovery_id)?;

        let secp_msg = Message::from_digest(Self::signed_msg_hash(msg));
        let recovered_pk = SECP.recover_ecdsa(&secp_msg, &recoverable)?;

        let recovered_addr = match flag {
            27..=30 => {
                let pk = PublicKey::new_uncompressed(recovered_pk);
                #[allow(deprecated)]
                Address::p2pkh(pk, network)
            }
            31..=34 => {
                let cpk = CompressedPublicKey(recovered_pk);
                #[allow(deprecated)]
                Address::p2pkh(PublicKey::from(cpk), network)
            }
            35..=38 => {
                let cpk = CompressedPublicKey(recovered_pk);
                Address::p2shwpkh(&cpk, network)
            }
            39..=42 => {
                let cpk = CompressedPublicKey(recovered_pk);
                Address::p2wpkh(&cpk, network)
            }
            _ => unreachable!(),
        };

        Ok(recovered_addr.script_pubkey() == expected_address.script_pubkey())
    }

    /// Sign all applicable inputs in a PSBT.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails for any input.
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<(), Error> {
        psbt.sign(&PsbtKey(self.key), &*SECP)
            .map(|_| ())
            .map_err(|(_, errors)| {
                let msg: Vec<String> = errors
                    .iter()
                    .map(|(idx, err)| format!("input {idx}: {err}"))
                    .collect();
                Error::Psbt(msg.join("; "))
            })
    }

    /// Get the compressed public key.
    ///
    /// # Panics
    ///
    /// Panics if the internal key is invalid (should never happen).
    #[must_use]
    pub fn compressed_public_key(&self) -> CompressedPublicKey {
        CompressedPublicKey::from_private_key(&*SECP, &self.key)
            .expect("valid private key always produces valid public key")
    }

    /// Get the full public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key(&*SECP)
    }

    /// Get the network kind.
    #[inline]
    #[must_use]
    pub const fn network_kind(&self) -> NetworkKind {
        self.key.network
    }

    /// P2WPKH address (Native Segwit).
    #[must_use]
    pub fn p2wpkh_address(&self, network: Network) -> Address {
        Address::p2wpkh(&self.compressed_public_key(), network)
    }

    /// P2TR address (Taproot).
    #[must_use]
    pub fn p2tr_address(&self, network: Network) -> Address {
        let keypair = secp256k1::Keypair::from_secret_key(&*SECP, &self.key.inner);
        let (xonly, _) = keypair.x_only_public_key();
        Address::p2tr(&*SECP, xonly, None, network)
    }

    /// P2PKH address (Legacy).
    #[must_use]
    pub fn p2pkh_address(&self, network: Network) -> Address {
        #[allow(deprecated)]
        Address::p2pkh(self.public_key(), network)
    }

    /// P2SH-P2WPKH address (Nested Segwit).
    #[must_use]
    pub fn p2sh_p2wpkh_address(&self, network: Network) -> Address {
        Address::p2shwpkh(&self.compressed_public_key(), network)
    }

    /// Compute the BIP-137 double-SHA256 message hash.
    fn signed_msg_hash(msg: &str) -> [u8; 32] {
        let mut engine = sha256d::Hash::engine();
        engine.input(b"\x18Bitcoin Signed Message:\n");
        let msg_bytes = msg.as_bytes();
        Self::write_compact_size(&mut engine, msg_bytes.len());
        engine.input(msg_bytes);
        sha256d::Hash::from_engine(engine).to_byte_array()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn write_compact_size<E: HashEngine>(engine: &mut E, size: usize) {
        if size < 253 {
            engine.input(&[size as u8]);
        } else if size <= 0xFFFF {
            engine.input(&[253]);
            engine.input(&(size as u16).to_le_bytes());
        } else if size <= 0xFFFF_FFFF {
            engine.input(&[254]);
            engine.input(&(size as u32).to_le_bytes());
        } else {
            engine.input(&[255]);
            engine.input(&(size as u64).to_le_bytes());
        }
    }
}

/// Internal [`GetKey`](bitcoin::psbt::GetKey) implementation for PSBT signing.
struct PsbtKey(PrivateKey);

impl bitcoin::psbt::GetKey for PsbtKey {
    type Error = bitcoin::psbt::GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: bitcoin::psbt::KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        let our_pk = self.0.public_key(secp);
        match key_request {
            bitcoin::psbt::KeyRequest::Pubkey(ref pk) if our_pk.inner == pk.inner => {
                Ok(Some(self.0))
            }
            bitcoin::psbt::KeyRequest::Bip32(_) => {
                // Single-key signer: always offer our key and let the
                // PSBT signer decide if it matches the derivation path.
                Ok(Some(self.0))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(feature = "kobe")]
impl Signer {
    /// Create a signer from a [`kobe_btc::DerivedAddress`].
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_derived(
        derived: &kobe_btc::DerivedAddress,
        network: Network,
    ) -> Result<Self, Error> {
        Self::from_wif(&derived.private_key_wif)
            .or_else(|_| Self::from_hex(&derived.private_key_hex, network))
    }

    /// Create a signer from a [`kobe_btc::StandardWallet`].
    ///
    /// # Errors
    ///
    /// Returns an error if the WIF key is invalid.
    pub fn from_standard_wallet(wallet: &kobe_btc::StandardWallet) -> Result<Self, Error> {
        Self::from_wif(&wallet.to_wif())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<Signer>();
    }

    #[test]
    fn assert_clone() {
        let s = Signer::random(Network::Bitcoin);
        let s2 = s.clone();
        assert_eq!(s.compressed_public_key(), s2.compressed_public_key());
    }

    #[test]
    fn random_signer() {
        let s = Signer::random(Network::Bitcoin);
        assert!(!s.compressed_public_key().to_string().is_empty());
    }

    #[test]
    fn wif_roundtrip() {
        let s = Signer::random(Network::Bitcoin);
        let wif = s.to_wif();
        let restored = Signer::from_wif(&wif).unwrap();
        assert_eq!(s.compressed_public_key(), restored.compressed_public_key());
    }

    #[test]
    fn hex_roundtrip() {
        let s = Signer::random(Network::Bitcoin);
        let hex_key = hex::encode(s.key.inner.secret_bytes());
        let restored = Signer::from_hex(&hex_key, Network::Bitcoin).unwrap();
        assert_eq!(s.compressed_public_key(), restored.compressed_public_key());
    }

    #[test]
    fn ecdsa_sign_verify() {
        let s = Signer::random(Network::Bitcoin);
        let msg = Message::from_digest([1u8; 32]);
        let sig = s.sign_ecdsa(&msg);
        SECP.verify_ecdsa(&msg, &sig, &s.public_key().inner)
            .unwrap();
    }

    #[test]
    fn schnorr_sign_verify() {
        let s = Signer::random(Network::Bitcoin);
        let msg = Message::from_digest([2u8; 32]);
        let sig = s.sign_schnorr(&msg);
        let keypair = secp256k1::Keypair::from_secret_key(&*SECP, &s.key.inner);
        let (xonly, _) = keypair.x_only_public_key();
        SECP.verify_schnorr(&sig, &msg, &xonly).unwrap();
    }

    #[test]
    fn bip137_p2wpkh() {
        let s = Signer::random(Network::Bitcoin);
        let sig = s.sign_message("Hello, Bitcoin!").unwrap();
        let addr = s.p2wpkh_address(Network::Bitcoin);
        assert!(Signer::verify_message("Hello, Bitcoin!", &sig, &addr, Network::Bitcoin).unwrap());
    }

    #[test]
    fn bip137_p2pkh() {
        let s = Signer::random(Network::Bitcoin);
        let sig = s
            .sign_message_with_type("test", AddressType::P2pkh)
            .unwrap();
        let addr = s.p2pkh_address(Network::Bitcoin);
        assert!(Signer::verify_message("test", &sig, &addr, Network::Bitcoin).unwrap());
    }

    #[test]
    fn bip137_p2sh_p2wpkh() {
        let s = Signer::random(Network::Bitcoin);
        let sig = s
            .sign_message_with_type("test", AddressType::P2shP2wpkh)
            .unwrap();
        let addr = s.p2sh_p2wpkh_address(Network::Bitcoin);
        assert!(Signer::verify_message("test", &sig, &addr, Network::Bitcoin).unwrap());
    }

    #[test]
    fn bip137_wrong_message_fails() {
        let s = Signer::random(Network::Bitcoin);
        let sig = s.sign_message("correct").unwrap();
        let addr = s.p2wpkh_address(Network::Bitcoin);
        assert!(!Signer::verify_message("wrong", &sig, &addr, Network::Bitcoin).unwrap());
    }

    #[test]
    fn address_generation() {
        let s = Signer::random(Network::Bitcoin);
        assert!(!s.p2wpkh_address(Network::Bitcoin).to_string().is_empty());
        assert!(!s.p2tr_address(Network::Bitcoin).to_string().is_empty());
        assert!(!s.p2pkh_address(Network::Bitcoin).to_string().is_empty());
        assert!(
            !s.p2sh_p2wpkh_address(Network::Bitcoin)
                .to_string()
                .is_empty()
        );
    }

    #[test]
    fn network_kind() {
        let s = Signer::random(Network::Testnet);
        assert_eq!(s.network_kind(), NetworkKind::Test);
    }

    #[test]
    fn deref_to_private_key() {
        let s = Signer::random(Network::Bitcoin);
        let _wif: String = s.to_wif();
    }
}
