//! Bitcoin transaction signer built on the [`bitcoin`] crate.
//!
//! This crate provides a [`Signer`] that wraps [`bitcoin::PrivateKey`] and a
//! [`bitcoin::secp256k1::Secp256k1`] context, exposing ECDSA, Schnorr, PSBT,
//! and Bitcoin message signing — all delegated to upstream libraries.
//!
//! **Zero hand-rolled cryptography.**
//!
//! # Exposed signing methods
//!
//! | Method | Description |
//! |---|---|
//! | [`Signer::sign_ecdsa`] | Raw ECDSA signature on a message digest |
//! | [`Signer::sign_schnorr`] | BIP-340 Schnorr signature (Taproot) |
//! | [`Signer::sign_message`] | Bitcoin Signed Message (BIP-137) |
//! | [`Signer::verify_message`] | Verify a Bitcoin Signed Message |
//! | [`Signer::sign_psbt`] | Sign all applicable PSBT inputs |

mod error;

pub use bitcoin;
use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::hashes::{Hash, HashEngine, sha256d};
pub use bitcoin::psbt::Psbt;
pub use bitcoin::secp256k1;
use bitcoin::secp256k1::{All, Message, Secp256k1, Signing};
pub use bitcoin::{
    Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey, Transaction,
};
pub use error::Error;

/// Bitcoin transaction signer.
///
/// Wraps a [`PrivateKey`] and a [`Secp256k1`] context. All cryptographic
/// operations are delegated to the `bitcoin` and `secp256k1` crates.
#[derive(Debug)]
pub struct Signer {
    private_key: PrivateKey,
    secp: Secp256k1<All>,
}

impl Signer {
    /// Create a signer from a WIF-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the WIF string is invalid.
    pub fn from_wif(wif: &str) -> Result<Self, Error> {
        let private_key: PrivateKey = wif.parse()?;
        Ok(Self {
            private_key,
            secp: Secp256k1::new(),
        })
    }

    /// Create a signer from a hex-encoded 32-byte private key.
    ///
    /// Accepts keys with or without `0x` prefix.
    /// Compatible with [`kobe_btc::DerivedAddress::private_key_hex`] output.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the key is not a valid
    /// secp256k1 secret key.
    pub fn from_hex(hex_str: &str, network: Network) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes: [u8; 32] = hex::decode(hex_str)?.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidPrivateKey(format!("expected 32 bytes, got {}", v.len()))
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
        let private_key = PrivateKey::new(secret_key, network);
        Ok(Self {
            private_key,
            secp: Secp256k1::new(),
        })
    }

    /// Generate a random signer for the given network.
    #[must_use]
    pub fn random(network: Network) -> Self {
        let (secret_key, _) = Secp256k1::new().generate_keypair(&mut secp256k1::rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, network);
        Self {
            private_key,
            secp: Secp256k1::new(),
        }
    }

    /// Sign a 32-byte message digest with ECDSA (secp256k1).
    #[must_use]
    pub fn sign_ecdsa(&self, msg: &Message) -> secp256k1::ecdsa::Signature {
        self.secp.sign_ecdsa(msg, &self.private_key.inner)
    }

    /// Sign a 32-byte message with BIP-340 Schnorr (used by Taproot / P2TR).
    ///
    /// # Panics
    ///
    /// Panics if the internal keypair construction fails, which should never
    /// happen for a valid private key.
    #[must_use]
    pub fn sign_schnorr(&self, msg: &Message) -> secp256k1::schnorr::Signature {
        let keypair = secp256k1::Keypair::from_secret_key(&self.secp, &self.private_key.inner);
        self.secp.sign_schnorr(msg, &keypair)
    }

    /// Create a Bitcoin Signed Message (BIP-137 compatible).
    ///
    /// The message is prefixed with `"\x18Bitcoin Signed Message:\n"` and
    /// double-SHA256 hashed before signing, as per the Bitcoin protocol.
    ///
    /// # Errors
    ///
    /// Returns an error if the message signing fails.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn sign_message(&self, msg: &str) -> Result<String, Error> {
        let msg_hash = Self::signed_msg_hash(msg);
        let secp_msg = Message::from_digest(msg_hash);
        let sig = self
            .secp
            .sign_ecdsa_recoverable(&secp_msg, &self.private_key.inner);
        let (recovery_id, sig_bytes) = sig.serialize_compact();

        let mut serialized = [0u8; 65];
        serialized[0] =
            27 + recovery_id.to_i32() as u8 + if self.private_key.compressed { 4 } else { 0 };
        serialized[1..].copy_from_slice(&sig_bytes);

        Ok(STANDARD.encode(serialized))
    }

    /// Verify a Bitcoin Signed Message.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is malformed or verification fails.
    pub fn verify_message(
        msg: &str,
        signature_base64: &str,
        expected_address: &Address,
        network: Network,
    ) -> Result<bool, Error> {
        let sig_bytes = STANDARD
            .decode(signature_base64)
            .map_err(|e| Error::InvalidPrivateKey(format!("invalid base64: {e}")))?;

        if sig_bytes.len() != 65 {
            return Err(Error::InvalidPrivateKey(format!(
                "signature must be 65 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let flag = sig_bytes[0];
        let compressed = flag >= 31;
        let recovery_id_raw = if compressed { flag - 31 } else { flag - 27 };

        let secp = Secp256k1::new();
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(i32::from(recovery_id_raw))
            .map_err(|e| Error::InvalidPrivateKey(format!("invalid recovery id: {e}")))?;
        let recoverable_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[1..], recovery_id)?;

        let msg_hash = Self::signed_msg_hash(msg);

        let secp_msg = Message::from_digest(msg_hash);
        let recovered_pubkey = secp.recover_ecdsa(&secp_msg, &recoverable_sig)?;

        let recovered_addr = if compressed {
            let compressed_pk = CompressedPublicKey(recovered_pubkey);
            Address::p2wpkh(&compressed_pk, network)
        } else {
            let pk = PublicKey::new_uncompressed(recovered_pubkey);
            #[allow(deprecated)]
            Address::p2pkh(pk, network)
        };

        Ok(recovered_addr.to_string() == expected_address.to_string())
    }

    /// Sign all applicable inputs in a PSBT.
    ///
    /// Returns the number of inputs that were signed.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails for any input.
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<(), Error> {
        let signer = SignPsbtKey {
            private_key: self.private_key,
        };
        psbt.sign(&signer, &self.secp)
            .map(|_| ())
            .map_err(|(_, errors)| {
                let err_msgs: Vec<String> = errors
                    .iter()
                    .map(|(idx, err)| format!("input {idx}: {err}"))
                    .collect();
                Error::PsbtSign(err_msgs.join("; "))
            })
    }

    /// Get the underlying [`PrivateKey`].
    #[inline]
    #[must_use]
    pub const fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Get the compressed public key.
    ///
    /// # Panics
    ///
    /// Panics if the internal key is invalid, which should never happen.
    #[must_use]
    pub fn compressed_public_key(&self) -> CompressedPublicKey {
        CompressedPublicKey::from_private_key(&self.secp, &self.private_key)
            .expect("valid private key always produces valid public key")
    }

    /// Get the public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key(&self.secp)
    }

    /// Get the network this signer is configured for.
    #[inline]
    #[must_use]
    pub const fn network_kind(&self) -> NetworkKind {
        self.private_key.network
    }

    /// Get a reference to the secp256k1 context.
    #[inline]
    #[must_use]
    pub const fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    /// Compute the Bitcoin Signed Message hash for the given message.
    fn signed_msg_hash(msg: &str) -> [u8; 32] {
        let mut engine = sha256d::Hash::engine();
        let prefix = b"\x18Bitcoin Signed Message:\n";
        engine.input(prefix);
        let msg_bytes = msg.as_bytes();
        Self::write_compact_size(&mut engine, msg_bytes.len());
        engine.input(msg_bytes);
        sha256d::Hash::from_engine(engine).to_byte_array()
    }

    /// Write a Bitcoin compact-size integer to a hash engine.
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

/// Internal helper that implements `GetKey` for PSBT signing.
struct SignPsbtKey {
    private_key: PrivateKey,
}

impl bitcoin::psbt::GetKey for SignPsbtKey {
    type Error = bitcoin::psbt::GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: bitcoin::psbt::KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            bitcoin::psbt::KeyRequest::Pubkey(ref pk) => {
                let our_pubkey = self.private_key.public_key(secp);
                if our_pubkey.inner == pk.inner {
                    Ok(Some(self.private_key))
                } else {
                    Ok(None)
                }
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
    /// Returns an error if the WIF private key is invalid.
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
    /// Returns an error if the WIF private key is invalid.
    pub fn from_standard_wallet(wallet: &kobe_btc::StandardWallet) -> Result<Self, Error> {
        Self::from_wif(&wallet.to_wif())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_signer() {
        let signer = Signer::random(Network::Bitcoin);
        let pk = signer.compressed_public_key();
        assert!(!pk.to_string().is_empty());
    }

    #[test]
    fn test_from_wif_roundtrip() {
        let signer = Signer::random(Network::Bitcoin);
        let wif = signer.private_key().to_wif();
        let restored = Signer::from_wif(&wif).unwrap();
        assert_eq!(
            signer.compressed_public_key(),
            restored.compressed_public_key()
        );
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let signer = Signer::random(Network::Bitcoin);
        let hex_key = hex::encode(signer.private_key().inner.secret_bytes());
        let restored = Signer::from_hex(&hex_key, Network::Bitcoin).unwrap();
        assert_eq!(
            signer.compressed_public_key(),
            restored.compressed_public_key()
        );
    }

    #[test]
    fn test_sign_ecdsa() {
        let signer = Signer::random(Network::Bitcoin);
        let msg = Message::from_digest([1u8; 32]);
        let sig = signer.sign_ecdsa(&msg);
        let pk = signer.public_key();
        signer.secp().verify_ecdsa(&msg, &sig, &pk.inner).unwrap();
    }

    #[test]
    fn test_sign_schnorr() {
        let signer = Signer::random(Network::Bitcoin);
        let msg = Message::from_digest([2u8; 32]);
        let sig = signer.sign_schnorr(&msg);
        let keypair =
            secp256k1::Keypair::from_secret_key(signer.secp(), &signer.private_key().inner);
        let (xonly, _) = keypair.x_only_public_key();
        signer.secp().verify_schnorr(&sig, &msg, &xonly).unwrap();
    }

    #[test]
    fn test_sign_and_verify_message() {
        let signer = Signer::random(Network::Bitcoin);
        let msg = "Hello, Bitcoin!";
        let sig_b64 = signer.sign_message(msg).unwrap();

        let cpk = signer.compressed_public_key();
        let address = Address::p2wpkh(&cpk, Network::Bitcoin);

        let valid = Signer::verify_message(msg, &sig_b64, &address, Network::Bitcoin).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_network_kind() {
        let signer = Signer::random(Network::Testnet);
        assert_eq!(signer.network_kind(), NetworkKind::Test);
    }
}
