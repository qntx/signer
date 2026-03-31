//! Sui transaction signer using Ed25519 with Blake2b intent-based signing.
//!
//! Sui uses BLAKE2b-256 for address derivation and intent-prefixed transaction
//! signing. The signature wire format is `flag(0x00) || sig(64) || pubkey(32)`.

mod error;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};

pub use ed25519_dalek;
pub use error::Error;

/// Ed25519 signature scheme flag used by Sui.
pub const ED25519_FLAG: u8 = 0x00;

/// Sui transaction intent prefix: `[scope=0, version=0, app_id=0]`.
const TX_INTENT_PREFIX: [u8; 3] = [0x00, 0x00, 0x00];

/// Sui personal message intent prefix: `[scope=3, version=0, app_id=0]`.
const PERSONAL_MSG_INTENT_PREFIX: [u8; 3] = [0x03, 0x00, 0x00];

/// Size of the Sui wire signature: flag(1) + sig(64) + pubkey(32) = 97.
pub const WIRE_SIG_LEN: usize = 1 + 64 + 32;

/// Sui signer.
#[derive(Debug)]
pub struct Signer {
    /// The Ed25519 signing key.
    signing_key: SigningKey,
}

/// Signature output from a Sui signing operation.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Raw Ed25519 signature bytes (64 bytes).
    pub bytes: [u8; 64],
    /// Public key bytes (32 bytes), needed for wire format.
    pub public_key: [u8; 32],
}

impl Signer {
    /// Create a signer from raw 32-byte private key.
    pub fn from_bytes(private_key: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(private_key),
        }
    }

    /// Create a signer from a hex-encoded private key.
    pub fn from_hex(hex_key: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_key).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(&key))
    }

    /// Create a signer from a kobe-sui derived address.
    #[cfg(feature = "kobe")]
    pub fn from_derived(derived: &kobe_sui::DerivedAddress) -> Result<Self, Error> {
        let bytes =
            hex::decode(&*derived.private_key_hex).map_err(|e| Error::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(&key))
    }

    /// Get the Sui address: `0x` + hex(BLAKE2b-256(0x00 || pubkey)).
    #[must_use]
    pub fn address(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        let mut buf = Vec::with_capacity(33);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(verifying_key.as_bytes());
        let hash = blake2b_256(&buf);
        format!("0x{}", hex::encode(hash))
    }

    /// Get the public key bytes.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    /// Sign raw bytes (Ed25519 direct sign, no intent prefix).
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature {
            bytes: sig.to_bytes(),
            public_key: self.public_key(),
        }
    }

    /// Sign a personal message with Sui intent prefix (scope=3).
    ///
    /// The message is BCS-serialized (ULEB128 length prefix + raw bytes),
    /// then intent-prefixed and hashed with BLAKE2b-256 before signing.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let bcs_msg = bcs_serialize_bytes(message);
        let digest = intent_hash(&PERSONAL_MSG_INTENT_PREFIX, &bcs_msg);
        let sig = self.signing_key.sign(&digest);
        Signature {
            bytes: sig.to_bytes(),
            public_key: self.public_key(),
        }
    }

    /// Sign a transaction with Sui intent prefix (scope=0).
    ///
    /// `tx_bytes` should be BCS-encoded transaction data.
    pub fn sign_transaction(&self, tx_bytes: &[u8]) -> Signature {
        let digest = intent_hash(&TX_INTENT_PREFIX, tx_bytes);
        let sig = self.signing_key.sign(&digest);
        Signature {
            bytes: sig.to_bytes(),
            public_key: self.public_key(),
        }
    }

    /// Encode the signed transaction in Sui wire format.
    ///
    /// Returns `tx_bytes || flag(0x00) || sig(64) || pubkey(32)`.
    #[must_use]
    pub fn encode_signed_transaction(tx_bytes: &[u8], sig: &Signature) -> Vec<u8> {
        let mut result = Vec::with_capacity(tx_bytes.len() + WIRE_SIG_LEN);
        result.extend_from_slice(tx_bytes);
        result.push(ED25519_FLAG);
        result.extend_from_slice(&sig.bytes);
        result.extend_from_slice(&sig.public_key);
        result
    }
}

/// Compute BLAKE2b-256.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct length");
    out
}

/// Build the intent message and hash: BLAKE2b-256(intent_prefix || data).
fn intent_hash(intent_prefix: &[u8; 3], data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(3 + data.len());
    buf.extend_from_slice(intent_prefix);
    buf.extend_from_slice(data);
    blake2b_256(&buf)
}

/// Minimal BCS serialization of a byte vector: ULEB128 length prefix + raw bytes.
fn bcs_serialize_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + data.len());
    let mut len = data.len();
    loop {
        let byte = (len & 0x7F) as u8;
        len >>= 7;
        if len == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
    buf.extend_from_slice(data);
    buf
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    #[test]
    fn address_format() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let addr = signer.address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66); // 0x + 64 hex
    }

    #[test]
    fn deterministic_address() {
        let s1 = Signer::from_hex(TEST_KEY).unwrap();
        let s2 = Signer::from_hex(TEST_KEY).unwrap();
        assert_eq!(s1.address(), s2.address());
    }

    #[test]
    fn sign_raw_verify() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let message = b"test sui message";
        let sig = signer.sign_raw(message);
        assert_eq!(sig.bytes.len(), 64);

        let verifying_key = signer.signing_key.verifying_key();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.bytes);
        verifying_key.verify(message, &dalek_sig).unwrap();
    }

    #[test]
    fn sign_transaction_produces_valid_sig() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let bcs_tx = b"fake_bcs_tx";
        let sig = signer.sign_transaction(bcs_tx);
        assert_eq!(sig.bytes.len(), 64);
        assert_eq!(sig.public_key.len(), 32);

        // Verify against intent digest
        let digest = intent_hash(&TX_INTENT_PREFIX, bcs_tx);
        let verifying_key = signer.signing_key.verifying_key();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.bytes);
        verifying_key.verify(&digest, &dalek_sig).unwrap();
    }

    #[test]
    fn wire_format_correct() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let tx = b"test_tx";
        let sig = signer.sign_transaction(tx);
        let encoded = Signer::encode_signed_transaction(tx, &sig);

        assert_eq!(encoded.len(), tx.len() + WIRE_SIG_LEN);
        let (tx_part, sig_part) = encoded.split_at(encoded.len() - WIRE_SIG_LEN);
        assert_eq!(tx_part, tx);
        assert_eq!(sig_part[0], ED25519_FLAG);
        assert_eq!(&sig_part[1..65], &sig.bytes[..]);
        assert_eq!(&sig_part[65..], &sig.public_key[..]);
    }

    #[test]
    fn deterministic_signing() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let s1 = signer.sign_transaction(b"test");
        let s2 = signer.sign_transaction(b"test");
        assert_eq!(s1.bytes, s2.bytes);
    }

    #[test]
    fn invalid_key_rejected() {
        assert!(Signer::from_hex("bad").is_err());
    }

    #[test]
    fn bcs_serialize_small() {
        let data = b"hello";
        let bcs = bcs_serialize_bytes(data);
        assert_eq!(bcs[0], 5);
        assert_eq!(&bcs[1..], b"hello");
    }

    #[test]
    fn bcs_serialize_128() {
        let data = vec![0xAA; 128];
        let bcs = bcs_serialize_bytes(&data);
        assert_eq!(bcs[0], 0x80);
        assert_eq!(bcs[1], 0x01);
        assert_eq!(&bcs[2..], data.as_slice());
    }

    #[test]
    fn address_correctness() {
        let signer = Signer::from_hex(TEST_KEY).unwrap();
        let addr = signer.address();
        let pubkey = signer.public_key();
        let mut buf = vec![ED25519_FLAG];
        buf.extend_from_slice(&pubkey);
        let expected = blake2b_256(&buf);
        assert_eq!(addr, format!("0x{}", hex::encode(expected)));
    }
}
