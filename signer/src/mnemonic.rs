//! BIP-39 mnemonic phrase generation and seed derivation.
//!
//! Hand-written implementation — no `coins-bip39` dependency.
//! Uses PBKDF2-HMAC-SHA512 for seed derivation and the standard English wordlist.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::error::MnemonicError;
use crate::secret::SecretBytes;

/// Mnemonic word count / entropy strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicStrength {
    /// 12 words (128 bits of entropy).
    Words12,
    /// 24 words (256 bits of entropy).
    Words24,
}

/// A BIP-39 mnemonic phrase.
pub struct Mnemonic {
    phrase: String,
}

impl Mnemonic {
    /// Generate a new random mnemonic with the given strength.
    ///
    /// # Errors
    ///
    /// Returns [`MnemonicError::GenerationFailed`] if entropy generation fails.
    pub fn generate(strength: MnemonicStrength) -> Result<Self, MnemonicError> {
        let entropy_bytes = match strength {
            MnemonicStrength::Words12 => 16,
            MnemonicStrength::Words24 => 32,
        };
        let mut entropy = alloc::vec![0u8; entropy_bytes];
        #[cfg(feature = "std")]
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut entropy);
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std, caller must provide entropy externally.
            return Err(MnemonicError::GenerationFailed(
                "random generation requires std feature".into(),
            ));
        }
        let phrase = entropy_to_phrase(&entropy)?;
        entropy.zeroize();
        Ok(Self { phrase })
    }

    /// Create from an existing phrase, validating words and checksum.
    ///
    /// # Errors
    ///
    /// Returns [`MnemonicError::InvalidPhrase`] if validation fails.
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        validate_phrase(phrase)?;
        Ok(Self {
            phrase: phrase.to_string(),
        })
    }

    /// Get the phrase as [`SecretBytes`].
    #[must_use]
    pub fn phrase(&self) -> SecretBytes {
        SecretBytes::new(self.phrase.as_bytes().to_vec())
    }

    /// Derive a BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds).
    #[must_use]
    pub fn to_seed(&self, passphrase: &str) -> SecretBytes {
        let salt = format!("mnemonic{passphrase}");
        let mut seed = [0u8; 64];
        pbkdf2_hmac_sha512(self.phrase.as_bytes(), salt.as_bytes(), 2048, &mut seed);
        SecretBytes::new(seed.to_vec())
    }

    /// Number of words in this mnemonic.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }
}

impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// BIP-39 English wordlist (2048 words).
const WORDLIST: &str = include_str!("wordlist_en.txt");

fn wordlist() -> Vec<&'static str> {
    WORDLIST.lines().collect()
}

fn word_index(word: &str) -> Option<usize> {
    // Linear search is fine — 2048 words, called infrequently
    wordlist().iter().position(|&w| w == word)
}

fn entropy_to_phrase(entropy: &[u8]) -> Result<String, MnemonicError> {
    let checksum = Sha256::digest(entropy);
    let mut bits = Vec::with_capacity(entropy.len() * 8 + entropy.len() / 4);

    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    let cs_bits = entropy.len() / 4; // checksum bits = entropy_bytes / 4
    for i in 0..cs_bits {
        bits.push((checksum[i / 8] >> (7 - (i % 8))) & 1);
    }

    let wl = wordlist();
    let mut words = Vec::new();
    for chunk in bits.chunks(11) {
        let mut idx = 0u16;
        for &bit in chunk {
            idx = (idx << 1) | u16::from(bit);
        }
        if (idx as usize) >= wl.len() {
            return Err(MnemonicError::GenerationFailed("word index out of range".into()));
        }
        words.push(wl[idx as usize]);
    }

    Ok(words.join(" "))
}

fn validate_phrase(phrase: &str) -> Result<(), MnemonicError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let word_count = words.len();

    if word_count != 12 && word_count != 15 && word_count != 18 && word_count != 21 && word_count != 24 {
        return Err(MnemonicError::InvalidPhrase(format!(
            "expected 12/15/18/21/24 words, got {word_count}"
        )));
    }

    // Convert words → 11-bit indices → bits
    let mut bits = Vec::with_capacity(word_count * 11);
    for word in &words {
        let idx = word_index(word).ok_or_else(|| {
            MnemonicError::InvalidPhrase(format!("unknown word: '{word}'"))
        })?;
        for i in (0..11).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
    }

    let cs_bits = word_count / 3; // checksum bits
    let entropy_bits = word_count * 11 - cs_bits;
    let entropy_bytes = entropy_bits / 8;

    // Extract entropy bytes
    let mut entropy = alloc::vec![0u8; entropy_bytes];
    for i in 0..entropy_bits {
        if bits[i] == 1 {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    // Verify checksum
    let checksum = Sha256::digest(&entropy);
    for i in 0..cs_bits {
        let expected = (checksum[i / 8] >> (7 - (i % 8))) & 1;
        let actual = bits[entropy_bits + i];
        if expected != actual {
            entropy.zeroize();
            return Err(MnemonicError::InvalidPhrase("invalid checksum".into()));
        }
    }

    entropy.zeroize();
    Ok(())
}

/// PBKDF2-HMAC-SHA512 implementation.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8; 64]) {
    type HmacSha512 = Hmac<Sha512>;

    // BIP-39 only needs dkLen=64 with a single block (i=1)
    let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key size");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    out.copy_from_slice(&u);

    for _ in 1..rounds {
        let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key size");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (o, &b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn from_phrase_valid() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        assert_eq!(m.word_count(), 12);
    }

    #[test]
    fn reject_invalid_word() {
        assert!(Mnemonic::from_phrase("invalid words that are not real").is_err());
    }

    #[test]
    fn reject_bad_checksum() {
        let result = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        );
        assert!(result.is_err());
    }

    #[test]
    fn seed_vector_no_passphrase() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = m.to_seed("");
        assert_eq!(
            hex::encode(seed.expose()),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn seed_with_trezor_passphrase() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = m.to_seed("TREZOR");
        assert_eq!(
            hex::encode(seed.expose()),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn debug_does_not_leak() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let dbg = alloc::format!("{m:?}");
        assert!(!dbg.contains("abandon"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn phrase_roundtrip() {
        let m = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let recovered = core::str::from_utf8(m.phrase().expose()).unwrap().to_string();
        assert_eq!(recovered, ABANDON_PHRASE);
    }

    #[cfg(feature = "std")]
    #[test]
    fn generate_12_words() {
        let m = Mnemonic::generate(MnemonicStrength::Words12).unwrap();
        assert_eq!(m.word_count(), 12);
        // Verify the generated phrase is valid
        let recovered = core::str::from_utf8(m.phrase().expose()).unwrap().to_string();
        Mnemonic::from_phrase(&recovered).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn generate_24_words() {
        let m = Mnemonic::generate(MnemonicStrength::Words24).unwrap();
        assert_eq!(m.word_count(), 24);
    }
}
