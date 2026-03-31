//! Elliptic curve identifiers.

/// Elliptic curve used for key generation and signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// secp256k1 (Bitcoin, Ethereum, Cosmos, TRON, …).
    Secp256k1,
    /// Ed25519 (Solana, TON, Sui, …).
    Ed25519,
}

impl Curve {
    /// Private key length in bytes.
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        match self {
            Self::Secp256k1 | Self::Ed25519 => 32,
        }
    }

    /// Compressed public key length in bytes.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::Secp256k1 => 33,
            Self::Ed25519 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_lengths() {
        assert_eq!(Curve::Secp256k1.private_key_len(), 32);
        assert_eq!(Curve::Secp256k1.public_key_len(), 33);
        assert_eq!(Curve::Ed25519.private_key_len(), 32);
        assert_eq!(Curve::Ed25519.public_key_len(), 32);
    }
}
