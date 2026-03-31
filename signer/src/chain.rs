//! Supported blockchain families.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

/// Blockchain family identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "lowercase"))]
pub enum Chain {
    /// Ethereum and EVM-compatible chains.
    Evm,
    /// Bitcoin.
    Bitcoin,
    /// Solana.
    Solana,
    /// Cosmos SDK chains.
    Cosmos,
    /// TRON.
    Tron,
    /// TON (The Open Network).
    Ton,
    /// Filecoin.
    Filecoin,
    /// Sui.
    Sui,
    /// Spark (Lightning-adjacent Bitcoin L2).
    Spark,
}

impl Chain {
    /// BIP-44 coin type for this chain family.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Evm => 60,
            Self::Bitcoin => 0,
            Self::Solana => 501,
            Self::Cosmos => 118,
            Self::Tron => 195,
            Self::Ton => 607,
            Self::Filecoin => 461,
            Self::Sui => 784,
            Self::Spark => 0, // shares Bitcoin's coin type
        }
    }

    /// CAIP-2 namespace string.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Evm => "eip155",
            Self::Bitcoin => "bip122",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Filecoin => "fil",
            Self::Sui => "sui",
            Self::Spark => "spark",
        }
    }

    /// All supported chain variants.
    pub const ALL: [Self; 9] = [
        Self::Evm,
        Self::Bitcoin,
        Self::Solana,
        Self::Cosmos,
        Self::Tron,
        Self::Ton,
        Self::Filecoin,
        Self::Sui,
        Self::Spark,
    ];
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Evm => "evm",
            Self::Bitcoin => "bitcoin",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Filecoin => "filecoin",
            Self::Sui => "sui",
            Self::Spark => "spark",
        })
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "evm" | "ethereum" => Ok(Self::Evm),
            "bitcoin" | "btc" => Ok(Self::Bitcoin),
            "solana" | "sol" => Ok(Self::Solana),
            "cosmos" | "atom" => Ok(Self::Cosmos),
            "tron" | "trx" => Ok(Self::Tron),
            "ton" => Ok(Self::Ton),
            "filecoin" | "fil" => Ok(Self::Filecoin),
            "sui" => Ok(Self::Sui),
            "spark" => Ok(Self::Spark),
            _ => Err(alloc::format!("unknown chain: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_roundtrip() {
        for chain in Chain::ALL {
            let s = alloc::format!("{chain}");
            assert_eq!(s.parse::<Chain>().unwrap(), chain);
        }
    }

    #[test]
    fn coin_types() {
        assert_eq!(Chain::Evm.coin_type(), 60);
        assert_eq!(Chain::Bitcoin.coin_type(), 0);
        assert_eq!(Chain::Solana.coin_type(), 501);
    }

    #[test]
    fn parse_aliases() {
        assert_eq!("btc".parse::<Chain>().unwrap(), Chain::Bitcoin);
        assert_eq!("ethereum".parse::<Chain>().unwrap(), Chain::Evm);
        assert_eq!("sol".parse::<Chain>().unwrap(), Chain::Solana);
    }
}
