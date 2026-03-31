//! Chain-specific signer implementations.

#[cfg(feature = "evm")]
pub mod evm;
#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "solana")]
pub mod solana;
#[cfg(feature = "cosmos")]
pub mod cosmos;
#[cfg(feature = "tron")]
pub mod tron;
#[cfg(feature = "ton")]
pub mod ton;
#[cfg(feature = "filecoin")]
pub mod filecoin;
#[cfg(feature = "sui")]
pub mod sui;
#[cfg(feature = "spark")]
pub mod spark;

use alloc::boxed::Box;
use crate::chain::Chain;
use crate::traits::ChainSigner;

/// Get a default signer for the given chain family.
///
/// # Panics
///
/// Panics if the corresponding chain feature is not enabled.
#[must_use]
pub fn signer_for_chain(chain: Chain) -> Box<dyn ChainSigner> {
    match chain {
        #[cfg(feature = "evm")]
        Chain::Evm => Box::new(evm::EvmSigner),
        #[cfg(feature = "bitcoin")]
        Chain::Bitcoin => Box::new(bitcoin::BitcoinSigner::mainnet()),
        #[cfg(feature = "solana")]
        Chain::Solana => Box::new(solana::SolanaSigner),
        #[cfg(feature = "cosmos")]
        Chain::Cosmos => Box::new(cosmos::CosmosSigner::cosmos_hub()),
        #[cfg(feature = "tron")]
        Chain::Tron => Box::new(tron::TronSigner),
        #[cfg(feature = "ton")]
        Chain::Ton => Box::new(ton::TonSigner),
        #[cfg(feature = "filecoin")]
        Chain::Filecoin => Box::new(filecoin::FilecoinSigner),
        #[cfg(feature = "sui")]
        Chain::Sui => Box::new(sui::SuiSigner),
        #[cfg(feature = "spark")]
        Chain::Spark => Box::new(spark::SparkSigner),
        #[allow(unreachable_patterns)]
        _ => panic!("chain {chain} is not enabled — enable the corresponding cargo feature"),
    }
}
