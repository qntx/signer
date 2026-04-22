//! CLI command definitions and handlers.

mod aptos;
mod btc;
mod cosmos;
mod evm;
mod fil;
mod nostr;
mod spark;
mod sui;
mod svm;
mod ton;
mod tron;
mod xrpl;

pub(crate) use aptos::AptosCommand;
pub(crate) use btc::BtcCommand;
use clap::{Parser, Subcommand};
pub(crate) use cosmos::CosmosCommand;
pub(crate) use evm::EvmCommand;
pub(crate) use fil::FilCommand;
pub(crate) use nostr::NostrCommand;
pub(crate) use spark::SparkCommand;
pub(crate) use sui::SuiCommand;
pub(crate) use svm::SvmCommand;
pub(crate) use ton::TonCommand;
pub(crate) use tron::TronCommand;
pub(crate) use xrpl::XrplCommand;

/// Parse a hex string (with optional 0x prefix) into a 32-byte array.
pub(crate) fn parse_hex32(input: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let s = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|_| "hash must be exactly 32 bytes".into())
}

/// Parse a hex string (with optional 0x prefix) into bytes.
pub(crate) fn parse_hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = input.strip_prefix("0x").unwrap_or(input);
    Ok(hex::decode(s)?)
}

/// Signer — A multi-chain transaction signing CLI tool.
#[derive(Parser)]
#[command(name = "signer")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct Cli {
    /// Output results in JSON format for programmatic/agent consumption.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available chain commands.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Aptos signing operations.
    #[command(name = "aptos", alias = "apt")]
    Aptos(AptosCommand),

    /// Ethereum / EVM signing operations.
    #[command(name = "evm", alias = "eth", alias = "ethereum")]
    Evm(EvmCommand),

    /// Bitcoin signing operations.
    #[command(name = "btc", alias = "bitcoin")]
    Btc(BtcCommand),

    /// Solana / SVM signing operations.
    #[command(name = "svm", alias = "sol", alias = "solana")]
    Svm(SvmCommand),

    /// Cosmos signing operations.
    #[command(name = "cosmos", alias = "atom")]
    Cosmos(CosmosCommand),

    /// Tron signing operations.
    #[command(name = "tron", alias = "trx")]
    Tron(TronCommand),

    /// Sui signing operations.
    #[command(name = "sui")]
    Sui(SuiCommand),

    /// TON signing operations.
    #[command(name = "ton")]
    Ton(TonCommand),

    /// Filecoin signing operations.
    #[command(name = "fil", alias = "filecoin")]
    Fil(FilCommand),

    /// Spark (Bitcoin L2) signing operations.
    #[command(name = "spark")]
    Spark(SparkCommand),

    /// XRP Ledger signing operations.
    #[command(name = "xrpl", alias = "xrp", alias = "ripple")]
    Xrpl(XrplCommand),

    /// Nostr signing operations (BIP-340 Schnorr, NIP-01/NIP-19).
    #[command(name = "nostr")]
    Nostr(NostrCommand),
}
