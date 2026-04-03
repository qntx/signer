//! CLI command definitions and handlers.

mod btc;
mod cosmos;
mod evm;
mod fil;
mod spark;
mod sui;
mod svm;
mod ton;
mod tron;
mod xrpl;

pub use btc::BtcCommand;
use clap::{Parser, Subcommand};
pub use cosmos::CosmosCommand;
pub use evm::EvmCommand;
pub use fil::FilCommand;
pub use spark::SparkCommand;
pub use sui::SuiCommand;
pub use svm::SvmCommand;
pub use ton::TonCommand;
pub use tron::TronCommand;
pub use xrpl::XrplCommand;

/// Derive compressed public key hex from a secp256k1 signing key.
pub fn secp256k1_pubkey_hex(sk: &k256::ecdsa::SigningKey) -> String {
    let pt = sk.verifying_key().to_encoded_point(true);
    hex::encode(pt.as_bytes())
}

/// Parse a hex string (with optional 0x prefix) into a 32-byte array.
pub fn parse_hex32(input: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let s = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|_| "hash must be exactly 32 bytes".into())
}

/// Parse a hex string (with optional 0x prefix) into bytes.
pub fn parse_hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = input.strip_prefix("0x").unwrap_or(input);
    Ok(hex::decode(s)?)
}

/// Signer — A multi-chain transaction signing CLI tool.
#[derive(Parser)]
#[command(name = "signer")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Output results in JSON format for programmatic/agent consumption.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available chain commands.
#[derive(Subcommand)]
pub enum Commands {
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
}
