//! CLI command definitions and handlers.

mod btc;
mod evm;
mod svm;

pub use btc::BtcCommand;
use clap::{Parser, Subcommand};
pub use evm::EvmCommand;
pub use svm::SvmCommand;

/// Signer - A multi-chain transaction signing CLI tool.
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
    /// Bitcoin signing operations.
    #[command(name = "btc", alias = "bitcoin")]
    Btc(BtcCommand),

    /// Ethereum / EVM signing operations.
    #[command(name = "evm", alias = "eth", alias = "ethereum")]
    Evm(EvmCommand),

    /// Solana / SVM signing operations.
    #[command(name = "svm", alias = "sol", alias = "solana")]
    Svm(SvmCommand),
}
