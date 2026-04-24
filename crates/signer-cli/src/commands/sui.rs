//! Sui signing CLI commands.

use clap::{Args, Subcommand};
use signer_sui::{SignMessage, Signer};

use super::parse_hex;
use crate::output::{self, CliResult};

const CHAIN: &str = "sui";

/// Sui signing operations.
#[derive(Args)]
pub(crate) struct SuiCommand {
    #[command(subcommand)]
    command: SuiSubcommand,
}

#[derive(Subcommand)]
enum SuiSubcommand {
    /// Sign a message (BCS + `BLAKE2b` intent).
    SignMessage {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// Message to sign.
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (`BLAKE2b` intent digest).
    SignTx {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded BCS transaction bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show Sui address and public key for a private key.
    Address {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
    },
}

impl SuiCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            SuiSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                output::sign(CHAIN, "personal message (BCS + intent)")
                    .address(signer.address())
                    .from_output(&out)
                    .message(message)
                    .render(json)
            }
            SuiSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction (intent digest)")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            SuiSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
