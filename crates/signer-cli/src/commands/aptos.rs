//! Aptos signing CLI commands.

use clap::{Args, Subcommand};
use signer_aptos::Signer;
use signer_primitives::Sign;

use super::parse_hex;
use crate::output::{self, CliResult};

const CHAIN: &str = "aptos";

/// Aptos signing operations.
#[derive(Args)]
pub(crate) struct AptosCommand {
    #[command(subcommand)]
    command: AptosSubcommand,
}

#[derive(Subcommand)]
enum AptosSubcommand {
    /// Sign a message with Ed25519.
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign a BCS-serialized `RawTransaction` (with APTOS domain prefix).
    SignTx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tx: String,
    },
    /// Show Aptos address for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl AptosCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            AptosSubcommand::Sign { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_message(&signer, message.as_bytes())?;
                output::sign(CHAIN, "Ed25519")
                    .address(signer.address())
                    .from_output(&out)
                    .public_key_hex(signer.public_key_hex())
                    .message(message)
                    .render(json)
            }
            AptosSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_transaction(&signer, &parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .public_key_hex(signer.public_key_hex())
                    .render(json)
            }
            AptosSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
