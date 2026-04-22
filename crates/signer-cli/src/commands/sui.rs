//! Sui signing CLI commands.

use clap::{Args, Subcommand};
use signer_primitives::Sign;
use signer_sui::Signer;

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
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (`BLAKE2b` intent digest).
    SignTx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tx: String,
    },
    /// Show Sui address and public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl SuiCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            SuiSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_message(&signer, message.as_bytes())?;
                output::sign(CHAIN, "personal message (BCS + intent)")
                    .address(signer.address())
                    .signature(&out.signature)
                    .public_key_opt_bytes(out.public_key)
                    .message(message)
                    .render(json)
            }
            SuiSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_transaction(&signer, &parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction (intent digest)")
                    .address(signer.address())
                    .signature(&out.signature)
                    .public_key_opt_bytes(out.public_key)
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
