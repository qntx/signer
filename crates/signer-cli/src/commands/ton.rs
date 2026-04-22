//! TON signing CLI commands.

use clap::{Args, Subcommand};
use signer_primitives::Sign;
use signer_ton::Signer;

use super::parse_hex;
use crate::output::{self, CliResult};

const CHAIN: &str = "ton";

/// TON signing operations.
#[derive(Args)]
pub(crate) struct TonCommand {
    #[command(subcommand)]
    command: TonSubcommand,
}

#[derive(Subcommand)]
enum TonSubcommand {
    /// Sign a message with Ed25519.
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes with Ed25519.
    SignTx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tx: String,
    },
    /// Show public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl TonCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            TonSubcommand::Sign { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_message(&signer, message.as_bytes())?;
                output::sign(CHAIN, "Ed25519")
                    .address(signer.address())
                    .signature(&out.signature)
                    .public_key_hex(signer.public_key_hex())
                    .message(message)
                    .render(json)
            }
            TonSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_transaction(&signer, &parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .signature(&out.signature)
                    .render(json)
            }
            TonSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
