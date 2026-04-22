//! Cosmos signing CLI commands.

use clap::{Args, Subcommand};
use signer_cosmos::Signer;

use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "cosmos";

/// Cosmos signing operations.
#[derive(Args)]
pub(crate) struct CosmosCommand {
    #[command(subcommand)]
    command: CosmosSubcommand,
}

#[derive(Subcommand)]
enum CosmosSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (SHA-256 then sign).
    SignMessage {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (SHA-256 then sign).
    SignTx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tx: String,
    },
    /// Show compressed public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl CosmosCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            CosmosSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash")
                    .address(signer.address())
                    .signature(&out.signature)
                    .recovery_id(out.recovery_id)
                    .message(hash)
                    .render(json)
            }
            CosmosSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                output::sign(CHAIN, "message (SHA-256)")
                    .address(signer.address())
                    .signature(&out.signature)
                    .recovery_id(out.recovery_id)
                    .public_key_bytes(&signer.public_key_bytes())
                    .message(message)
                    .render(json)
            }
            CosmosSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .signature(&out.signature)
                    .recovery_id(out.recovery_id)
                    .render(json)
            }
            CosmosSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
