//! Tron signing CLI commands.

use clap::{Args, Subcommand};
use signer_tron::Signer;

use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "tron";

/// Tron signing operations.
#[derive(Args)]
pub(crate) struct TronCommand {
    #[command(subcommand)]
    command: TronSubcommand,
}

#[derive(Subcommand)]
enum TronSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (TRON Signed Message prefix + Keccak-256).
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
    /// Show public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl TronCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            TronSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            TronSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                output::sign(CHAIN, "TRON Signed Message")
                    .address(signer.address())
                    .from_output(&out)
                    .message(message)
                    .render(json)
            }
            TronSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            TronSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
