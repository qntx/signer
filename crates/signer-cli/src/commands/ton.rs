//! TON signing CLI commands.

use clap::{Args, Subcommand};
use signer_ton::{SignMessage, Signer};

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
    /// Show signer identity (hex public key) for a private key.
    ///
    /// TON wallet addresses depend on the deployed contract code and
    /// workchain ID, so the signer only exposes its identity (public
    /// key hex). Use `kobe-ton` for full wallet-address derivation.
    Identity {
        #[arg(short, long)]
        key: String,
    },
}

impl TonCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            TonSubcommand::Sign { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = SignMessage::sign_message(&signer, message.as_bytes())?;
                output::sign(CHAIN, "Ed25519")
                    .identity(signer.identity())
                    .from_output(&out)
                    .public_key_hex(signer.public_key_hex())
                    .message(message)
                    .render(json)
            }
            TonSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .identity(signer.identity())
                    .from_output(&out)
                    .render(json)
            }
            TonSubcommand::Identity { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .identity(signer.identity())
                    .render(json)
            }
        }
    }
}
