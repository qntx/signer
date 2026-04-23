//! Solana signing CLI commands.

use clap::{Args, Subcommand};
use signer_primitives::Sign;
use signer_svm::Signer;

use super::parse_hex;
use crate::output::{self, CliResult};

const CHAIN: &str = "solana";

/// Solana signing operations.
#[derive(Args)]
pub(crate) struct SvmCommand {
    #[command(subcommand)]
    command: SvmSubcommand,
}

#[derive(Subcommand)]
enum SvmSubcommand {
    /// Sign a message with Ed25519.
    Sign {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,
        /// Message to sign.
        #[arg(short, long)]
        message: String,
        /// Treat message as hex-encoded bytes.
        #[arg(long)]
        hex: bool,
    },
    /// Sign transaction bytes.
    SignTx {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,
        /// Hex-encoded transaction bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show address and public key for a private key.
    Address {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,
    },
}

fn load_signer(key: &str) -> Result<Signer, Box<dyn std::error::Error>> {
    Signer::from_hex(key)
        .or_else(|_| Signer::from_keypair_base58(key))
        .map_err(|e| format!("invalid private key: {e}").into())
}

impl SvmCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            SvmSubcommand::Sign { key, message, hex } => {
                let signer = load_signer(&key)?;
                let msg_bytes = if hex {
                    parse_hex(&message)?
                } else {
                    message.as_bytes().to_vec()
                };
                let out = signer.sign_message(&msg_bytes)?;
                output::sign(CHAIN, "Ed25519")
                    .address(signer.address())
                    .from_output(&out)
                    .public_key_bytes(&signer.public_key_bytes())
                    .message(message)
                    .render(json)
            }
            SvmSubcommand::SignTx { key, tx } => {
                let signer = load_signer(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            SvmSubcommand::Address { key } => {
                let signer = load_signer(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
