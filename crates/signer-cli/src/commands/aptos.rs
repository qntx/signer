//! Aptos signing CLI commands.

use clap::{Args, Subcommand};
use signer_aptos::Signer;

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
    /// Sign a BCS-serialized `RawTransaction` (with `APTOS::RawTransaction`
    /// SHA3-256 domain prefix).
    ///
    /// Aptos has no canonical off-chain personal-message envelope; the
    /// on-chain signing message is the only convention. For raw Ed25519
    /// over arbitrary bytes, call `Signer::sign_raw` from library code.
    SignTx {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded BCS `RawTransaction` bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show Aptos address for a private key.
    Address {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
    },
}

impl AptosCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            AptosSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
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
