//! Filecoin signing CLI commands.

use clap::{Args, Subcommand};
use signer_fil::{Sign, Signer};

use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "fil";

/// Filecoin signing operations.
#[derive(Args)]
pub(crate) struct FilCommand {
    #[command(subcommand)]
    command: FilSubcommand,
}

#[derive(Subcommand)]
enum FilSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// 32-byte hash in hex (with or without 0x prefix).
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a CID byte array (or arbitrary preimage), Blake2b-256 then sign.
    ///
    /// Filecoin has no separate personal-message scheme; feed any preimage
    /// you wish to sign here and the wrapper will hash it with Blake2b-256
    /// before the ECDSA step.
    SignTx {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded CID / preimage bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show public key for a private key.
    Address {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
    },
}

impl FilCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            FilSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            FilSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            FilSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
