//! XRPL signing CLI commands.

use clap::{Args, Subcommand};
use signer_xrpl::{SignDigest, Signer};

use super::key::load_secret_key;
use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "xrpl";

/// XRP Ledger signing operations.
#[derive(Args)]
pub(crate) struct XrplCommand {
    #[command(subcommand)]
    command: XrplSubcommand,
}

#[derive(Subcommand)]
enum XrplSubcommand {
    /// Sign a raw 32-byte hash (DER-encoded output).
    #[command(name = "sign-digest")]
    Digest {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// 32-byte hash in hex (with or without 0x prefix).
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign transaction bytes (STX\0 prefix + SHA-512-half, then sign).
    SignTx {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded unsigned transaction bytes (without `STX\0`).
        #[arg(short, long)]
        tx: String,
    },
    /// Show compressed public key for a private key.
    Address {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
    },
}

impl XrplCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            XrplSubcommand::Digest { key, hash } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_digest(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash (DER)")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            XrplSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction (SHA-512-half + DER)")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            XrplSubcommand::Address { key } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
