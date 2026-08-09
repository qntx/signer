//! Spark signing CLI commands.

use clap::{Args, Subcommand};
use signer_spark::{SignDigest, SignMessage, Signer};

use super::key::load_secret_key;
use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "spark";

/// Spark signing operations.
#[derive(Args)]
pub(crate) struct SparkCommand {
    #[command(subcommand)]
    command: SparkSubcommand,
}

#[derive(Subcommand)]
enum SparkSubcommand {
    /// Sign a raw 32-byte hash.
    #[command(name = "sign-digest")]
    Digest {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// 32-byte hash in hex (with or without 0x prefix).
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (double-SHA256 then sign).
    SignMessage {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// Message to sign.
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (double-SHA256 then sign).
    SignTx {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded transaction bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show public key for a private key.
    Address {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
    },
}

impl SparkCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            SparkSubcommand::Digest { key, hash } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_digest(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            SparkSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_message(message.as_bytes())?;
                output::sign(CHAIN, "message (double-SHA256)")
                    .address(signer.address())
                    .from_output(&out)
                    .message(message)
                    .render(json)
            }
            SparkSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            SparkSubcommand::Address { key } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
