//! EVM signing CLI commands.

use clap::{Args, Subcommand};
use signer_evm::{Sign, SignMessage, Signer};

use super::key::load_secret_key;
use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "evm";

/// EVM signing operations.
#[derive(Args)]
pub(crate) struct EvmCommand {
    #[command(subcommand)]
    command: EvmSubcommand,
}

#[derive(Subcommand)]
enum EvmSubcommand {
    /// Sign a message (EIP-191 `personal_sign`).
    SignMessage {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// Message to sign.
        #[arg(short, long)]
        message: String,
    },
    /// Sign a raw 32-byte hash.
    SignHash {
        /// Private key: hex, `-` for stdin, or `@path`.
        #[arg(short, long)]
        key: String,
        /// 32-byte hash in hex.
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign transaction bytes (Keccak-256 hash then sign).
    SignTx {
        /// Private key: hex, `-` for stdin, or `@path`.
        #[arg(short, long)]
        key: String,
        /// Hex-encoded transaction bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show address and public key for a private key.
    Address {
        /// Private key: hex, `-` for stdin, or `@path`.
        #[arg(short, long)]
        key: String,
    },
}

impl EvmCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            EvmSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_message(message.as_bytes())?;
                output::sign(CHAIN, "EIP-191 personal_sign")
                    .address(signer.address())
                    .from_output(&out)
                    .message(message)
                    .render(json)
            }
            EvmSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            EvmSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            EvmSubcommand::Address { key } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
