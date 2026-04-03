//! EVM signing CLI commands.

use clap::{Args, Subcommand};
use signer_evm::Signer;

use super::{parse_hex, parse_hex32};
use crate::output::{self, AddressOutput, SignOutput};

/// EVM signing operations.
#[derive(Args)]
pub struct EvmCommand {
    #[command(subcommand)]
    command: EvmSubcommand,
}

#[derive(Subcommand)]
enum EvmSubcommand {
    /// Sign a message (EIP-191 `personal_sign`).
    SignMessage {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// Message to sign.
        #[arg(short, long)]
        message: String,
    },
    /// Sign a raw 32-byte hash.
    SignHash {
        /// Private key in hex.
        #[arg(short, long)]
        key: String,
        /// 32-byte hash in hex.
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign transaction bytes (Keccak-256 hash then sign).
    SignTx {
        /// Private key in hex.
        #[arg(short, long)]
        key: String,
        /// Hex-encoded transaction bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show address and public key for a private key.
    Address {
        /// Private key in hex.
        #[arg(short, long)]
        key: String,
    },
}

impl EvmCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            EvmSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                let result = SignOutput {
                    chain: "ethereum",
                    operation: "EIP-191 personal_sign",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            EvmSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let hash_bytes = parse_hex32(&hash)?;
                let out = signer.sign_hash(&hash_bytes)?;
                let result = SignOutput {
                    chain: "ethereum",
                    operation: "raw hash",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            EvmSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let tx_bytes = parse_hex(&tx)?;
                let out = signer.sign_transaction(&tx_bytes)?;
                let result = SignOutput {
                    chain: "ethereum",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            EvmSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "ethereum",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
