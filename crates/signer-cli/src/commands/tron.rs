//! Tron signing CLI commands.

use clap::{Args, Subcommand};
use signer_tron::Signer;

use super::parse_hex32;
use crate::output::{self, AddressOutput, SignOutput};

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
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            TronSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                let result = SignOutput {
                    chain: "tron",
                    operation: "raw hash",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            TronSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                let result = SignOutput {
                    chain: "tron",
                    operation: "TRON Signed Message",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            TronSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&super::parse_hex(&tx)?)?;
                let result = SignOutput {
                    chain: "tron",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            TronSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "tron",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
