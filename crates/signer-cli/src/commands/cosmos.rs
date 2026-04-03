//! Cosmos signing CLI commands.

use clap::{Args, Subcommand};
use signer_cosmos::Signer;

use super::parse_hex32;
use crate::output::{self, AddressOutput, SignOutput};

/// Cosmos signing operations.
#[derive(Args)]
pub struct CosmosCommand {
    #[command(subcommand)]
    command: CosmosSubcommand,
}

#[derive(Subcommand)]
enum CosmosSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (SHA-256 then sign).
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
    /// Show compressed public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl CosmosCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            CosmosSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                let result = SignOutput {
                    chain: "cosmos",
                    operation: "raw hash",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            CosmosSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                let result = SignOutput {
                    chain: "cosmos",
                    operation: "message (SHA-256)",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: Some(hex::encode(signer.public_key_bytes())),
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            CosmosSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&super::parse_hex(&tx)?)?;
                let result = SignOutput {
                    chain: "cosmos",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            CosmosSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "cosmos",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
