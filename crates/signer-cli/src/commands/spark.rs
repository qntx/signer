//! Spark signing CLI commands.

use clap::{Args, Subcommand};
use signer_spark::Signer;

use super::parse_hex32;
use crate::output::{self, AddressOutput, SignOutput};

/// Spark signing operations.
#[derive(Args)]
pub struct SparkCommand {
    #[command(subcommand)]
    command: SparkSubcommand,
}

#[derive(Subcommand)]
enum SparkSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (double-SHA256 then sign).
    SignMessage {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (double-SHA256 then sign).
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

impl SparkCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SparkSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                let result = SignOutput {
                    chain: "spark",
                    operation: "raw hash",
                    address: None,
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            SparkSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                let result = SignOutput {
                    chain: "spark",
                    operation: "message (double-SHA256)",
                    address: None,
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            SparkSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&super::parse_hex(&tx)?)?;
                let result = SignOutput {
                    chain: "spark",
                    operation: "transaction",
                    address: None,
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            SparkSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "spark",
                    address: None,
                    public_key: super::secp256k1_pubkey_hex(signer.signing_key()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
