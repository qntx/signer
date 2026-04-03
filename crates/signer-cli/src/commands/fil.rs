//! Filecoin signing CLI commands.

use clap::{Args, Subcommand};
use signer_fil::Signer;

use super::parse_hex32;
use crate::output::{self, AddressOutput, SignOutput};

/// Filecoin signing operations.
#[derive(Args)]
pub struct FilCommand {
    #[command(subcommand)]
    command: FilSubcommand,
}

#[derive(Subcommand)]
enum FilSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (Blake2b-256 then sign).
    SignMessage {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (Blake2b-256 then sign).
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

impl FilCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            FilSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                let result = SignOutput {
                    chain: "filecoin",
                    operation: "raw hash",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            FilSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                let result = SignOutput {
                    chain: "filecoin",
                    operation: "message (Blake2b-256)",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            FilSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&super::parse_hex(&tx)?)?;
                let result = SignOutput {
                    chain: "filecoin",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            FilSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "filecoin",
                    address: Some(signer.address()),
                    public_key: super::secp256k1_pubkey_hex(signer.signing_key()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
