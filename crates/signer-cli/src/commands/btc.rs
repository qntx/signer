//! Bitcoin signing CLI commands.

use clap::{Args, Subcommand};
use signer_btc::Signer;

use super::parse_hex32;
use crate::output::{self, AddressOutput, SignOutput};

/// Bitcoin signing operations.
#[derive(Args)]
pub struct BtcCommand {
    #[command(subcommand)]
    command: BtcSubcommand,
}

#[derive(Subcommand)]
enum BtcSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a message (Bitcoin Signed Message).
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
    /// Show compressed public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl BtcCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            BtcSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let hash_bytes = parse_hex32(&hash)?;
                let out = signer.sign_hash(&hash_bytes)?;
                let result = SignOutput {
                    chain: "bitcoin",
                    operation: "raw hash",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            BtcSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                let result = SignOutput {
                    chain: "bitcoin",
                    operation: "Bitcoin Signed Message",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: Some(hex::encode(signer.public_key_bytes())),
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            BtcSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let tx_bytes = super::parse_hex(&tx)?;
                let out = signer.sign_transaction(&tx_bytes)?;
                let result = SignOutput {
                    chain: "bitcoin",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            BtcSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "bitcoin",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
