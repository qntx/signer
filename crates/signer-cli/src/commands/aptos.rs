//! Aptos signing CLI commands.

use clap::{Args, Subcommand};
use signer_aptos::Signer;
use signer_primitives::Sign;

use crate::output::{self, AddressOutput, SignOutput};

/// Aptos signing operations.
#[derive(Args)]
pub(crate) struct AptosCommand {
    #[command(subcommand)]
    command: AptosSubcommand,
}

#[derive(Subcommand)]
enum AptosSubcommand {
    /// Sign a message with Ed25519.
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign a BCS-serialized `RawTransaction` (with APTOS domain prefix).
    SignTx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tx: String,
    },
    /// Show Aptos address for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl AptosCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            AptosSubcommand::Sign { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_message(&signer, message.as_bytes())?;
                let result = SignOutput {
                    chain: "aptos",
                    operation: "Ed25519",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: Some(signer.public_key_hex()),
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            AptosSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let tx_bytes = super::parse_hex(&tx)?;
                let out = Sign::sign_transaction(&signer, &tx_bytes)?;
                let result = SignOutput {
                    chain: "aptos",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: Some(signer.public_key_hex()),
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            AptosSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "aptos",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
