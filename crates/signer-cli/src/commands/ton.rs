//! TON signing CLI commands.

use clap::{Args, Subcommand};
use signer_primitives::Sign;
use signer_ton::Signer;

use crate::output::{self, AddressOutput, SignOutput};

/// TON signing operations.
#[derive(Args)]
pub struct TonCommand {
    #[command(subcommand)]
    command: TonSubcommand,
}

#[derive(Subcommand)]
enum TonSubcommand {
    /// Sign a message with Ed25519.
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes with Ed25519.
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

impl TonCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            TonSubcommand::Sign { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_message(&signer, message.as_bytes())?;
                let result = SignOutput {
                    chain: "ton",
                    operation: "Ed25519",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: Some(signer.public_key_hex()),
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            TonSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let tx_bytes = super::parse_hex(&tx)?;
                let out = Sign::sign_transaction(&signer, &tx_bytes)?;
                let result = SignOutput {
                    chain: "ton",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            TonSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "ton",
                    address: Some(signer.address()),
                    public_key: signer.public_key_hex(),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
