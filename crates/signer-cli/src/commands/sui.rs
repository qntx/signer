//! Sui signing CLI commands.

use clap::{Args, Subcommand};
use signer_core::Sign;
use signer_sui::Signer;

use crate::output::{self, AddressOutput, SignOutput};

/// Sui signing operations.
#[derive(Args)]
pub struct SuiCommand {
    #[command(subcommand)]
    command: SuiSubcommand,
}

#[derive(Subcommand)]
enum SuiSubcommand {
    /// Sign a message (BCS + `BLAKE2b` intent).
    SignMessage {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Sign transaction bytes (`BLAKE2b` intent digest).
    SignTx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tx: String,
    },
    /// Show Sui address and public key for a private key.
    Address {
        #[arg(short, long)]
        key: String,
    },
}

impl SuiCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SuiSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let out = Sign::sign_message(&signer, message.as_bytes())?;
                let result = SignOutput {
                    chain: "sui",
                    operation: "personal message (BCS + intent)",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: out.public_key.map(hex::encode),
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            SuiSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let tx_bytes = super::parse_hex(&tx)?;
                let out = Sign::sign_transaction(&signer, &tx_bytes)?;
                let result = SignOutput {
                    chain: "sui",
                    operation: "transaction (intent digest)",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: out.public_key.map(hex::encode),
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            SuiSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "sui",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
