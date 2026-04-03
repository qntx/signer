//! Solana signing CLI commands.

use clap::{Args, Subcommand};
use signer_primitives::Sign;
use signer_svm::Signer;

use crate::output::{self, AddressOutput, SignOutput};

/// Solana signing operations.
#[derive(Args)]
pub struct SvmCommand {
    #[command(subcommand)]
    command: SvmSubcommand,
}

#[derive(Subcommand)]
enum SvmSubcommand {
    /// Sign a message with Ed25519.
    Sign {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,
        /// Message to sign.
        #[arg(short, long)]
        message: String,
        /// Treat message as hex-encoded bytes.
        #[arg(long)]
        hex: bool,
    },
    /// Sign transaction bytes.
    SignTx {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,
        /// Hex-encoded transaction bytes.
        #[arg(short, long)]
        tx: String,
    },
    /// Show address and public key for a private key.
    Address {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,
    },
}

fn load_signer(key: &str) -> Result<Signer, Box<dyn std::error::Error>> {
    Signer::from_hex(key)
        .or_else(|_| Signer::from_keypair_base58(key))
        .map_err(|e| format!("invalid private key: {e}").into())
}

impl SvmCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SvmSubcommand::Sign { key, message, hex } => {
                let signer = load_signer(&key)?;
                let msg_bytes = if hex {
                    super::parse_hex(&message)?
                } else {
                    message.as_bytes().to_vec()
                };
                let out = signer.sign_message(&msg_bytes)?;
                let result = SignOutput {
                    chain: "solana",
                    operation: "Ed25519",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: Some(hex::encode(signer.public_key_bytes())),
                    message: Some(message),
                };
                output::render_sign(&result, json)?;
            }
            SvmSubcommand::SignTx { key, tx } => {
                let signer = load_signer(&key)?;
                let tx_bytes = super::parse_hex(&tx)?;
                let out = signer.sign_transaction(&tx_bytes)?;
                let result = SignOutput {
                    chain: "solana",
                    operation: "transaction",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: None,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            SvmSubcommand::Address { key } => {
                let signer = load_signer(&key)?;
                let result = AddressOutput {
                    chain: "solana",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
