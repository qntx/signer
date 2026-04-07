//! XRPL signing CLI commands.

use clap::{Args, Subcommand};
use signer_xrpl::Signer;

use super::parse_hex32;
use crate::output::{self, AddressOutput, SignOutput};

/// XRP Ledger signing operations.
#[derive(Args)]
pub(crate) struct XrplCommand {
    #[command(subcommand)]
    command: XrplSubcommand,
}

#[derive(Subcommand)]
enum XrplSubcommand {
    /// Sign a raw 32-byte hash (DER-encoded output).
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign transaction bytes (STX\0 prefix + SHA-512-half, then sign).
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

impl XrplCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            XrplSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                let result = SignOutput {
                    chain: "xrpl",
                    operation: "raw hash (DER)",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: Some(hash),
                };
                output::render_sign(&result, json)?;
            }
            XrplSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&super::parse_hex(&tx)?)?;
                let result = SignOutput {
                    chain: "xrpl",
                    operation: "transaction (SHA-512-half + DER)",
                    address: Some(signer.address()),
                    signature: hex::encode(&out.signature),
                    recovery_id: out.recovery_id,
                    public_key: None,
                    message: None,
                };
                output::render_sign(&result, json)?;
            }
            XrplSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let result = AddressOutput {
                    chain: "xrpl",
                    address: Some(signer.address()),
                    public_key: hex::encode(signer.public_key_bytes()),
                };
                output::render_address(&result, json)?;
            }
        }
        Ok(())
    }
}
