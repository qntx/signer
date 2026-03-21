//! Solana signing CLI commands.

use clap::{Args, Subcommand};
use signer_svm::Signer;

use crate::output::{self, AddressOutput, SignOutput, VerifyOutput};

/// Solana signing operations.
#[derive(Args)]
pub struct SvmCommand {
    #[command(subcommand)]
    command: SvmSubcommand,
}

#[derive(Subcommand)]
enum SvmSubcommand {
    /// Sign arbitrary bytes with Ed25519.
    Sign {
        /// Private key in hex or base58 keypair format.
        #[arg(short, long)]
        key: String,

        /// Message to sign (UTF-8 string).
        #[arg(short, long)]
        message: String,

        /// Treat message as hex-encoded bytes.
        #[arg(long)]
        hex: bool,
    },

    /// Verify an Ed25519 signature.
    Verify {
        /// Hex-encoded signature (64 bytes).
        #[arg(short, long)]
        signature: String,

        /// Message that was signed.
        #[arg(short, long)]
        message: String,

        /// Public key (base58 address or hex).
        #[arg(short, long)]
        pubkey: String,

        /// Treat message as hex-encoded bytes.
        #[arg(long)]
        hex: bool,
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

fn resolve_message(message: &str, is_hex: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if is_hex {
        let s = message.strip_prefix("0x").unwrap_or(message);
        Ok(hex::decode(s)?)
    } else {
        Ok(message.as_bytes().to_vec())
    }
}

impl SvmCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SvmSubcommand::Sign { key, message, hex } => {
                let signer = load_signer(&key)?;
                let msg_bytes = resolve_message(&message, hex)?;
                let sig = signer.sign_transaction_message(&msg_bytes);
                let out = SignOutput {
                    chain: "solana",
                    operation: "Ed25519",
                    address: Some(signer.address()),
                    signature: ::hex::encode(sig.to_bytes()),
                    message: Some(message),
                };
                output::render_sign(&out, json)?;
            }
            SvmSubcommand::Verify {
                signature,
                message,
                pubkey,
                hex,
            } => {
                let msg_bytes = resolve_message(&message, hex)?;
                let sig_hex = signature.strip_prefix("0x").unwrap_or(&signature);
                let sig_bytes: [u8; 64] = ::hex::decode(sig_hex)?
                    .try_into()
                    .map_err(|_| "signature must be 64 bytes")?;
                let sig = signer_svm::Signature::from_bytes(&sig_bytes);

                let pk_bytes = parse_pubkey(&pubkey)?;
                let vk = signer_svm::VerifyingKey::from_bytes(&pk_bytes)
                    .map_err(|e| format!("invalid public key: {e}"))?;
                use signer_svm::ed25519_dalek::Verifier;
                let valid = vk.verify(&msg_bytes, &sig).is_ok();

                let out = VerifyOutput {
                    chain: "solana",
                    valid,
                    address: Some(pubkey),
                    message: Some(message),
                };
                output::render_verify(&out, json)?;
            }
            SvmSubcommand::Address { key } => {
                let signer = load_signer(&key)?;
                let out = AddressOutput {
                    chain: "solana",
                    network: None,
                    address: signer.address(),
                    public_key: signer.public_key_hex(),
                    addresses: vec![],
                };
                output::render_address(&out, json)?;
            }
        }
        Ok(())
    }
}

fn parse_pubkey(input: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = if input.starts_with("0x") || input.len() == 64 {
        let h = input.strip_prefix("0x").unwrap_or(input);
        hex::decode(h)?
    } else {
        bs58::decode(input)
            .into_vec()
            .map_err(|e| format!("invalid base58: {e}"))?
    };
    bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".into())
}
