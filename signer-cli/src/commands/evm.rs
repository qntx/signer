//! EVM signing CLI commands.

use clap::{Args, Subcommand};
use signer_evm::{Address, B256, Signer, SignerSync};

use crate::output::{self, AddressOutput, SignOutput, VerifyOutput};

/// EVM signing operations.
#[derive(Args)]
pub struct EvmCommand {
    #[command(subcommand)]
    command: EvmSubcommand,
}

#[derive(Subcommand)]
enum EvmSubcommand {
    /// Sign a message (EIP-191 `personal_sign`).
    SignMessage {
        /// Private key in hex format (with or without 0x prefix).
        #[arg(short, long)]
        key: String,

        /// Message to sign.
        #[arg(short, long)]
        message: String,
    },

    /// Sign a raw 32-byte hash.
    SignHash {
        /// Private key in hex format.
        #[arg(short, long)]
        key: String,

        /// 32-byte hash in hex.
        #[arg(short = 'x', long)]
        hash: String,
    },

    /// Verify an EIP-191 signed message.
    VerifyMessage {
        /// Hex-encoded signature (with or without 0x prefix).
        #[arg(short, long)]
        signature: String,

        /// Message that was signed.
        #[arg(short, long)]
        message: String,

        /// Expected Ethereum address.
        #[arg(short, long)]
        address: String,
    },

    /// Show address and public key for a private key.
    Address {
        /// Private key in hex format.
        #[arg(short, long)]
        key: String,
    },
}

impl EvmCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            EvmSubcommand::SignMessage { key, message } => {
                let signer = Signer::from_hex(&key)?;
                let sig = signer.sign_message_sync(message.as_bytes())?;
                let out = SignOutput {
                    chain: "ethereum",
                    operation: "EIP-191 personal_sign",
                    address: Some(format!("{}", signer.address())),
                    signature: format!("0x{sig}"),
                    message: Some(message),
                };
                output::render_sign(&out, json)?;
            }
            EvmSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let hash_bytes = parse_b256(&hash)?;
                let sig = signer.sign_hash_sync(&hash_bytes)?;
                let out = SignOutput {
                    chain: "ethereum",
                    operation: "raw hash",
                    address: Some(format!("{}", signer.address())),
                    signature: format!("0x{sig}"),
                    message: Some(hash),
                };
                output::render_sign(&out, json)?;
            }
            EvmSubcommand::VerifyMessage {
                signature,
                message,
                address,
            } => {
                let expected: Address = address
                    .parse()
                    .map_err(|e| format!("invalid address: {e}"))?;
                let sig_hex = signature.strip_prefix("0x").unwrap_or(&signature);
                let sig_bytes = hex::decode(sig_hex)?;
                let sig = signer_evm::Signature::try_from(sig_bytes.as_slice())
                    .map_err(|e| format!("invalid signature: {e}"))?;
                let recovered = sig
                    .recover_address_from_msg(message.as_bytes())
                    .map_err(|e| format!("recovery failed: {e}"))?;
                let valid = recovered == expected;
                let out = VerifyOutput {
                    chain: "ethereum",
                    valid,
                    address: Some(address),
                    message: Some(message),
                };
                output::render_verify(&out, json)?;
            }
            EvmSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                let addr = signer.address();
                let pk_bytes = signer.credential().verifying_key().to_sec1_bytes();
                let out = AddressOutput {
                    chain: "ethereum",
                    network: None,
                    address: format!("{addr}"),
                    public_key: format!("0x{}", hex::encode(&pk_bytes)),
                    addresses: vec![],
                };
                output::render_address(&out, json)?;
            }
        }
        Ok(())
    }
}

fn parse_b256(hex_str: &str) -> Result<B256, Box<dyn std::error::Error>> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "hash must be exactly 32 bytes")?;
    Ok(B256::from(arr))
}
