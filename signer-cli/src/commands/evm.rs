//! EVM signing CLI commands.

use clap::{Args, Subcommand};
use signer_evm::{Address, B256, Signer, SignerSync, TxSignerSync};

use crate::output::{self, AddressOutput, SignOutput, TransactionOutput, VerifyOutput};

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

    /// Sign a raw unsigned transaction (hex-encoded EIP-2718 bytes).
    SignTransaction {
        /// Private key in hex format.
        #[arg(short, long)]
        key: String,

        /// Hex-encoded unsigned transaction bytes (EIP-2718 typed envelope).
        #[arg(short, long)]
        tx: String,
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
            EvmSubcommand::SignTransaction { key, tx } => {
                sign_transaction(&key, &tx, json)?;
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

fn sign_transaction(key: &str, tx_hex: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    use signer_evm::alloy_consensus::{Signed, TxEnvelope, TypedTransaction};
    use signer_evm::alloy_network::eip2718::Encodable2718;

    let signer = Signer::from_hex(key)?;
    let tx_hex = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex)?;

    // Decode unsigned transaction from EIP-2718 bytes
    let mut typed_tx = TypedTransaction::decode_unsigned(&mut &tx_bytes[..])
        .map_err(|e| format!("failed to decode transaction: {e}"))?;

    // Sign
    let sig = signer
        .sign_transaction_sync(&mut typed_tx)
        .map_err(|e| format!("signing failed: {e}"))?;

    // Build signed envelope
    let tx_hash = typed_tx.tx_hash(&sig);
    let envelope = match typed_tx {
        TypedTransaction::Legacy(tx) => TxEnvelope::Legacy(Signed::new_unchecked(tx, sig, tx_hash)),
        TypedTransaction::Eip2930(tx) => {
            TxEnvelope::Eip2930(Signed::new_unchecked(tx, sig, tx_hash))
        }
        TypedTransaction::Eip1559(tx) => {
            TxEnvelope::Eip1559(Signed::new_unchecked(tx, sig, tx_hash))
        }
        TypedTransaction::Eip4844(tx) => {
            TxEnvelope::Eip4844(Signed::new_unchecked(tx, sig, tx_hash))
        }
        TypedTransaction::Eip7702(tx) => {
            TxEnvelope::Eip7702(Signed::new_unchecked(tx, sig, tx_hash))
        }
    };

    // Encode signed transaction
    let signed_bytes = envelope.encoded_2718();

    let out = TransactionOutput {
        chain: "ethereum",
        operation: "transaction",
        address: format!("{}", signer.address()),
        signature: format!("0x{sig}"),
        signed_tx: format!("0x{}", hex::encode(&signed_bytes)),
        tx_hash: format!("{tx_hash}"),
    };
    output::render_transaction(&out, json)?;
    Ok(())
}

fn parse_b256(hex_str: &str) -> Result<B256, Box<dyn std::error::Error>> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "hash must be exactly 32 bytes")?;
    Ok(B256::from(arr))
}
