//! Nostr signing CLI commands (BIP-340 Schnorr, NIP-01/NIP-19).

use clap::{Args, Subcommand};
use sha2::{Digest as _, Sha256};
use signer_nostr::{SignError, Signer};

use super::parse_hex;
use crate::output::{self, CliResult};

const CHAIN: &str = "nostr";

/// Nostr signing operations.
#[derive(Args)]
pub(crate) struct NostrCommand {
    #[command(subcommand)]
    command: NostrSubcommand,
}

#[derive(Subcommand)]
enum NostrSubcommand {
    /// Sign a 32-byte NIP-01 `event.id` (hex).
    SignHash {
        /// Private key in hex or `nsec1…` bech32.
        #[arg(short, long)]
        key: String,
        /// 32-byte event id in hex (with or without `0x`).
        #[arg(short = 'x', long, alias = "hash")]
        event_id: String,
    },
    /// Sign arbitrary UTF-8 text with BIP-340 Schnorr (raw message).
    SignMessage {
        /// Private key in hex or `nsec1…` bech32.
        #[arg(short, long)]
        key: String,
        /// Message text to sign.
        #[arg(short, long)]
        message: String,
    },
    /// Sign a serialized NIP-01 event: computes `sha256(event)` then signs.
    ///
    /// Input is the canonical NIP-01 serialization
    /// `[0, pubkey, created_at, kind, tags, content]` as hex-encoded UTF-8 JSON.
    SignTx {
        /// Private key in hex or `nsec1…` bech32.
        #[arg(short, long)]
        key: String,
        /// Serialized event bytes in hex (with or without `0x`).
        #[arg(short, long)]
        tx: String,
    },
    /// Show the Nostr `npub`, `nsec`, and x-only public key for a private key.
    Address {
        /// Private key in hex or `nsec1…` bech32.
        #[arg(short, long)]
        key: String,
    },
}

impl NostrCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            NostrSubcommand::SignHash { key, event_id } => {
                let signer = load_signer(&key)?;
                let digest = super::parse_hex32(&event_id)?;
                let out = signer.sign_hash(&digest)?;
                output::sign(CHAIN, "event id (BIP-340 Schnorr)")
                    .address(signer.address())
                    .from_output(&out)
                    .message(event_id)
                    .render(json)
            }
            NostrSubcommand::SignMessage { key, message } => {
                let signer = load_signer(&key)?;
                let out = signer.sign_message(message.as_bytes())?;
                output::sign(CHAIN, "raw message (BIP-340 Schnorr)")
                    .address(signer.address())
                    .from_output(&out)
                    .message(message)
                    .render(json)
            }
            NostrSubcommand::SignTx { key, tx } => {
                let signer = load_signer(&key)?;
                let serialized = parse_hex(&tx)?;
                let event_id: [u8; 32] = Sha256::digest(&serialized).into();
                let out = signer.sign_hash(&event_id)?;
                output::sign(CHAIN, "NIP-01 serialized event")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hex::encode(event_id))
                    .render(json)
            }
            NostrSubcommand::Address { key } => {
                let signer = load_signer(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}

/// Accept either a hex-encoded private key or an `nsec1…` bech32 string.
fn load_signer(key: &str) -> Result<Signer, SignError> {
    if key.starts_with("nsec1") {
        Signer::from_nsec(key)
    } else {
        Signer::from_hex(key)
    }
}
