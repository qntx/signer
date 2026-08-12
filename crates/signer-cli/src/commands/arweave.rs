//! Arweave ECDSA signing CLI commands.

use clap::{Args, Subcommand};
use signer_arweave::{SignDigest, Signer};

use super::key::load_secret_key;
use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "arweave";

/// Arweave ECDSA signing operations (format=2, recoverable secp256k1).
#[derive(Args)]
pub(crate) struct ArweaveCommand {
    #[command(subcommand)]
    command: ArweaveSubcommand,
}

#[derive(Subcommand)]
enum ArweaveSubcommand {
    /// Sign a raw 32-byte hash (recoverable ECDSA; use when digest is already SHA-256(deep-hash)).
    #[command(name = "sign-digest")]
    Digest {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// 32-byte hash in hex (with or without 0x prefix).
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign deep-hash output (or any message): SHA-256(msg) then recoverable ECDSA.
    ///
    /// Matches `secp256k1_nif:sign/2` / arweave-js ECDSA when `msg` is the
    /// 48-byte deep-hash preimage.
    #[command(name = "sign-payload")]
    Payload {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded deep-hash output (typically 48 bytes) or other message.
        #[arg(short = 'd', long)]
        data: String,
    },
    /// Show address and compressed public key for a private key.
    Address {
        /// Private key: hex, `-` for stdin, or `@path` (optional 0x).
        #[arg(short, long)]
        key: String,
    },
}

impl ArweaveCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            ArweaveSubcommand::Digest { key, hash } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let out = signer.sign_digest(&parse_hex32(&hash)?)?;
                // `message` is the caller-supplied digest hex (input), not a tx id.
                output::sign(CHAIN, "raw digest (recoverable ECDSA)")
                    .address(signer.address())
                    .public_key_bytes(&signer.public_key_bytes())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            ArweaveSubcommand::Payload { key, data } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                let msg = parse_hex(&data)?;
                let out = signer.sign_payload(&msg)?;
                // Tx id = Base64URL(SHA-256(sig65)); deterministic from `signature`.
                // Do not stuff it into `message` (that field is human input elsewhere).
                // `identity` carries recovered-owner encoding (not the empty JSON owner).
                output::sign(CHAIN, "payload SHA-256 + recoverable ECDSA")
                    .address(signer.address())
                    .identity(signer.owner())
                    .public_key_bytes(&signer.public_key_bytes())
                    .from_output(&out)
                    .render(json)
            }
            ArweaveSubcommand::Address { key } => {
                let signer = Signer::from_bytes(&load_secret_key(&key)?)?;
                // `address` = wallet id; `identity` = recovered-owner Base64URL(pk).
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .identity(signer.owner())
                    .render(json)
            }
        }
    }
}
