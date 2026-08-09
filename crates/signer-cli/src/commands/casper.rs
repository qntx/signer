//! Casper Network signing CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use signer_casper::{KeyAlgo, Signer};

use super::key::load_secret_key;
use super::parse_hex32;
use crate::output::{self, CliResult};

const CHAIN: &str = "casper";

/// Casper signing operations.
#[derive(Args)]
pub(crate) struct CasperCommand {
    #[command(subcommand)]
    command: CasperSubcommand,
}

#[derive(Clone, Copy, Default, ValueEnum)]
enum CliKeyAlgo {
    #[default]
    #[value(alias = "secp", alias = "ecdsa")]
    Secp256k1,
    #[value(alias = "ed", alias = "eddsa")]
    Ed25519,
}

impl From<CliKeyAlgo> for KeyAlgo {
    fn from(v: CliKeyAlgo) -> Self {
        match v {
            CliKeyAlgo::Secp256k1 => Self::Secp256k1,
            CliKeyAlgo::Ed25519 => Self::Ed25519,
        }
    }
}

#[derive(Subcommand)]
enum CasperSubcommand {
    /// Sign a 32-byte digest (e.g. BLAKE2b-256 of a serialized deploy).
    #[command(name = "sign-digest")]
    Digest {
        /// Private key: hex, `-` for stdin, or `@path`.
        #[arg(short, long)]
        key: String,
        /// 32-byte digest in hex.
        #[arg(short = 'x', long)]
        hash: String,
        /// Signature algorithm.
        #[arg(long, value_enum, default_value_t = CliKeyAlgo::Secp256k1)]
        algo: CliKeyAlgo,
    },
    /// Sign arbitrary message bytes (ed25519: full message; secp: requires 32-byte digest).
    SignMessage {
        /// Private key: hex, `-` for stdin, or `@path`.
        #[arg(short, long)]
        key: String,
        /// Message (UTF-8).
        #[arg(short, long)]
        message: String,
        /// Signature algorithm.
        #[arg(long, value_enum, default_value_t = CliKeyAlgo::Secp256k1)]
        algo: CliKeyAlgo,
    },
    /// Show tagged public key for a private key.
    Address {
        /// Private key: hex, `-` for stdin, or `@path`.
        #[arg(short, long)]
        key: String,
        /// Signature algorithm.
        #[arg(long, value_enum, default_value_t = CliKeyAlgo::Secp256k1)]
        algo: CliKeyAlgo,
    },
}

impl CasperCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            CasperSubcommand::Digest { key, hash, algo } => {
                let signer = load_signer(&key, algo.into())?;
                let digest = parse_hex32(&hash)?;
                let out = signer.sign_deploy_hash(&digest)?;
                output::sign(CHAIN, "deploy digest")
                    .from_output(&out)
                    .message(hash)
                    .public_key_hex(signer.tagged_public_key_hex())
                    .render(json)
            }
            CasperSubcommand::SignMessage { key, message, algo } => {
                let signer = load_signer(&key, algo.into())?;
                let out = signer.sign_bytes(message.as_bytes())?;
                output::sign(CHAIN, "message bytes")
                    .from_output(&out)
                    .message(message)
                    .public_key_hex(signer.tagged_public_key_hex())
                    .render(json)
            }
            CasperSubcommand::Address { key, algo } => {
                let signer = load_signer(&key, algo.into())?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.tagged_public_key_hex())
                    .render(json)
            }
        }
    }
}

fn load_signer(key: &str, algo: KeyAlgo) -> Result<Signer, Box<dyn std::error::Error>> {
    Ok(Signer::from_bytes_with_algo(&load_secret_key(key)?, algo)?)
}
