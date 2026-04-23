//! Cosmos signing CLI commands.

use clap::{Args, Subcommand};
use signer_cosmos::{Sign, Signer};

use super::{parse_hex, parse_hex32};
use crate::output::{self, CliResult};

const CHAIN: &str = "cosmos";

/// Cosmos signing operations.
#[derive(Args)]
pub(crate) struct CosmosCommand {
    #[command(subcommand)]
    command: CosmosSubcommand,
}

#[derive(Subcommand)]
enum CosmosSubcommand {
    /// Sign a raw 32-byte hash.
    SignHash {
        #[arg(short, long)]
        key: String,
        #[arg(short = 'x', long)]
        hash: String,
    },
    /// Sign a Cosmos SDK `SignDoc` (proto direct mode or amino JSON,
    /// hex-encoded). The bytes are SHA-256'd and signed with secp256k1.
    ///
    /// For off-chain message signing use ADR-036: build the `StdSignDoc`
    /// externally (or with `kobe cosmos adr036-doc`) and feed the canonical
    /// bytes into this subcommand.
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

impl CosmosCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            CosmosSubcommand::SignHash { key, hash } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_hash(&parse_hex32(&hash)?)?;
                output::sign(CHAIN, "raw hash")
                    .address(signer.address())
                    .from_output(&out)
                    .message(hash)
                    .render(json)
            }
            CosmosSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "transaction")
                    .address(signer.address())
                    .from_output(&out)
                    .render(json)
            }
            CosmosSubcommand::Address { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .address(signer.address())
                    .render(json)
            }
        }
    }
}
