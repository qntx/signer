//! TON signing CLI commands.

use clap::{Args, Subcommand};
use signer_ton::Signer;

use super::parse_hex;
use crate::output::{self, CliResult};

const CHAIN: &str = "ton";

/// TON signing operations.
#[derive(Args)]
pub(crate) struct TonCommand {
    #[command(subcommand)]
    command: TonSubcommand,
}

#[derive(Subcommand)]
enum TonSubcommand {
    /// Sign arbitrary preimage bytes with raw Ed25519.
    ///
    /// TON has no canonical personal-message envelope (TON Connect
    /// `ton_proof`, `ton-proof-item-v2/`, and wallet cell-hash all pick
    /// different preimages), so the signer simply applies raw Ed25519 to
    /// the bytes the caller supplies. Use this subcommand for both tx
    /// preimages (e.g. `cell_hash`) and hand-framed off-chain messages.
    SignTx {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
        /// Hex-encoded preimage bytes (`cell_hash`, `ton_proof`, …).
        #[arg(short, long)]
        tx: String,
    },
    /// Show signer identity (hex public key) for a private key.
    ///
    /// TON wallet addresses depend on the deployed contract code and
    /// workchain ID, so the signer only exposes its identity (public
    /// key hex). Use `kobe-ton` for full wallet-address derivation.
    Identity {
        /// Private key in hex (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
    },
}

impl TonCommand {
    pub(crate) fn execute(self, json: bool) -> CliResult {
        match self.command {
            TonSubcommand::SignTx { key, tx } => {
                let signer = Signer::from_hex(&key)?;
                let out = signer.sign_transaction(&parse_hex(&tx)?)?;
                output::sign(CHAIN, "raw Ed25519")
                    .identity(signer.identity())
                    .from_output(&out)
                    .public_key_hex(signer.public_key_hex())
                    .render(json)
            }
            TonSubcommand::Identity { key } => {
                let signer = Signer::from_hex(&key)?;
                output::address(CHAIN, &signer.public_key_bytes())
                    .identity(signer.identity())
                    .render(json)
            }
        }
    }
}
