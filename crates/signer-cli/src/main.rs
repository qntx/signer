#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items,
    missing_docs,
    reason = "CLI binary intentionally uses stdout/stderr and does not require doc comments"
)]
//! Signer — multi-chain transaction signing CLI.

mod commands;
pub mod output;

use clap::Parser;
use commands::{Cli, Commands};

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        if json {
            if output::print_json(&output::ErrorOutput {
                error: e.to_string(),
            })
            .is_err()
            {
                eprintln!("Error: {e}");
            }
        } else {
            eprintln!("Error: {e}");
        }
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    match cli.command {
        Commands::Aptos(cmd) => cmd.execute(json)?,
        Commands::Evm(cmd) => cmd.execute(json)?,
        Commands::Btc(cmd) => cmd.execute(json)?,
        Commands::Svm(cmd) => cmd.execute(json)?,
        Commands::Cosmos(cmd) => cmd.execute(json)?,
        Commands::Tron(cmd) => cmd.execute(json)?,
        Commands::Sui(cmd) => cmd.execute(json)?,
        Commands::Ton(cmd) => cmd.execute(json)?,
        Commands::Fil(cmd) => cmd.execute(json)?,
        Commands::Spark(cmd) => cmd.execute(json)?,
        Commands::Xrpl(cmd) => cmd.execute(json)?,
    }
    Ok(())
}
