#![allow(clippy::print_stdout, clippy::print_stderr)]
//! Signer — Multi-chain transaction signing CLI tool.

mod commands;
pub mod output;

use clap::Parser;
use commands::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        if json {
            let err = output::ErrorOutput {
                error: e.to_string(),
            };
            let _ = output::print_json(&err);
        } else {
            eprintln!("Error: {e}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    match cli.command {
        Commands::Btc(cmd) => cmd.execute(json)?,
        Commands::Evm(cmd) => cmd.execute(json)?,
        Commands::Svm(cmd) => cmd.execute(json)?,
    }
    Ok(())
}
