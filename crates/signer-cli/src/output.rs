#![allow(clippy::print_stdout)]
//! Structured output types and unified rendering.
//!
//! These types serve as the single source of truth for both JSON and
//! human-readable output. Chain-specific code builds these structs,
//! then calls the shared render functions.

use colored::Colorize;
use serde::Serialize;

/// Output for signing operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct SignOutput {
    pub chain: &'static str,
    pub operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Output for address/key-info operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AddressOutput {
    pub chain: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub public_key: String,
}

/// Structured error output for JSON mode.
#[derive(Debug, Serialize)]
pub struct ErrorOutput {
    pub error: String,
}

/// Render a signing result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_sign(out: &SignOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("      {} {}", "Chain".cyan().bold(), out.chain);
    println!("  {} {}", "Operation".cyan().bold(), out.operation);
    if let Some(ref addr) = out.address {
        println!("    {} {}", "Address".cyan().bold(), addr.green());
    }
    if let Some(ref msg) = out.message {
        println!("    {} {}", "Message".cyan().bold(), msg.dimmed());
    }
    println!("  {} {}", "Signature".cyan().bold(), out.signature);
    if let Some(rid) = out.recovery_id {
        println!("    {} {}", "Recovery".cyan().bold(), rid);
    }
    if let Some(ref pk) = out.public_key {
        println!(" {} {}", "Public Key".cyan().bold(), pk.dimmed());
    }
    println!();
    Ok(())
}

/// Render an address/key-info result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_address(out: &AddressOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("      {} {}", "Chain".cyan().bold(), out.chain);
    if let Some(ref addr) = out.address {
        println!("    {} {}", "Address".cyan().bold(), addr.green());
    }
    println!(" {} {}", "Public Key".cyan().bold(), out.public_key);
    println!();
    Ok(())
}

/// Serialize a value as pretty-printed JSON to stdout.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}
