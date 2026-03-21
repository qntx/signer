#![allow(clippy::print_stdout)]
//! Structured output types and unified rendering.
//!
//! All types implement [`Serialize`] so they serve both JSON and
//! human-readable output from the same source of truth.

use colored::Colorize;
use serde::Serialize;

/// Output for signing operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct SignOutput {
    /// Blockchain identifier.
    pub chain: &'static str,
    /// Signing operation type.
    pub operation: &'static str,
    /// Signer's address (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The produced signature.
    pub signature: String,
    /// The signed message or hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Output for verification operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct VerifyOutput {
    /// Blockchain identifier.
    pub chain: &'static str,
    /// Whether the signature is valid.
    pub valid: bool,
    /// Address used for verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The verified message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Output for address/key-info operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AddressOutput {
    /// Blockchain identifier.
    pub chain: &'static str,
    /// Network name (mainnet/testnet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<&'static str>,
    /// Primary address.
    pub address: String,
    /// Public key in chain-native format.
    pub public_key: String,
    /// All address variants (e.g. P2WPKH, P2TR for BTC).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<NamedAddress>,
}

/// A named address variant (e.g. P2WPKH, P2TR).
#[derive(Debug, Serialize)]
pub struct NamedAddress {
    /// Address type name.
    pub kind: &'static str,
    /// The address string.
    pub address: String,
}

/// Output for PSBT signing operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct PsbtOutput {
    /// Blockchain identifier.
    pub chain: &'static str,
    /// Signing operation type.
    pub operation: &'static str,
    /// The signed PSBT in base64 format.
    pub psbt: String,
}

/// Output for transaction signing operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct TransactionOutput {
    /// Blockchain identifier.
    pub chain: &'static str,
    /// Signing operation type.
    pub operation: &'static str,
    /// Signer's address.
    pub address: String,
    /// The produced signature.
    pub signature: String,
    /// The signed transaction in hex format (ready to broadcast).
    pub signed_tx: String,
    /// The transaction hash.
    pub tx_hash: String,
}

/// Structured error output for JSON mode.
#[derive(Debug, Serialize)]
pub struct ErrorOutput {
    /// Error message.
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
    println!("    {} {}", "Operation".cyan().bold(), out.operation);
    if let Some(ref addr) = out.address {
        println!("      {} {}", "Address".cyan().bold(), addr.green());
    }
    if let Some(ref msg) = out.message {
        println!("      {} {}", "Message".cyan().bold(), msg.dimmed());
    }
    println!("    {} {}", "Signature".cyan().bold(), out.signature);
    println!();
    Ok(())
}

/// Render a verification result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_verify(out: &VerifyOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    let status = if out.valid {
        "VALID".green().bold().to_string()
    } else {
        "INVALID".red().bold().to_string()
    };
    println!("       {} {}", "Valid".cyan().bold(), status);
    if let Some(ref addr) = out.address {
        println!("     {} {}", "Address".cyan().bold(), addr);
    }
    if let Some(ref msg) = out.message {
        println!("     {} {}", "Message".cyan().bold(), msg.dimmed());
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
    if let Some(network) = out.network {
        println!("      {} {}", "Network".cyan().bold(), network);
    }
    println!("      {} {}", "Address".cyan().bold(), out.address.green());
    println!("   {} {}", "Public Key".cyan().bold(), out.public_key.dimmed());
    for named in &out.addresses {
        println!("  {}   {}", format!("{:>10}", named.kind).cyan().bold(), named.address);
    }
    println!();
    Ok(())
}

/// Render a PSBT signing result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_psbt(out: &PsbtOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("    {} {}", "Operation".cyan().bold(), out.operation);
    println!("         {} {}", "PSBT".cyan().bold(), out.psbt);
    println!();
    Ok(())
}

/// Render a transaction signing result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_transaction(out: &TransactionOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("    {} {}", "Operation".cyan().bold(), out.operation);
    println!("      {} {}", "Address".cyan().bold(), out.address.green());
    println!("    {} {}", "Signature".cyan().bold(), out.signature);
    println!("      {} {}", "Tx Hash".cyan().bold(), out.tx_hash.green());
    println!("    {} {}", "Signed Tx".cyan().bold(), out.signed_tx);
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
