#![allow(
    clippy::print_stdout,
    reason = "output module intentionally prints to stdout"
)]
//! Structured output types and unified rendering.
//!
//! Exposes two fluent builders — [`sign`] and [`address`] — that each
//! chain command uses to emit a result in JSON or colored-text form.

use colored::Colorize;
use serde::Serialize;

/// Convenience error alias for CLI result rendering.
pub type CliResult = Result<(), Box<dyn std::error::Error>>;

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
    pub v: Option<u8>,
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

/// Start building a sign-result output.
pub const fn sign(chain: &'static str, operation: &'static str) -> SignBuilder {
    SignBuilder {
        chain,
        operation,
        address: None,
        signature: String::new(),
        v: None,
        public_key: None,
        message: None,
    }
}

/// Start building an address-result output.
pub fn address(chain: &'static str, public_key_bytes: &[u8]) -> AddressBuilder {
    AddressBuilder {
        chain,
        address: None,
        public_key: hex::encode(public_key_bytes),
    }
}

/// Fluent builder for [`SignOutput`].
#[derive(Debug)]
#[must_use]
pub struct SignBuilder {
    chain: &'static str,
    operation: &'static str,
    address: Option<String>,
    signature: String,
    v: Option<u8>,
    public_key: Option<String>,
    message: Option<String>,
}

impl SignBuilder {
    /// Attach the signer's chain-native address.
    pub fn address(mut self, addr: impl Into<String>) -> Self {
        self.address = Some(addr.into());
        self
    }

    /// Attach the compressed/raw public key bytes (hex-encoded automatically).
    pub fn public_key_bytes(mut self, pk: &[u8]) -> Self {
        self.public_key = Some(hex::encode(pk));
        self
    }

    /// Attach an already hex-encoded public key.
    pub fn public_key_hex(mut self, pk: String) -> Self {
        self.public_key = Some(pk);
        self
    }

    /// Attach the original human-readable message.
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Populate signature / `v` byte / public key from a
    /// [`signer_primitives::SignOutput`].
    ///
    /// Works for every variant; ECDSA emits the full 65-byte wire form,
    /// Ed25519 emits 64 bytes, Schnorr / Ed25519-with-pubkey also propagate
    /// the attached public key.
    pub fn from_output(mut self, out: &signer_primitives::SignOutput) -> Self {
        self.signature = out.to_hex();
        self.v = out.v();
        if let Some(pk) = out.public_key() {
            self.public_key = Some(hex::encode(pk));
        }
        self
    }

    /// Render to stdout (JSON or colored text).
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn render(self, json: bool) -> CliResult {
        let out = SignOutput {
            chain: self.chain,
            operation: self.operation,
            address: self.address,
            signature: self.signature,
            v: self.v,
            public_key: self.public_key,
            message: self.message,
        };
        render_sign(&out, json)
    }
}

/// Fluent builder for [`AddressOutput`].
#[derive(Debug)]
#[must_use]
pub struct AddressBuilder {
    chain: &'static str,
    address: Option<String>,
    public_key: String,
}

impl AddressBuilder {
    /// Attach the signer's chain-native address.
    pub fn address(mut self, addr: impl Into<String>) -> Self {
        self.address = Some(addr.into());
        self
    }

    /// Render to stdout (JSON or colored text).
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn render(self, json: bool) -> CliResult {
        let out = AddressOutput {
            chain: self.chain,
            address: self.address,
            public_key: self.public_key,
        };
        render_address(&out, json)
    }
}

#[rustfmt::skip]
fn render_sign(out: &SignOutput, json: bool) -> CliResult {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("      {}       {}", "Chain".cyan().bold(), out.chain);
    println!("      {}   {}", "Operation".cyan().bold(), out.operation);
    if let Some(ref addr) = out.address {
        println!("      {}     {}", "Address".cyan().bold(), addr.green());
    }
    if let Some(ref msg) = out.message {
        println!("      {}     {}", "Message".cyan().bold(), msg.dimmed());
    }
    println!("      {}   {}", "Signature".cyan().bold(), out.signature);
    if let Some(v) = out.v {
        println!("      {}           {}", "v".cyan().bold(), v);
    }
    if let Some(ref pk) = out.public_key {
        println!("      {}  {}", "Public Key".cyan().bold(), pk.dimmed());
    }
    println!();
    Ok(())
}

#[rustfmt::skip]
fn render_address(out: &AddressOutput, json: bool) -> CliResult {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("      {}       {}", "Chain".cyan().bold(), out.chain);
    if let Some(ref addr) = out.address {
        println!("      {}     {}", "Address".cyan().bold(), addr.green());
    }
    println!("      {}  {}", "Public Key".cyan().bold(), out.public_key);
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
