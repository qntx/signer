<!-- markdownlint-disable MD033 MD041 MD036 -->

# Signer

[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[ci-badge]: https://github.com/qntx/signer/actions/workflows/rust.yml/badge.svg
[ci-url]: https://github.com/qntx/signer/actions/workflows/rust.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**Multi-chain transaction signer built on mature cryptography libraries — zero hand-rolled crypto, and a batteries-included CLI.**

signer provides thin wrappers around battle-tested signing libraries ([alloy](https://docs.rs/alloy-signer-local) for EVM, [bitcoin](https://docs.rs/bitcoin) for BTC, [ed25519-dalek](https://docs.rs/ed25519-dalek) for Solana), exposing a unified API while delegating all cryptographic operations to upstream crates. All signers `Deref` to their underlying types for full API access, and private keys are zeroed on drop. Optional [kobe](https://github.com/qntx/kobe) integration enables seamless HD wallet bridging.

## Crates

| Crate                             |                                                                                                           | Description                                                           |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| **[`signer`](signer/)**           | [![crates.io][signer-crate]][signer-crate-url] [![docs.rs][signer-doc]][signer-doc-url]                   | Umbrella crate — re-exports all chain signers                         |
| **[`signer-btc`](signer-btc/)**   | [![crates.io][signer-btc-crate]][signer-btc-crate-url] [![docs.rs][signer-btc-doc]][signer-btc-doc-url]   | Bitcoin — ECDSA, Schnorr, PSBT, BIP-137 message signing               |
| **[`signer-evm`](signer-evm/)**   | [![crates.io][signer-evm-crate]][signer-evm-crate-url] [![docs.rs][signer-evm-doc]][signer-evm-doc-url]   | Ethereum / EVM — EIP-191, EIP-712, transaction signing                |
| **[`signer-svm`](signer-svm/)**   | [![crates.io][signer-svm-crate]][signer-svm-crate-url] [![docs.rs][signer-svm-doc]][signer-svm-doc-url]   | Solana / SVM — Ed25519 signing                                        |
| **[`signer-cli`](signer-cli/)**   | [![crates.io][signer-cli-crate]][signer-cli-crate-url]                                                    | CLI tool — sign, verify, and inspect keys across all supported chains |

[signer-crate]: https://img.shields.io/crates/v/signer.svg
[signer-crate-url]: https://crates.io/crates/signer
[signer-btc-crate]: https://img.shields.io/crates/v/signer-btc.svg
[signer-btc-crate-url]: https://crates.io/crates/signer-btc
[signer-evm-crate]: https://img.shields.io/crates/v/signer-evm.svg
[signer-evm-crate-url]: https://crates.io/crates/signer-evm
[signer-svm-crate]: https://img.shields.io/crates/v/signer-svm.svg
[signer-svm-crate-url]: https://crates.io/crates/signer-svm
[signer-cli-crate]: https://img.shields.io/crates/v/signer-cli.svg
[signer-cli-crate-url]: https://crates.io/crates/signer-cli
[signer-doc]: https://img.shields.io/docsrs/signer.svg
[signer-doc-url]: https://docs.rs/signer
[signer-btc-doc]: https://img.shields.io/docsrs/signer-btc.svg
[signer-btc-doc-url]: https://docs.rs/signer-btc
[signer-evm-doc]: https://img.shields.io/docsrs/signer-evm.svg
[signer-evm-doc-url]: https://docs.rs/signer-evm
[signer-svm-doc]: https://img.shields.io/docsrs/signer-svm.svg
[signer-svm-doc-url]: https://docs.rs/signer-svm

## Quick Start

### Install the CLI

**Shell** (macOS / Linux):

```sh
curl -fsSL https://sh.qntx.fun/signer | sh
```

**PowerShell** (Windows):

```powershell
irm https://sh.qntx.fun/signer/ps | iex
```

Or via Cargo:

```bash
cargo install signer-cli
```

### Sign an Ethereum Message (Library)

```rust
use signer_evm::{Signer, SignerSync};

let signer = Signer::random();
let signature = signer.sign_message_sync(b"hello")?;

println!("Address:   {}", signer.address());
println!("Signature: {signature}");
```

### Sign a Bitcoin Message (Library)

```rust
use signer_btc::{Signer, Network};

let signer = Signer::random(Network::Bitcoin);
let signature = signer.sign_message("Hello, Bitcoin!")?;
let address = signer.p2wpkh_address(Network::Bitcoin);
let valid = Signer::verify_message("Hello, Bitcoin!", &signature, &address, Network::Bitcoin)?;

println!("Address: {address}");
println!("Valid:   {valid}");
```

### Sign with Solana (Library)

```rust
use signer_svm::Signer;
use ed25519_dalek::Signer as _;

let signer = Signer::random();
let sig = signer.sign(b"hello solana");
signer.verify(b"hello solana", &sig)?;

println!("Address: {}", signer.address());
```

### Via Umbrella Crate

```rust
use signer::{evm, btc, svm};

let eth_signer = evm::Signer::random();
let btc_signer = btc::Signer::random(btc::Network::Bitcoin);
let sol_signer = svm::Signer::random();
```

### Kobe HD Wallet Integration

Enable the `kobe` feature to construct signers from [kobe](https://github.com/qntx/kobe) derived keys:

```rust
use kobe::Wallet;
use kobe_evm::Deriver;
use signer_evm::Signer;

let wallet = Wallet::from_mnemonic("abandon abandon ... about", None)?;
let deriver = Deriver::new(&wallet);
let derived = deriver.derive(0)?;

let signer = Signer::from_derived(&derived)?;
println!("Address: {}", signer.address());
```

## CLI Usage

The CLI uses `--json` for machine-readable output — ideal for agent and script consumption.

```text
signer [--json] <chain> <subcommand> [options]
```

### Chain subcommands and aliases

| Chain    | Primary | Aliases           |
| -------- | ------- | ----------------- |
| Bitcoin  | `btc`   | `bitcoin`         |
| Ethereum | `evm`   | `eth`, `ethereum` |
| Solana   | `svm`   | `sol`, `solana`   |

### Bitcoin

```bash
# BIP-137 message signing (default: Native SegWit)
signer btc sign-message --key "L1a..." --message "Hello, Bitcoin!"

# Sign with specific address type
signer btc sign-message --key "L1a..." --message "test" --address-type legacy

# Verify a signed message
signer btc verify-message --signature "H..." --message "Hello" --address "bc1q..."

# Raw ECDSA / Schnorr hash signing
signer btc sign-ecdsa   --key "L1a..." --hash "abcdef..."
signer btc sign-schnorr --key "L1a..." --hash "abcdef..."

# Sign a PSBT (base64 in → base64 out)
signer btc sign-psbt --key "L1a..." --psbt "cHNidP8B..."

# Show all address types for a key
signer btc address --key "L1a..."
```

### Ethereum

```bash
# EIP-191 personal_sign
signer evm sign-message --key "0xabc..." --message "Hello, Ethereum!"

# Raw hash signing
signer evm sign-hash --key "0xabc..." --hash "0xdef..."

# Sign a raw unsigned transaction (hex-encoded EIP-2718 bytes)
signer evm sign-transaction --key "0xabc..." --tx "0x02f8..."

# Verify a signed message
signer evm verify-message --signature "0x..." --message "Hello" --address "0x..."

# Show address and public key
signer evm address --key "0xabc..."
```

### Solana

```bash
# Ed25519 signing
signer svm sign --key "deadbeef..." --message "Hello, Solana!"

# Sign hex-encoded bytes (e.g., serialized transaction)
signer svm sign --key "deadbeef..." --message "0a0b0c..." --hex

# Verify a signature
signer svm verify --signature "abcdef..." --message "Hello" --pubkey "Base58Address..."

# Show address and public key
signer svm address --key "deadbeef..."
```

### JSON output

Pass `--json` **before** the chain subcommand. All output (including errors) becomes a single JSON object on stdout with no ANSI colors.

```bash
signer --json btc sign-message --key "L1a..." --message "test"
```

```json
{
  "chain": "bitcoin",
  "operation": "BIP-137 message",
  "address": "bc1q...",
  "signature": "H...",
  "message": "test"
}
```

Errors in JSON mode return exit code 1 with `{"error": "..."}`.

## Design

- **Zero hand-rolled crypto** — All signing delegated to audited upstream libraries
- **Thin wrappers** — `Deref` to underlying types (`PrivateKey`, `PrivateKeySigner`, `SigningKey`) for full API access
- **Memory safety** — Private keys zeroed on drop (`ZeroizeOnDrop` / `non_secure_erase`)
- **Multi-chain** — EVM, Bitcoin, Solana from one workspace
- **Kobe integration** — Optional HD wallet bridging via feature flag
- **CSPRNG** — Random generation via OS-provided entropy ([`getrandom`](https://docs.rs/getrandom))
- **Linting** — `pedantic` + `nursery` + `correctness` (deny) — strict Clippy across workspace
- **Edition** — Rust **2024**

## Signing Methods

### EVM (`signer-evm`)

| Method                                       | Standard                  |
| -------------------------------------------- | ------------------------- |
| `sign_hash_sync` / `sign_hash`               | Raw 32-byte hash          |
| `sign_message_sync` / `sign_message`         | EIP-191 personal_sign     |
| `sign_typed_data_sync` / `sign_typed_data`   | EIP-712 (via alloy)       |
| `sign_transaction_sync` / `sign_transaction` | All EVM transaction types |

### Bitcoin (`signer-btc`)

| Method                                    | Standard                                             |
| ----------------------------------------- | ---------------------------------------------------- |
| `sign_ecdsa`                              | secp256k1 ECDSA                                      |
| `sign_schnorr`                            | BIP-340 Schnorr (Taproot)                            |
| `sign_message` / `sign_message_with_type` | BIP-137 (P2PKH, P2SH-P2WPKH, P2WPKH)                 |
| `verify_message`                          | BIP-137 verification                                 |
| `sign_psbt`                               | PSBT (with Bip32Derivation support)                  |
| `p2wpkh_address` / `p2tr_address` / ...   | All address types (P2WPKH, P2TR, P2SH-P2WPKH, P2PKH) |

### Solana (`signer-svm`)

| Method                     | Standard                             |
| -------------------------- | ------------------------------------ |
| `sign` (via Deref)         | Ed25519 signature                    |
| `verify`                   | Ed25519 verification                 |
| `sign_transaction_message` | Solana transaction signing           |
| `keypair_base58`           | Phantom / Backpack / Solflare format |

## Feature Flags

| Crate       | Feature | Description                                    |
| ----------- | ------- | ---------------------------------------------- |
| `signer`    | `btc`   | Enable Bitcoin signer (default)                |
| `signer`    | `evm`   | Enable EVM signer (default)                    |
| `signer`    | `svm`   | Enable Solana signer (default)                 |
| `signer`    | `kobe`  | Enable kobe HD wallet bridging for all chains  |
| `signer-*`  | `kobe`  | Enable kobe bridging for a specific chain      |

## Security

This library has **not** been independently audited. Use at your own risk.

- All cryptographic operations are delegated to upstream libraries
- Private keys are zeroed from memory on drop (EVM/SVM via `ZeroizeOnDrop`, BTC via `non_secure_erase`)
- Review the security advisories of upstream dependencies

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QNTX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QNTX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx-banner.svg" /></a>

<!--prettier-ignore-->
Code is law. We write both.

</div>
