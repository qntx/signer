<!-- markdownlint-disable MD033 MD041 MD036 -->

# Signer

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[crates-badge]: https://img.shields.io/crates/v/signer.svg
[crates-url]: https://crates.io/crates/signer
[docs-badge]: https://img.shields.io/docsrs/signer.svg
[docs-url]: https://docs.rs/signer
[ci-badge]: https://github.com/qntx/signer/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/qntx/signer/actions/workflows/ci.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**Modular, `no_std`-compatible Rust toolkit for multi-chain transaction signing — 12 chains, zero hand-written cryptography, cross-implementation KATs.**

Signer provides thin, secure wrappers around battle-tested cryptographic libraries ([k256](https://docs.rs/k256) for secp256k1 ECDSA and BIP-340 Schnorr, [ed25519-dalek](https://docs.rs/ed25519-dalek) for Ed25519) and exposes a capability-driven trait surface across Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Aptos, and Nostr. Every library crate compiles under `no_std + alloc`, zeroizes sensitive material on drop, and is asserted byte-for-byte against an independent `@noble/curves` + `@noble/hashes` JavaScript reference.

<p align="center">
  <img src="demo.gif" alt="Signer CLI Demo"/>
</p>

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

### CLI Usage

```bash
# Ethereum — EIP-191 personal_sign (v = 27 | 28)
signer evm sign-message -k "0x4c0883a6..." -m "Hello, Ethereum!"

# Bitcoin — BIP-137 message signing (compressed-P2PKH header, v = 31 | 32)
signer btc sign-message -k "4c0883a6..." -m "Hello, Bitcoin!"

# Solana — Ed25519 raw
signer svm sign -k "9d61b19d..." -m "Hello, Solana!"

# Sui — BLAKE2b intent signing
signer sui sign-tx -k "9d61b19d..." -t "0000..."

# Cosmos — ADR-036 canonical SignDoc bytes (no `sign-message` subcommand:
# build the StdSignDoc externally, e.g. with `kobe cosmos`, then feed it here)
signer cosmos sign-tx -k "4c0883a6..." -t "<hex of canonical SignDoc>"

# XRP Ledger — STX\0 prefix + SHA-512/2 + DER
signer xrpl sign-tx -k "4c0883a6..." -t "<hex of unsigned tx fields>"

# Nostr — BIP-340 Schnorr, accepts hex or NIP-19 nsec
signer nostr sign-hash -k "nsec10allq0g..." -x "5e6ea04f..."
signer nostr address  -k "7f7ff03d..."   # prints npub1… and x-only pubkey

# Show address / public key
signer evm address -k "0x4c0883a6..."

# JSON output (for scripts / agents)
signer --json evm sign-message -k "0x4c0883a6..." -m "test"
```

### Library Usage

The signing surface is split across two traits so capability gaps are
visible at the type level:

- [`Sign`](https://docs.rs/signer-primitives/latest/signer_primitives/trait.Sign.html)
  — mandatory, exposes `sign_hash(&[u8; 32])` and `sign_transaction(&[u8])`
  on every chain.
- [`SignMessage`](https://docs.rs/signer-primitives/latest/signer_primitives/trait.SignMessage.html)
  — opt-in. Implemented by chains with a standardised off-chain message
  scheme (EVM, BTC, Spark, Tron, Filecoin, SVM, Sui, TON, Aptos, Nostr);
  deliberately **not** implemented by XRPL (no canonical spec) or Cosmos
  (defers to ADR-036, which needs a pre-built `StdSignDoc`).

`SignOutput` is a discriminated enum whose variants (`Ecdsa`, `EcdsaDer`,
`Ed25519`, `Ed25519WithPubkey`, `Schnorr`) carry each chain's native wire
format — callers pattern-match instead of juggling `Option` metadata.
Address derivation, `verify_hash`, and `public_key_{bytes,hex}` are
inherent methods on every chain's `Signer`.

```rust
use signer_evm::{Sign as _, SignMessage as _, Signer};

let signer = Signer::from_hex(
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
)?;

let digest = [0x42u8; 32];
let raw    = signer.sign_hash(&digest)?;       // v = 0 | 1 (raw parity)
let eip191 = signer.sign_message(b"hello")?;   // v = 27 | 28 (EIP-191 header)

println!("Address:   {}", signer.address());
println!("Signature: {}", eip191.to_hex());    // 65-byte r || s || v hex
if let Some(v) = eip191.v() { println!("v: {v}"); }
```

```rust
// BIP-137 Bitcoin message signing — default is compressed-P2PKH (v = 31 | 32);
// other address types select their own header via `sign_message_with`.
use signer_btc::{BitcoinMessageAddressType, SignMessage as _, Signer};

let signer = Signer::from_hex("4c0883a6...")?;
let default = signer.sign_message(b"Hello, Bitcoin!")?;                // v = 31 | 32
let bech32  = signer.sign_message_with(
    BitcoinMessageAddressType::SegwitBech32,
    b"Hello, Bitcoin!",
)?;                                                                     // v = 39 | 40
```

```rust
use signer_svm::{SignMessage as _, Signer};

let signer = Signer::try_random()?;                     // fallible: surfaces entropy failure
let out    = signer.sign_message(b"hello solana")?;     // SignOutput::Ed25519([u8; 64])
signer.verify(b"hello solana", &out.to_bytes())?;       // inherent verify

println!("Address: {}", signer.address());
```

```rust
// Cosmos does NOT implement SignMessage: off-chain message signing goes
// through ADR-036, which requires a pre-built StdSignDoc.
use signer_cosmos::{Sign as _, Signer};

let signer    = Signer::from_hex("4c0883a6...")?;
let sign_doc  = build_adr036_sign_doc("cosmos1…", b"hello");   // user / kobe builds this
let signature = signer.sign_transaction(sign_doc.as_bytes())?;
```

### Kobe HD Wallet Integration

Enable the `kobe` feature to construct signers from
[kobe](https://github.com/qntx/kobe) 1.x derived keys:

```rust
use kobe::Wallet;
use kobe_evm::Deriver;
use signer_evm::Signer;

let wallet  = Wallet::from_mnemonic("abandon abandon ... about", None)?;
let account = Deriver::new(&wallet).derive(0)?;
let signer  = Signer::from_derived(&account)?;
println!("Address: {}", signer.address());
```

For chains with newtype-wrapped accounts (Bitcoin / Solana), pass the
chain-specific account directly:

```rust
// Bitcoin: kobe_btc::BtcAccount wraps DerivedAccount + WIF / address type
let account = kobe_btc::Deriver::new(&wallet, kobe_btc::Network::Mainnet)?.derive(0)?;
let signer  = signer_btc::Signer::from_derived(&account)?;
```

## Design

- **12 chains** — Ethereum, Bitcoin, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Aptos, Nostr.
- **Zero hand-rolled crypto** — secp256k1 ECDSA and BIP-340 Schnorr via [k256](https://docs.rs/k256), Ed25519 via [ed25519-dalek](https://docs.rs/ed25519-dalek). Hashing is outsourced to `sha2` / `sha3` / `blake2` / `ripemd`; address encoding to [`bech32`](https://docs.rs/bech32) / `bs58`.
- **Capability-split traits** — mandatory `Sign` (`sign_hash` + `sign_transaction`) plus three opt-in capabilities (`SignMessage`, `EncodeSignedTransaction`, `ExtractSignableBytes`) so chains without a canonical off-chain scheme surface the gap at compile time instead of a runtime `Err`.
- **Type-safe digests** — `sign_hash` takes `&[u8; 32]`; ragged byte slices are rejected at compile time. `Secp256k1Signer::verify_prehash` is strict 64-byte compact; `verify_prehash_recoverable` is strict 65-byte; `verify_prehash_any` does length dispatch for chain-level wrappers.
- **Discriminated `SignOutput`** — `Ecdsa { signature, v }` / `EcdsaDer(Vec<u8>)` / `Ed25519([u8; 64])` / `Ed25519WithPubkey { signature, public_key }` / `Schnorr { signature, xonly_public_key }`. The `v` byte is fully documented per producer (raw parity `0 | 1`, EIP-191 `27 | 28`, BIP-137 `27..=42`).
- **BIP-137 compliance** — Bitcoin and Spark `sign_message` emit the compressed-P2PKH header byte (`v = 31 | 32`) directly consumable by Bitcoin Core `verifymessage`, Electrum, and every BIP-137 verifier. `BitcoinMessageAddressType` + `sign_message_with` unlock the SegWit-P2SH and bech32 header variants when needed.
- **Standard error contract** — `Sign::Error: core::error::Error + From<SignError> + Send + Sync + 'static`, so signers interoperate with `?`, `Box<dyn Error>`, and `thiserror` out of the box.
- **Fallible entropy** — every primitive and chain `Signer` exposes `try_random() -> Result<Self, SignError>`; the panicking `random()` is a thin wrapper for std environments.
- **`no_std` + `alloc`** — Every library crate compiles on `thumbv7m-none-eabi` under CI; embedded / WASM ready.
- **Security hardened** — `ZeroizeOnDrop`, `Debug` output redacted to `[REDACTED]`, `Clone` intentionally removed, `Send + Sync` required.
- **Kobe integration** — Optional HD wallet bridging via the `kobe` feature flag ([kobe](https://github.com/qntx/kobe) 1.x derived accounts).
- **Cross-implementation KATs** — Every chain crate's test suite asserts its Rust output byte-for-byte against an independent `@noble/curves` + `@noble/hashes` + `@scure/base` JavaScript reference (generator at [`tests/goldens/`](tests/goldens/README.md)). Tests are real protocol-equivalence checks, not self-confirming dumps.
- **Strict linting** — Clippy `pedantic` + `nursery` + `correctness` (deny), `rust_2018_idioms` deny, `rust_2024_compatibility` warn, zero warnings on nightly.

## Crates

See **[`crates/README.md`](crates/README.md)** for the full crate table, dependency graph, and feature flag reference.

## Testing

- `cargo test --workspace --all-features` runs the full suite — every chain crate is a Known Answer Test suite asserting byte-for-byte equality with [`@noble/curves`](https://github.com/paulmillr/noble-curves) / [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) / [`@scure/base`](https://github.com/paulmillr/scure-base).
- Cross-cutting sanity (constructor validation, curve-order rejection, `verify_prehash*` dispatch, `SignOutput` wire layout, `Debug [REDACTED]`) lives once in `signer-primitives::tests`; per-chain suites pin only the chain-specific spec (domain separator, address encoding, BIP-137 header, intent prefix, …).
- KAT generator: [`tests/goldens/generate.mjs`](tests/goldens/README.md). Outputs are `.gitignored`; the hex constants are inlined into each `tests.rs`.

## Security

This library has **not** been independently audited. Use at your own risk.

- Private keys wrapped in [`ZeroizeOnDrop`](https://docs.rs/zeroize) — zeroed from memory on drop.
- `Debug` impl outputs `[REDACTED]` — no key material leaks to logs.
- `Clone` intentionally removed — prevents uncontrolled key copies.
- Random generation uses OS-provided CSPRNG via [`getrandom`](https://docs.rs/getrandom); prefer `try_random()` on embedded / WASM targets where entropy can legitimately fail.
- `Sign` + `SignMessage` require `Send + Sync` — safe for concurrent use and async executors.
- No key material is logged or persisted by the workspace.

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
