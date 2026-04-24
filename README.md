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

**`no_std`-compatible Rust toolkit for multi-chain transaction signing — twelve networks, zero hand-written cryptography, cross-implementation KATs.**

Signer composes thin wrappers around [`k256`](https://docs.rs/k256) (secp256k1 ECDSA and BIP-340 Schnorr) and [`ed25519-dalek`](https://docs.rs/ed25519-dalek) into a capability-driven trait surface for Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, and Nostr. Every library crate builds under `no_std + alloc`; private keys wrap in `ZeroizeOnDrop`, `Debug` prints `[REDACTED]`, and every chain-specific output is pinned against the relevant RFC / BIP / EIP vectors plus an independent [`@noble/curves`](https://github.com/paulmillr/noble-curves) reference.

> **See also** [`kobe`](https://github.com/qntx/kobe) — the companion HD-wallet derivation toolkit that feeds `Signer::from_derived` with BIP-39 / BIP-32 / SLIP-10 accounts.

<p align="center">
  <img src="demo.gif" alt="Signer CLI Demo"/>
</p>

## Quick Start

### Install the CLI

**Shell** (macOS / Linux):

```bash
curl -fsSL https://sh.qntx.fun/signer | sh
```

**PowerShell** (Windows):

```powershell
irm https://sh.qntx.fun/signer/ps | iex
```

### CLI Usage

```bash
signer evm    sign-message -k "0x4c0883a6.."    -m "Hello, Ethereum!"   # EIP-191
signer btc    sign-message -k "4c0883a6..."     -m "Hello, Bitcoin!"    # BIP-137
signer sui    sign-tx      -k "9d61b19d..."     -t "0000..."            # BLAKE2b intent
signer cosmos sign-tx      -k "4c0883a6..."     -t "<SignDoc hex>"      # ADR-036 input
signer xrpl   sign-tx      -k "4c0883a6..."     -t "<tx fields hex>"    # STX\0 + SHA-512/2 + DER
signer nostr  sign-hash    -k "nsec10allq0g..." -x "5e6ea04f..."        # NIP-19 accepted
signer evm    address      -k "0x4c0883a6..."                           # EIP-55 checksummed

signer --json evm sign-message -k "0x4c0883a6..." -m "test"             # agent-friendly
```

### Library Usage

```rust
use signer_evm::{Sign as _, SignMessage as _, Signer};

let signer = Signer::from_hex(
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
)?;

let raw = signer.sign_hash(&[0x42u8; 32])?;  // v = 0 | 1  (raw parity, feeds RLP)
let msg = signer.sign_message(b"hello")?;    // v = 27 | 28 (EIP-191 wire)

println!("Address:   {}", signer.address());
println!("Signature: {}", msg.to_hex());
```

`SignOutput` is a discriminated enum (`Ecdsa { signature, v }` / `EcdsaDer(Vec<u8>)` / `Ed25519([u8; 64])` / `Ed25519WithPubkey { signature, public_key }` / `Schnorr { signature, xonly_public_key }`) — callers pattern-match on the variant that matches their chain's wire format instead of juggling `Option` metadata.

Chains without a canonical off-chain scheme deliberately do not implement `SignMessage`; callers build the domain-specific preimage themselves and pass it through the chain's inherent `Signer::sign_transaction` method (not a trait method — transaction-bytes semantics differ irreconcilably across chains, so `Sign` only contains `sign_hash`):

```rust
// Cosmos: build the ADR-036 `StdSignDoc` externally (e.g. via `kobe cosmos`)
// and hand its canonical bytes to `sign_transaction`.
use signer_cosmos::Signer;

let signer    = Signer::from_hex("4c0883a6...")?;
let sign_doc  = build_adr036_sign_doc("cosmos1...", b"hello");
let signature = signer.sign_transaction(sign_doc.as_bytes())?;
```

Bitcoin message signing picks the BIP-137 header byte for the target address type; the default matches Bitcoin Core's `signmessage`:

```rust
use signer_btc::{BitcoinMessageAddressType, SignMessage as _, Signer};

let signer = Signer::from_hex("4c0883a6...")?;

// Default: compressed-P2PKH header (v = 31 | 32), Bitcoin Core compatible.
let compressed = signer.sign_message(b"Hi")?;

// Explicit: native SegWit (bech32) header, v = 39 | 40.
let bech32 = signer.sign_message_with(
    BitcoinMessageAddressType::SegwitBech32,
    b"Hi",
)?;
```

### Kobe HD Wallet Integration

Enable the `kobe` feature to construct signers from [kobe](https://github.com/qntx/kobe) derived accounts:

```rust
use kobe::Wallet;
use kobe_evm::Deriver;
use signer_evm::Signer;

let wallet  = Wallet::from_mnemonic("abandon abandon ... about", None)?;
let account = Deriver::new(&wallet).derive(0)?;
let signer  = Signer::from_derived(&account)?;
println!("Address: {}", signer.address());
```

## Supported Chains

| Chain      | Crate           | Curve           | Sighash                     | Off-chain message                    |
| ---------- | --------------- | --------------- | --------------------------- | ------------------------------------ |
| Bitcoin    | `signer-btc`    | secp256k1       | double-SHA-256              | BIP-137 (four header variants)       |
| Ethereum   | `signer-evm`    | secp256k1       | Keccak-256                  | EIP-191, EIP-712                     |
| Cosmos     | `signer-cosmos` | secp256k1       | SHA-256                     | ADR-036 `StdSignDoc` (external)      |
| Tron       | `signer-tron`   | secp256k1       | SHA-256 (`raw_data` txID)   | TRON prefix, wire `v = 27/28`        |
| Filecoin   | `signer-fil`    | secp256k1       | BLAKE2b-256 over CID bytes  | BLAKE2b-256                          |
| Spark      | `signer-spark`  | secp256k1       | double-SHA-256              | BIP-137 (compressed P2PKH)           |
| TON        | `signer-ton`    | Ed25519         | raw                         | raw (caller builds the preimage)     |
| XRP Ledger | `signer-xrpl`   | secp256k1       | `STX\0` + SHA-512-half, DER | none (no canonical spec)             |
| Solana     | `signer-svm`    | Ed25519         | raw                         | raw Ed25519                          |
| Sui        | `signer-sui`    | Ed25519         | BLAKE2b-256 intent + BCS    | `PersonalMessage` intent             |
| Aptos      | `signer-aptos`  | Ed25519         | SHA3-256 domain + BCS       | raw Ed25519                          |
| Nostr      | `signer-nostr`  | Schnorr BIP-340 | SHA-256 (NIP-01 event id)   | raw BIP-340 (caller frames it)       |

## Design

- **12 chains** — Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Nostr
- **Zero hand-written cryptography** — `k256` for secp256k1 ECDSA and BIP-340 Schnorr, `ed25519-dalek` for Ed25519; hashing via `sha2` / `sha3` / `blake2` / `ripemd`; encoding via `bech32` / `bs58`
- **Capability-split traits** — mandatory `Sign::sign_hash` as the primitive-level interface (32 bytes in, `SignOutput` out) plus opt-in `SignMessage`, `ExtractSignableBytes`, `EncodeSignedTransaction`; each chain's protocol-level `sign_transaction` is an inherent method on its `Signer` (transaction-bytes semantics differ irreconcilably across chains, so a trait would be a false abstraction). Capability gaps surface at compile time, not a runtime `Err`.
- **Type-safe digests** — `sign_hash` takes `&[u8; 32]`; `verify_prehash*` dispatches strictly on wire length (64-byte compact, 65-byte recoverable, DER)
- **Discriminated `SignOutput`** — `Ecdsa { signature, v }` / `EcdsaDer(Vec<u8>)` / `Ed25519([u8; 64])` / `Ed25519WithPubkey` / `Schnorr`, with `v` byte semantics fully documented per producer (raw parity, EIP-191, BIP-137 four ranges)
- **Cross-implementation KATs** — RFC 6979 deterministic ECDSA, RFC 8032 Test Vectors 1–3, BIP-340 `test-vectors.csv` indices 0–3/5/6, EIP-712 "Mail" example (`be609aee…30957bd2`), BIP-137 four-variant header, plus `ecrecover` / `verifymessage` / intent-digest round-trips — no self-confirming dumps
- **Standard error contract** — `Sign::Error: core::error::Error + From<SignError> + Send + Sync + 'static`, interoperating with `?`, `Box<dyn Error>`, and `thiserror` out of the box
- **Fallible entropy** — every signer exposes `try_random() -> Result<Self, SignError>`; the panicking `random()` is a thin wrapper for std environments
- **`no_std` + `alloc`** — every library crate compiles on `thumbv7m-none-eabi` under CI; embedded / WASM ready
- **Security hardened** — `ZeroizeOnDrop`, `Debug` redacted to `[REDACTED]`, `Clone` intentionally removed, `Send + Sync` required
- **Kobe integration** — optional HD wallet bridging via the `kobe` feature flag (feeds `Signer::from_derived` with [kobe](https://github.com/qntx/kobe) derived accounts)
- **Strict linting** — Clippy `pedantic` + `nursery` + `correctness` (deny), `rust_2018_idioms` deny, zero warnings on nightly

## Crates

See **[`crates/README.md`](crates/README.md)** for the full crate table, dependency graph, and feature flag reference.

## Security

This library has **not** been independently audited. Use at your own risk.

- Private keys wrapped in [`zeroize`](https://docs.rs/zeroize) — wiped from memory on drop
- `Debug` impl prints `[REDACTED]` — no key material reaches logs
- `Clone` intentionally removed — prevents uncontrolled key duplication
- Random generation uses OS-provided CSPRNG via [`getrandom`](https://docs.rs/getrandom); prefer `try_random()` on embedded / WASM targets where entropy can legitimately fail
- `Sign` and `SignMessage` require `Send + Sync` — safe to share across async executors
- No key material is logged or persisted by the workspace

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
