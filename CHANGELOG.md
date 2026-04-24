# Changelog

All notable changes to this workspace are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0]

First major release since `1.0.0`. A workspace-wide rearchitecture that reframes the [`Sign`] trait as a **primitive-level** surface (only `sign_hash` is required), promotes every chain's transaction signing to an **inherent method** documented in its own right, collapses `SignError` to a single type across the workspace, fixes several address-derivation bugs, upgrades to `kobe 2.0`, and synchronises `signer-cli` with the library's new semantics.

### Design judgement

- **`Sign::sign_transaction` was a pseudo-abstraction.** Every chain interprets the `tx_bytes` argument under a different canonical format (EVM RLP, BTC sighash preimage, Cosmos `SignDoc`, BCS `TransactionData`, serialized Nostr event JSON, …) and hashes it with a different algorithm. Generic code `fn any<S: Sign>(s: &S, tx: &[u8])` was almost always wrong; the trait method contributed zero real constraint. v2.0 therefore removes it from the trait and re-publishes it as a documented inherent method on each chain's `Signer`.
- **`Sign::sign_hash` is now explicitly primitive-level, not protocol-level.** For ECDSA / Schnorr chains the 32 bytes is a prehash; for Ed25519 chains the 32 bytes is signed **as the entire message** (EdDSA does not accept prehash). Sui and Aptos `sign_hash` output is **not on-chain verifiable** without intent / domain framing — the docstring says so explicitly; use `Signer::sign_transaction` for on-chain correctness.
- **`SignExt` / `SignMessageExt` were sugar-only blanket traits.** `.sign_hash(h)?.to_bytes()` is one line; the blanket traits added IDE-autocomplete noise without real value. Deleted.

### Fixed

- **`signer-spark::Signer::address()` now emits the canonical bech32m `spark1…` address** (`bech32m(hrp="spark", RIPEMD160(SHA-256(compressed_pubkey)))`), matching `kobe-spark`'s derivation. Previously returned a Bitcoin-compatible `1…` P2PKH address that Spark L2 nodes do not accept.
- **`signer-ton::Signer::address()` renamed to `identity()`.** TON wallet addresses depend on the deployed contract code and workchain ID, so a receivable address cannot be derived from the key alone. The method now honestly returns the signer **identity** (hex Ed25519 public key) rather than misleadingly calling it an address. Use `kobe-ton` for full wallet-address derivation.
- **`signer-xrpl::Signer::verify_hash` renamed to `verify_hash_der`.** XRPL's on-wire signature format is DER, distinguishing this method from the compact-signature `verify_hash` on other secp256k1 chains. Same function, more honest name.

### Added

- **`signer-cosmos::Signer::address_with_hrp(hrp: &str)`** — fallible bech32 encoding with a caller-chosen HRP. Lets the same signing key produce `cosmos1…`, `osmo1…`, `juno1…`, `terra1…`, `secret1…`, `kava1…`, etc. The zero-arg `address()` remains as the `"cosmos"`-defaulting convenience.
- **`SignOutput::with_v_offset(u8)`** — chainable builder for `Ecdsa` `v` byte rewriting, used to implement EIP-191 (`+27`), TRON (`+27`), and all four BIP-137 offsets (27/31/35/39). Non-`Ecdsa` variants pass through unchanged.
- **`signer::prelude`** — a glob-importable module that re-exports every capability trait plus [`SignOutput`] and [`SignError`] in one `use signer::prelude::*;`.
- **Workspace MSRV pinned to `1.83`** (`rust-version = "1.83"` in `[workspace.package]`) — the minimum for `core::error::Error` + inline-const expressions used across the trait contracts.

### Changed

- **`Sign` trait is now `{ type Error; fn sign_hash }` only.** `sign_transaction` is removed; each chain crate exposes `Signer::sign_transaction` as a documented inherent method (call sites like `signer.sign_transaction(..)` keep working — only fully-qualified paths like `Sign::sign_transaction(&signer, ..)` must be rewritten).
- **`SignError` unified across the workspace.** Deleted the local wrapper enums in `signer-svm` (`InvalidKeypair`) and `signer-nostr` (`Bech32`); their variants fold into `signer_primitives::SignError::InvalidKey(String)` with descriptive prefixes (`"keypair: …"`, `"nip-19 bech32: …"`). The entire workspace now has exactly one `SignError` type.
- **`kobe-*` dependencies upgraded to `2.0`.** `kobe 2.0` introduces a `DerivedPublicKey` enum (unified across all chains) replacing per-chain `Vec<u8>` public-key fields. `signer-*::from_derived(&kobe_*::DerivedAccount)` signatures are unchanged; only test helpers that manually construct `DerivedAccount` need the new `DerivedPublicKey` variant (`Secp256k1Compressed` / `Secp256k1Uncompressed` / `Ed25519` / `Secp256k1XOnly`).
- **Spark `Cargo.toml` swaps `bs58` for `bech32`** as the address encoder. `ripemd` + `sha2` remain for the hash160 payload.
- **CLI `CHAIN` constants** unified to the short subcommand names — `"ethereum"` → `"evm"`, `"bitcoin"` → `"btc"`, `"filecoin"` → `"fil"`, `"solana"` → `"svm"`. JSON `"chain"` fields are now symmetric across all 12 commands.
- **CLI `signer ton address` subcommand renamed to `signer ton identity`** to match the library method.
- **`signer` umbrella crate** adds `EncodeSignedTransaction` / `ExtractSignableBytes` to the top-level re-exports (previously only available via `signer::primitives`).
- Workspace version `3.0.0` (internal, unreleased) → `2.0.0` (first public major since v1.0.0). `kobe-*` workspace deps `1.1` → `2`.

### Removed

- **`Sign::sign_transaction`** — moved to inherent method on each chain's `Signer`.
- **`SignExt` and `SignMessageExt`** blanket extension traits — `.sign_hash(h)?.to_bytes()` / `.sign_message(m)?.to_bytes()` replace `.sign_hash_bytes(h)?` / `.sign_message_bytes(m)?`.
- **`signer-svm::SignError`** (local wrapper) — folded into `signer_primitives::SignError`.
- **`signer-nostr::SignError`** (local wrapper) — folded into `signer_primitives::SignError`.
- `thiserror` as a direct dependency of `signer-svm` / `signer-nostr` (no longer needed after the error merge).

### Migration

```rust
// 1.0 — Sign trait had sign_transaction as a trait method.
use signer_evm::{Sign, Signer};
let out = Sign::sign_transaction(&signer, &unsigned_rlp)?;

// 2.0 — sign_transaction is an inherent method; method call syntax unchanged.
use signer_evm::Signer;
let out = signer.sign_transaction(&unsigned_rlp)?;
```

```rust
// 1.0 — SignExt / SignMessageExt gave you `*_bytes` helpers.
use signer_evm::{Sign, SignExt, Signer};
let bytes = signer.sign_hash_bytes(&digest)?;

// 2.0 — call to_bytes() on the SignOutput instead.
use signer_evm::{Sign, Signer};
let bytes = signer.sign_hash(&digest)?.to_bytes();
```

```rust
// 1.0 — Spark returned a Bitcoin-format 1… address (not accepted by Spark nodes).
let addr = spark_signer.address(); // e.g. "1FB3WSwtExGLQUmNp4AQF66tAwAQp6igW3"

// 2.0 — Spark returns the canonical spark1… bech32m address.
let addr = spark_signer.address(); // e.g. "spark1nduq8yy8h4nr7g9vuuglzklqatmaquq9g2keef"
```

```rust
// 1.0 — TON misleadingly called the hex public key an "address".
let addr = ton_signer.address();

// 2.0 — The method is called identity() to reflect reality.
let id = ton_signer.identity();
```

```rust
// 1.0 — Cosmos was hard-coded to HRP "cosmos".
let addr = cosmos_signer.address();

// 2.0 — same default, plus multi-HRP support for other Cosmos-SDK chains.
let cosmos = cosmos_signer.address();
let osmo = cosmos_signer.address_with_hrp("osmo")?;
let juno = cosmos_signer.address_with_hrp("juno")?;
```

```rust
// 1.0 — XRPL verify took DER via a method named verify_hash (ambiguous).
signer.verify_hash(&digest, &der_sig)?;

// 2.0 — The method is renamed to make the DER expectation explicit.
signer.verify_hash_der(&digest, &der_sig)?;
```

```rust
// 1.0 — SVM / Nostr had local wrapper SignError enums.
use signer_svm::SignError;
match err {
    SignError::Core(core) => …,
    SignError::InvalidKeypair(msg) => …,
}

// 2.0 — single SignError across the workspace.
use signer_svm::SignError; // == signer_primitives::SignError
match err {
    SignError::InvalidKey(msg) => …, // keypair failures fold into InvalidKey
    SignError::InvalidTransaction(msg) => …,
    …
}
```

[`Sign`]: https://docs.rs/signer-primitives
[`SignOutput`]: https://docs.rs/signer-primitives
[`SignError`]: https://docs.rs/signer-primitives

## [1.0.0]

First stable release. **Breaking across every crate** — the companion `kobe` library also cuts its 1.0. See the migration notes below.

### Added

- `SignOutput` is now a discriminated `enum` with variants covering every wire format in the workspace: `Ecdsa { signature, v }`, `EcdsaDer(Vec<u8>)`, `Ed25519([u8; 64])`, `Ed25519WithPubkey { signature, public_key }`, and `Schnorr { signature, xonly_public_key }`.
- `SignOutput::{to_bytes, to_hex, public_key, v}` accessors.
- Every chain `Signer` now exposes **canonical inherent** `sign_hash`, `sign_message`, `sign_transaction` and `public_key_hex` methods. The `Sign` trait implementation delegates to them so users do not have to `use signer_primitives::Sign` for everyday signing.
- secp256k1 chain signers additionally expose an inherent `verify_hash(&[u8; 32], &[u8]) -> Result<()>` for symmetric verification.
- `SignExt::sign_message_bytes` convenience method.
- `Secp256k1Signer::verify_prehash` for in-crate round-trip testing.
- `Ed25519Signer::{sign_output, sign_output_with_pubkey}` helpers that wrap raw signatures into the unified enum.
- Full publishing metadata (`readme`, `keywords`, `categories`) on every crate so crates.io pages render correctly.

### Changed

- `Sign::sign_hash` now takes `&[u8; 32]` instead of `&[u8]`. Ragged byte slices are rejected at compile time.
- Every chain crate's `Signer::sign_hash` and inherent siblings also take `&[u8; 32]`.
- `Ed25519Signer::from_bytes` now returns `Result<Self, SignError>` for symmetry with `Secp256k1Signer` / `SchnorrSigner`; it never fails in practice.
- Every chain `Signer::verify` takes `&[u8]` for the signature argument (previously `&ed25519_dalek::Signature` or `&k256::…`).
- `signer-btc::Signer::from_derived` now accepts `&kobe_btc::BtcAccount`; `signer-svm::Signer::from_derived` accepts `&kobe_svm::SvmAccount`.
- All 12 chain crates' `SignError` are hand-written enums with an explicit `From<signer_primitives::SignError>` impl.
- `signer-evm`: `sign_message` / `sign_typed_data` now return `SignOutput::Ecdsa` with `v ∈ {27, 28}` (EIP-191 semantics baked into the variant). `sign_hash` / `sign_transaction` keep the raw `{0, 1}` `v` byte and are wired into `encode_signed_transaction` accordingly.
- `signer-tron::sign_message` bumps `v` by 27 in the same style to match EVM wallet expectations.
- `signer-evm::encode_signed_transaction` is now a single inherent function taking `&SignOutput` (previously two overlapping signatures existed — one free-standing, one on the `Sign` trait).
- `SignOutput::Ecdsa.recovery_id` renamed to `v`. The byte carries either the raw parity (0 | 1) or the EIP-191 wire encoding (27 | 28) depending on the call site; the new name is intentionally neutral. The accessor `SignOutput::recovery_id()` was renamed to `SignOutput::v()`.

### Removed

- `signer_primitives::Verify` trait. Verification is chain-specific (each chain has a different message → digest transform), so it is exposed as inherent `verify` / `verify_hash` methods on every `Signer` instead of a generic trait. See `crates/signer-primitives/src/lib.rs` module docs.
- The `define_sign_error!` and `impl_sign_delegate!` macros — replaced by explicit per-chain implementations. This eliminates hidden boilerplate and makes each chain's `Sign` impl self-documenting.
- `signer_primitives::__private` module (leftover macro plumbing).
- `hex::FromHexError` leakage through `SignError` variants (all hex decode errors are now folded into `InvalidKey(String)`).
- Redundant chain-specific signing aliases whose behaviour is already covered by the canonical inherent methods:
  - `signer-aptos::Signer::sign_transaction_bcs` (use `sign_transaction`)
  - `signer-sui::Signer::{sign_transaction_intent, sign_message_intent}` (use `sign_transaction` / `sign_message`)
  - `signer-svm::Signer::sign_transaction_message` (use `sign_transaction` or `sign_raw`).

### Migration

```rust
// 0.8 — struct access
let out = signer.sign_hash(hash_bytes)?;
assert_eq!(out.signature.len(), 65);
if let Some(rid) = out.recovery_id { … }

// 1.0 — tight types, enum access
let digest: [u8; 32] = Sha256::digest(input).into();
let out = signer.sign_hash(&digest)?;     // inherent, no `use Sign` required
let wire = out.to_bytes();                 // Vec<u8>, 65 / 64 / DER by variant
if let Some(v) = out.v() { … }              // accessor, not field
```

```rust
// 0.8 — per-chain sig type
let sig = signer.sign_raw(msg);
signer.verify(msg, &sig)?;

// 1.0 — &[u8] everywhere
let sig = signer.sign_raw(msg);
signer.verify(msg, sig.to_bytes().as_slice())?;
// …or via the trait:
let out = <Signer as Sign>::sign_message(&signer, msg)?;
signer.verify(msg, &out.to_bytes())?;
```

```rust
// 0.8 — EVM: manual +27 on top of sign_hash
let mut out = signer.sign_hash(&hash)?;
out.signature[64] += 27;

// 1.0 — sign_message already returns v = 27 | 28
let out = signer.sign_message(msg)?;        // SignOutput::Ecdsa { … v: 27|28 }
let wire = out.to_bytes();                  // 65 bytes, last byte is 27 | 28
```

```rust
// 1.0 — unified verify on every chain
let out = signer.sign_message(msg)?;
signer.verify(msg, &out.to_bytes())?;       // inherent, same signature on all 12 chains

// secp256k1 chains also expose verify_hash for pre-hashed digests:
let digest: [u8; 32] = Sha256::digest(msg).into();
let out = signer.sign_hash(&digest)?;
signer.verify_hash(&digest, &out.to_bytes())?;
```
