# Changelog

All notable changes to this workspace are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.0]

Breaking release that splits off-chain message signing into a dedicated [`SignMessage`] capability trait, fixes long-standing correctness gaps in Bitcoin / Spark message signing, strictifies signature verification, and upgrades the [`Sign::Error`] bound to the standard `core::error::Error` contract. All chain crates ship a fallible `try_random` constructor; the panicking `random` is now a thin wrapper.

### Fixed

- **Bitcoin / Spark `sign_message` now emit BIP-137 headers.** `signer_btc::Signer::sign_message` and `signer_spark::Signer::sign_message` default to the compressed-P2PKH header byte (`v = 31 | 32`, i.e. `27 + recid + 4`). Previously the `v` byte was the raw recovery id (`0 | 1`), which Bitcoin Core's `verifymessage`, Electrum, and every BIP-137 verifier reject. See [BIP-137].
- **EIP-712 `uintN` / `intN` now range-check the encoded value.** Passing `uint8 = 256` or `int8 = 128` silently truncated before; both are rejected now. Negative decimals are parsed with full `int256` precision (no more `u128` truncation at `|x| > 2^127`).
- Cosmos `sign_message` previously produced a bare `SHA-256(message) + ECDSA` signature that no wallet in the Cosmos ecosystem can verify. The method has been removed; callers sign a canonical `StdSignDoc` (proto direct or amino JSON, including ADR-036) through `sign_transaction`.

### Added

- `signer_primitives::SignMessage` capability trait + `SignMessageExt` flat-bytes helper. Implemented by every chain with a documented off-chain scheme (EVM, BTC, Spark, Tron, Filecoin, SVM, Sui, TON, Aptos, Nostr). Not implemented by XRPL (no canonical spec) or Cosmos (ADR-036 is a separate `SignDoc` pipeline) — callers see the capability gap at the type level instead of a runtime `Err`.
- `signer_btc::BitcoinMessageAddressType` enum + `signer_btc::Signer::sign_message_with` for choosing the BIP-137 header byte (P2PKH uncompressed / compressed / SegWit-P2SH / SegWit-Bech32).
- `try_random` constructors on every primitive (`Secp256k1Signer`, `Ed25519Signer`, `SchnorrSigner`) and every chain `Signer`. Returns `Result<Self, SignError>` on entropy failure instead of panicking; the `delegate_*_ctors!` macros also expose `try_random` on the tuple newtypes.
- `Secp256k1Signer::verify_prehash_recoverable(&[u8; 32], &[u8; 65])` and `verify_prehash_any(&[u8; 32], &[u8])` — the former strict, the latter a length-dispatching helper used by chain-level `verify_hash` wrappers.
- `signer_svm::Signer::splice_signature(&[u8], &[u8; 64])` — low-level helper that powers `encode_signed_transaction`.

### Changed

- **`Sign` trait is now two methods: `sign_hash` + `sign_transaction`.** `sign_message` moved to the opt-in `SignMessage` trait; chains that implement it continue to expose `signer.sign_message(msg)` as before, but downstream code must import `SignMessage` (or use `signer::*`) to call it.
- **`Sign::Error` now requires `core::error::Error`** (stable since Rust 1.81) on top of `From<SignError> + Send + Sync + 'static`. Implicit `Debug + Display` bounds are gone — they follow from `Error`. All workspace errors already satisfy the new bound because they use `thiserror`.
- **`Secp256k1Signer::verify_prehash` is now strict 64-byte compact only.** For recoverable input use `verify_prehash_recoverable`; for either shape use the new `verify_prehash_any`. Chain-level `Signer::verify_hash(&[u8; 32], &[u8])` now dispatches through `verify_prehash_any` and therefore keeps accepting both wire shapes.
- `signer_svm::Signer::encode_signed_transaction` now takes `&SignOutput` (matching `EncodeSignedTransaction`); callers that still want to splice a raw `ed25519_dalek::Signature` use `Signer::splice_signature` on its bytes.
- `random()` on every primitive and chain `Signer` is now a thin panicking wrapper over `try_random()`. Semantics are unchanged for std consumers; embedded / WASM targets should prefer the fallible form.
- `SignOutput::Ecdsa.v` docs expanded to cover every producer across the workspace (EVM EIP-191 `27|28`, Tron `27|28`, BTC / Spark BIP-137 `31|32`, all `sign_hash` / `sign_transaction` `0|1`).
- `signer_cosmos` documents ADR-036 and points users at `sign_transaction(sign_doc_bytes)`.
- CLI: `signer cosmos sign-message` removed. Build the ADR-036 `StdSignDoc` externally (or via `kobe cosmos`) and feed it to `signer cosmos sign-tx`.
- Workspace bumped to `3.0.0`.

### Removed

- `Sign::sign_message` (moved to `SignMessage::sign_message`).
- `SignExt::sign_message_bytes` (now on `SignMessageExt`).
- `signer_cosmos::Signer::sign_message` and `signer_xrpl::Signer::sign_message` — both were runtime `Err` sentinels in spirit; with capability traits the gap is now compile-time.
- `signer_svm::Signer::encode_signed_transaction(tx_bytes, &ed25519_dalek::Signature)` inherent signature — see `splice_signature` for the native-signature path.

### Migration

```rust
// 2.x — sign_message on every chain, callable through `Sign`.
use signer_evm::{Sign, Signer};
let signer = Signer::from_hex(key)?;
let out = signer.sign_message(b"hi")?;

// 3.x — same call site, import SignMessage.
use signer_evm::{SignMessage, Signer};           // or `use signer_evm::*;`
let signer = Signer::from_hex(key)?;
let out = signer.sign_message(b"hi")?;
```

```rust
// 2.x — BTC sign_message returned v = 0 | 1 (raw parity), incompatible
// with Bitcoin Core's verifymessage.
let out = btc_signer.sign_message(b"hi")?;       // v ∈ {0, 1}

// 3.x — v is now 31 | 32 (compressed P2PKH per BIP-137); call
// `sign_message_with` to target a different address type.
use signer_btc::{BitcoinMessageAddressType, SignMessage, Signer};
let out = btc_signer.sign_message(b"hi")?;                             // 31 | 32
let out = btc_signer.sign_message_with(BitcoinMessageAddressType::SegwitBech32, b"hi")?; // 39 | 40
```

```rust
// 2.x — Cosmos sign_message was a bare SHA-256 + ECDSA with no wire format.
let sig = cosmos_signer.sign_message(b"hello")?; // unusable

// 3.x — build a canonical StdSignDoc (e.g. ADR-036) and feed it to sign_transaction.
let sign_doc = build_adr036_sign_doc("cosmos1…", b"hello");
let sig = cosmos_signer.sign_transaction(sign_doc.as_bytes())?;
```

```rust
// 2.x — random() panicked on entropy failure.
let s = Signer::random();

// 3.x — try_random() surfaces the failure; random() still works for std code.
let s = Signer::try_random()?;
```

[BIP-137]: https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
[`SignMessage`]: https://docs.rs/signer-primitives

## [2.0.0]

Breaking release that tightens the API surface, fixes a signature-verification bug in XRPL, and removes more than 2000 lines of duplicated boilerplate across the thirteen chain crates.

### Fixed

- **XRPL `verify_hash` now verifies the DER signatures produced by `sign_hash` / `sign_transaction`.** Previously `verify_hash` only accepted the 64/65-byte compact wire form, so the canonical `sign → verify` round-trip was broken for XRPL alone. See `Secp256k1Signer::verify_prehash_der` and `signer_xrpl::Signer::verify_hash`.

### Added

- `signer_primitives::EncodeSignedTransaction` trait — opt-in capability implemented only by chains whose wire format can be assembled from `(unsigned_tx, signature)` (currently EVM typed-tx RLP and Solana signature-slot splicing).
- `signer_primitives::ExtractSignableBytes` trait — opt-in capability implemented only by chains whose wire format interleaves signed payload and non-signed metadata (currently Solana's compact-u16 header).
- `Secp256k1Signer::verify_prehash_der` for DER-format verification.
- Public macros `signer_primitives::delegate_secp256k1_ctors!`, `delegate_ed25519_ctors!`, `delegate_schnorr_ctors!` that expand to `from_bytes` / `from_hex` / `random` on a tuple-newtype signer wrapper. Each macro has a single-argument form (`delegate_*_ctors!(MyError)`) for crates that carry a chain-specific error wrapper.

### Changed

- **Chain signers are now tuple newtypes.** `pub struct Signer(Secp256k1Signer);` in every chain crate, with `#[derive(Debug)]` inherited from the inner type's `[REDACTED]` debug impl. Constructors (`from_bytes`, `from_hex`, `random`) are generated by the new `delegate_*_ctors!` macros rather than being hand-written in each crate.
- **`Sign` trait is now minimal and mandatory.** It exposes only the three signing entry points (`sign_hash`, `sign_message`, `sign_transaction`). The optional `extract_signable_bytes` / `encode_signed_transaction` methods moved to the new dedicated traits above — types never carry "not implemented" default-impl lies.
- **Chain crates no longer hand-write `impl Sign`.** All chain-specific hashing and prefixing live directly inside the `Sign` trait impl instead of being split between duplicated inherent methods and a forwarding trait impl. Users need `use signer_<chain>::{Sign, Signer};` (or `use signer_<chain>::*`) to call `signer.sign_message(...)`, matching idiomatic Rust (e.g. `std::io::Read`).
- **`SignError` is re-exported directly from `signer_primitives` on ten chain crates** (BTC / Cosmos / EVM / Fil / Spark / Sui / TON / Tron / XRPL / Aptos). `signer-svm` and `signer-nostr` keep a `#[non_exhaustive]` wrapper enum with a transparent `Core(#[from] signer_primitives::SignError)` variant plus chain-specific variants (`InvalidKeypair`, `Bech32`), following the upstream `kobe` pattern.
- `signer-xrpl::Signer::verify_hash` now takes a DER-encoded signature (previously 64/65-byte compact).
- Workspace cryptography dependencies bumped: `sha2 0.10 → 0.11.0`, `sha3 0.10 → 0.11.0` — keeps `signer` and `kobe` on a single dependency version when both are in the same binary.
- `signer-primitives` no longer forwards an `alloc` feature from chain crates; the previous flag was a no-op because the crate unconditionally requires `alloc` (`String`/`Vec` imports in `SignError` / trait output types).
- Every chain crate re-exports `Sign`, `SignExt`, `SignError`, `SignOutput` at the top level so downstream users can `use signer_btc::*;` to bring both the `Signer` type and the trait API into scope at once.

### Removed

- `Sign::encode_signed_transaction` and `Sign::extract_signable_bytes` default methods. The "returns `Err("not implemented")` for most chains" pattern was a type-system lie; capabilities now live in dedicated traits that are only implemented where they make sense.
- Hand-written `SignError` enums + `From<signer_primitives::SignError>` impls in ten chain crates (≈370 lines of boilerplate replaced by a single `pub use`).
- Per-chain hand-written `from_bytes` / `from_hex` / `random` constructors (≈200 lines replaced by `delegate_*_ctors!` macro invocations).
- Per-chain hand-written `Debug` impls (`[REDACTED]` now inherits through the inner primitive's debug impl).
- Inherent `sign_hash` / `sign_message` / `sign_transaction` methods on every chain `Signer` — users access the same methods via the `Sign` trait, which is now the single source of truth for signing logic.
- Per-chain `pub use ed25519_dalek::{self, Signature}` re-exports. Only `Signature` is re-exported now; chain crates do not leak the whole `ed25519_dalek` crate.
- `thiserror` dependency from ten chain crates (no longer needed after the `SignError` re-export consolidation).

### Migration

```rust
// 1.0 — separate inherent + trait methods, delegated
use signer_btc::Signer;
let signer = Signer::from_hex(hex)?;
let out = signer.sign_message(b"hi")?;     // inherent method

// 2.0 — single source of truth: trait-only; bring both into scope
use signer_btc::{Sign, Signer};
let signer = Signer::from_hex(hex)?;
let out = signer.sign_message(b"hi")?;     // trait method (same call site)
```

```rust
// 1.0 — Sign trait exposed encode_signed_transaction with a
//       default Err("not implemented") — false positive for most chains.
let encoded = signer.encode_signed_transaction(&unsigned, &sig)?;

// 2.0 — EncodeSignedTransaction is now a separate opt-in trait; only
//       EVM and SVM implement it.
use signer_evm::{EncodeSignedTransaction, Signer};
let encoded = signer.encode_signed_transaction(&unsigned, &sig)?;
```

```rust
// 1.0 — chain crates each had their own SignError struct, forcing conversions.
use signer_btc::SignError as BtcErr;
use signer_evm::SignError as EvmErr;
fn convert(e: EvmErr) -> BtcErr { BtcErr::InvalidKey(e.to_string()) }  // lossy!

// 2.0 — both re-export signer_primitives::SignError directly; no wrappers.
use signer_btc::SignError;            // == signer_primitives::SignError
use signer_evm::SignError as AlsoCore; // same type
```

```rust
// 1.0 — XRPL verify_hash was broken: sign produced DER, verify rejected DER.
let sig = signer.sign_hash(&digest)?;
signer.verify_hash(&digest, &sig.to_bytes())?; // always InvalidSignature!

// 2.0 — sign + verify round-trip works.
let sig = signer.sign_hash(&digest)?;
signer.verify_hash(&digest, &sig.to_bytes())?; // OK
```

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
