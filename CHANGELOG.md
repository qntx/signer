# Changelog

All notable changes to this workspace are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

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
