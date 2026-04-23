# KAT Generator

Reproducible Known Answer Test vectors for the Rust `signer` workspace. Each chain-specific `tests.rs` embeds the expected hex strings directly, so the Rust test suite has **no runtime dependency** on this folder. The script exists solely as the auditable origin of those constants — a mature, independent JavaScript cryptography stack that anyone can re-run and diff against.

## Why another implementation?

A test that signs with `k256` and then verifies with `k256` only proves the signer is internally consistent with its own past output. We want **protocol equivalence**: the signer must agree with a completely separate implementation of the same standard. We use:

- [`@noble/curves`](https://github.com/paulmillr/noble-curves) — audited secp256k1 ECDSA, BIP-340 Schnorr, Ed25519.
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — SHA-256, SHA-512, SHA3-256, Keccak-256, BLAKE2b, RIPEMD-160.
- [`@scure/base`](https://github.com/paulmillr/scure-base) — Base58, bech32.

All three are maintained by Paul Miller and widely deployed across the Ethereum / Bitcoin / Solana ecosystems, so matching them is strong evidence of protocol conformance.

## Usage

```sh
npm install --prefix tests/goldens
node tests/goldens/generate.mjs
```

Outputs (both are `.gitignored`):

- `vectors.json` — diff-friendly human-readable form.
- `vectors.rs`   — ready-to-paste Rust `const`s.

## Updating a KAT

If you ever need to rotate a fixture (a new digest, a new transaction preimage, …), follow this flow:

1. Edit the constants at the top of `generate.mjs` (`SECP_KEY_HEX`, `TEST_DIGEST`, …).
2. Re-run the script.
3. Copy the new hex values into the affected crate's `tests.rs`, replacing the inline `const …_HEX: &str = …;` entries.
4. `cargo test --workspace --all-features` — any mismatched test will fail, giving you an independent check that every chain's Rust implementation still agrees with the JS reference.
