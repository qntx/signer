# Contributing to Signer

Thank you for improving Signer. This document is the single source of truth for
how to develop, extend, and release the workspace. Please read it before
opening a pull request.

## Code of collaboration

- Prefer **small, reviewable PRs** with a clear problem statement.
- Match existing style: workspace Clippy lints (`pedantic` + `nursery`),
  `rustfmt` with the project config (nightly import grouping via `just fmt`),
  explicit error handling.
- Do **not** invent APIs. Follow the [chain sign contract](#chain-sign-contract).
- Do **not** reintroduce the full `bitcoin` crate (`deny.toml` bans it).
- Secrets (private keys, `nsec`, Solana keypairs) must stay in `Zeroizing` and
  use **redacted `Debug`**. Never `#[derive(Debug)]` on types that hold secret
  material (`Zeroizing` itself does not redact).
- Every chain signing path that claims compatibility must be pinned with
  **cross-implementation KATs** (not self-confirming dumps).

By contributing, you agree that your contributions are dual-licensed under the
project’s [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) terms (see
`README.md`).

## Prerequisites

| Tool | Notes |
| --- | --- |
| Rust | Stable + nightly (fmt/clippy). MSRV is declared in root `Cargo.toml` (`rust-version`). |
| [`just`](https://github.com/casey/just) | Preferred task runner (`Justfile`; `Makefile` mirrors the same suite). |
| [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) | License / ban / advisory checks. |

```bash
rustup toolchain install stable nightly --component rustfmt,clippy
cargo install just cargo-deny
```

## Local development

```bash
git clone https://github.com/qntx/signer.git
cd signer

just all    # fmt + clippy-fix + no_std + cargo deny + tests
just test   # cargo test --workspace --all-features
```

Useful recipes (see `just --list`):

| Recipe | Purpose |
| --- | --- |
| `just all` | Default quality gate before a PR (includes tests) |
| `just test` | Full workspace tests |
| `just check-no-std` | Host-side no_std feature matrix (CI also builds `thumbv7m-none-eabi`) |
| `just check-names` | Fail if forbidden API names reappear (`sign-hash`, trait `Sign`, …) |
| `just deny` | `cargo deny check` (`all-features` is configured in `deny.toml` `[graph]`) |
| `just fmt` / `just clippy` | Format and lint |

CI (`.github/workflows/ci.yml`) runs format, Clippy `-D warnings`, tests,
`cargo-deny`, and no_std targets. A PR should be green there.

### Commit and PR hygiene

- Use imperative commit subjects (`feat(cli): …`, `fix(btc): …`, `docs: …`).
- Reference issues when applicable.
- Update [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]` for user-visible
  changes (Keep a Changelog format).
- Do not force-push shared branches without coordination.

## Project layout

```text
Cargo.toml              workspace + shared deps / lints
crates/
  signer-primitives/    Sign / SignOutput / SignError / curve primitives
  signer-<chain>/       one crate per network
  signer/               umbrella re-exports + features
  signer-cli/           `signer` binary
crates/README.md        crate table, graph, features
deny.toml               licenses, bans (no full `bitcoin` crate)
skills/signer/SKILL.md  agent-oriented CLI skill
```

Library crates target `no_std` + `alloc` where possible. Crypto is delegated to
`k256` / `ed25519-dalek` and standard hash crates — no hand-rolled curves.

### Umbrella defaults (vs kobe)

| Crate | Default features | Rationale |
| --- | --- | --- |
| `signer` | `std` + `mainstream` (`btc`,`evm`,`svm`) | A bare signer with zero chains is not useful |
| `kobe` | `std` only | HD core is useful without a chain deriver |

Use `all-chains` or per-chain features when you need the full set.

## Chain sign contract

Every `signer-<chain>` crate follows the same surface. Prefer this table when
adding a chain or reviewing API diffs.

### Construction

| Method | Contract |
| --- | --- |
| `FromSecretKey::from_secret_bytes` / `from_secret_hex` | Canonical key ingest (shared via `signer-primitives`). |
| `Signer::try_from_bytes` / `from_bytes` / `try_random` / `random` | Emitted by `delegate_*_ctors!` macros where applicable. |
| `FromDerived::from_derived` (`kobe` feature) | Build from `kobe` account types via `AsRef<DerivedAccount>`. |

Do **not** re-implement hex decoding per chain; use `parse_secret_hex` /
`FromSecretKey`.

### Signing surface

| Method / trait | When |
| --- | --- |
| `SignDigest::sign_digest` | Always — 32-byte `Digest32` in, `SignOutput` out (scheme-dependent semantics). |
| `SignMessage::sign_message` | **Only** when the chain has a real off-chain message convention. |
| Inherent `sign_transaction` / `sign_raw` | Protocol-level bytes; semantics are chain-specific (not a shared trait). |
| `EncodeSignedTransaction` / `ExtractSignableBytes` | Only where the wire format needs assembly / extraction. |

Capability gaps must surface at **compile time** (missing trait impl), not as a
runtime “unsupported” error for a faked message scheme.

### Output and errors

| Type | Contract |
| --- | --- |
| `SignOutput` | Discriminated: `Ecdsa` / `EcdsaDer` / `Ed25519` / `Ed25519WithPubkey` / `Schnorr`. Document `v` semantics per producer. |
| `SignError` | `#[non_exhaustive]`; chains map all failures into this enum (or `From<SignError>`). |

### Debug / secrets

| Type | `Debug` contract |
| --- | --- |
| Curve wrappers / chain `Signer` | Redact private key material (`[REDACTED]`). |
| CLI | Prefer `-k -` (stdin) or `-k @path`; never log key material. |

### Naming

- Shared secret traits: `FromSecretKey`, `FromDerived` (under `kobe`)
- Do not reintroduce per-chain copy-pasted `from_hex` helpers that bypass primitives

## Adding a chain

1. Scaffold `crates/signer-<name>/` with `no_std` + `alloc`, workspace lints, and
   `FromSecretKey` + `Sign` (plus optional traits as justified).
2. Wire features on the `signer` umbrella and `signer-cli` (subcommand + output).
3. Add KATs against an independent reference implementation where claims exist.
4. Extend CI no_std thumb checks for the new crate.
5. Document the chain in `README.md`, `crates/README.md`, and
   `skills/signer/SKILL.md`; update `CHANGELOG.md`.
6. Keep `cargo deny` clean (no banned crates).

## ECDSA `v` offsets

Use `signer_primitives::v_encoding` constants (`EIP191_OFFSET`, `BIP137_*`, …).
Do not hard-code `27` / `31` in new chain code.

## KAT strength

Update [`docs/KAT_MATRIX.md`](docs/KAT_MATRIX.md) when adding chains or claims.

## CLI notes

- Global flag: `--json` (must appear before the chain subcommand).
- Private key flag `-k` / `--key` accepts hex, `-` (stdin), or `@path` (file).
- Prefer stdin / files over argv on shared hosts (shell history / process listings).
- Self-upgrade for installs from `https://sh.qntx.fun/signer`:

  ```bash
  signer upgrade              # alias: signer update
  signer upgrade --check
  ```

  Re-invokes the official installer. Cargo installs under `.cargo/bin` are
  **not** overwritten; the command prints a `cargo install signer-cli --force`
  hint instead.

## Release process

Maintainers only.

1. CI green on `main` (`lint`, `test`, `deny`, `no_std`).
2. Local: `just all` (includes tests).
3. Move `[Unreleased]` notes in `CHANGELOG.md` into a dated version section;
   no leftover **Breaking** bullets that belong in the release.
4. Bump workspace `version` and path dependency major/minor strings in root
   `Cargo.toml` (e.g. `3.0.0` → path `"3.0"`).
5. Tag and push: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
6. Confirm GitHub Actions `release.yml` (binaries) and `publish.yml`
   (crates.io) succeed.
7. Publish order is handled by the workflow: `signer-primitives` → chain crates →
   `signer` → `signer-cli`.

Semantic Versioning applies. Document breaking API changes under a major bump.

## Security

This project has **not** been independently audited. Report vulnerabilities
privately to the maintainers when possible; do not open public issues that
expose exploit details before a fix is available.
