# Signer

Multi-chain transaction signer built on mature cryptography libraries. **Zero hand-rolled cryptography.**

## Crates

| Crate | Description | Upstream Library |
| --- | --- | --- |
| [`signer`](signer/) | Umbrella crate — re-exports all chain signers | — |
| [`signer-evm`](signer-evm/) | Ethereum / EVM signing (EIP-191, EIP-712, transactions) | [alloy-signer-local](https://docs.rs/alloy-signer-local) |
| [`signer-btc`](signer-btc/) | Bitcoin signing (ECDSA, Schnorr, PSBT, BIP-137 messages) | [bitcoin](https://docs.rs/bitcoin) |
| [`signer-svm`](signer-svm/) | Solana / SVM signing (Ed25519) | [ed25519-dalek](https://docs.rs/ed25519-dalek) |

## Usage

```rust
// Via umbrella crate (all chains enabled by default)
use signer::evm;
let s = evm::Signer::random();

// Or depend on a single chain crate
use signer_btc::Signer;
let s = Signer::random(signer_btc::Network::Bitcoin);
```

### Kobe Wallet Bridge

Enable the `kobe` feature to construct signers from [kobe](https://github.com/qntx/kobe) HD wallet derived keys:

```rust
use signer_evm::Signer;
let signer = Signer::from_derived(&derived_address).unwrap();
```

## Features

| Feature | Description |
| --- | --- |
| `btc` | Enable Bitcoin signer (default) |
| `evm` | Enable EVM signer (default) |
| `svm` | Enable Solana signer (default) |
| `kobe` | Enable kobe HD wallet bridging |

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
