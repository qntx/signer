# Crates

| Crate | | Description |
| --- | --- | --- |
| **[`signer`](signer/)** | [![crates.io][signer-crate]][signer-crate-url] [![docs.rs][signer-doc]][signer-doc-url] | Umbrella crate — re-exports all chain signers via feature flags |
| **[`signer-primitives`](signer-primitives/)** | [![crates.io][signer-primitives-crate]][signer-primitives-crate-url] [![docs.rs][signer-primitives-doc]][signer-primitives-doc-url] | Core library — `Sign` trait, `SignOutput`, error types |
| **[`signer-evm`](signer-evm/)** | [![crates.io][signer-evm-crate]][signer-evm-crate-url] [![docs.rs][signer-evm-doc]][signer-evm-doc-url] | Ethereum — EIP-191, EIP-712, RLP transaction encoding |
| **[`signer-btc`](signer-btc/)** | [![crates.io][signer-btc-crate]][signer-btc-crate-url] [![docs.rs][signer-btc-doc]][signer-btc-doc-url] | Bitcoin — message signing, CompactSize varint, double-SHA256 |
| **[`signer-svm`](signer-svm/)** | [![crates.io][signer-svm-crate]][signer-svm-crate-url] [![docs.rs][signer-svm-doc]][signer-svm-doc-url] | Solana — Ed25519, compact-u16, transaction encoding |
| **[`signer-cosmos`](signer-cosmos/)** | [![crates.io][signer-cosmos-crate]][signer-cosmos-crate-url] [![docs.rs][signer-cosmos-doc]][signer-cosmos-doc-url] | Cosmos — secp256k1 + SHA-256 |
| **[`signer-tron`](signer-tron/)** | [![crates.io][signer-tron-crate]][signer-tron-crate-url] [![docs.rs][signer-tron-doc]][signer-tron-doc-url] | Tron — TRON message prefix + Keccak-256 |
| **[`signer-sui`](signer-sui/)** | [![crates.io][signer-sui-crate]][signer-sui-crate-url] [![docs.rs][signer-sui-doc]][signer-sui-doc-url] | Sui — BLAKE2b-256 intent-based signing, BCS |
| **[`signer-ton`](signer-ton/)** | [![crates.io][signer-ton-crate]][signer-ton-crate-url] [![docs.rs][signer-ton-doc]][signer-ton-doc-url] | TON — Ed25519 signing |
| **[`signer-fil`](signer-fil/)** | [![crates.io][signer-fil-crate]][signer-fil-crate-url] [![docs.rs][signer-fil-doc]][signer-fil-doc-url] | Filecoin — secp256k1 + Blake2b-256 |
| **[`signer-spark`](signer-spark/)** | [![crates.io][signer-spark-crate]][signer-spark-crate-url] [![docs.rs][signer-spark-doc]][signer-spark-doc-url] | Spark — secp256k1 + double-SHA256 (Bitcoin L2) |
| **[`signer-xrpl`](signer-xrpl/)** | [![crates.io][signer-xrpl-crate]][signer-xrpl-crate-url] [![docs.rs][signer-xrpl-doc]][signer-xrpl-doc-url] | XRP Ledger — secp256k1 + SHA-512-half + DER |
| **[`signer-aptos`](signer-aptos/)** | [![crates.io][signer-aptos-crate]][signer-aptos-crate-url] [![docs.rs][signer-aptos-doc]][signer-aptos-doc-url] | Aptos — Ed25519 + SHA3-256 domain-separated signing |
| **[`signer-cli`](signer-cli/)** | [![crates.io][signer-cli-crate]][signer-cli-crate-url] | CLI — sign, inspect keys across all 11 chains |

## Dependency Graph

```text
signer-cli
  └── signer-{evm,btc,svm,cosmos,tron,sui,ton,fil,spark,xrpl,aptos}
        └── signer-primitives (Sign trait, SignOutput)

signer (umbrella)
  ├── signer-primitives
  ├── signer-evm    ── k256 + sha3 (Keccak-256)
  ├── signer-btc    ── k256 + sha2 (double-SHA256)
  ├── signer-svm    ── ed25519-dalek (Ed25519)
  ├── signer-cosmos ── k256 + sha2
  ├── signer-tron   ── k256 + sha3 + sha2
  ├── signer-sui    ── ed25519-dalek + blake2 (BLAKE2b intent)
  ├── signer-ton    ── ed25519-dalek
  ├── signer-fil    ── k256 + blake2
  ├── signer-spark  ── k256 + sha2
  ├── signer-xrpl   ── k256 + sha2 (SHA-512-half)
  └── signer-aptos  ── ed25519-dalek + sha3 (SHA3-256)
```

## Feature Flags

The umbrella `signer` crate provides fine-grained feature control:

| Feature | Default | Description |
| --- | --- | --- |
| `std` | ✅ | Enable standard library (implies `alloc`) |
| `alloc` | | Enable `alloc` crate for `no_std` environments |
| `getrandom` | | Enable `Signer::random()` via OS-provided CSPRNG |
| `all-chains` | | Enable all 11 chain signers |
| `btc` | ✅ | Bitcoin signer |
| `evm` | ✅ | Ethereum signer |
| `svm` | ✅ | Solana signer |
| `cosmos` | ✅ | Cosmos signer |
| `tron` | ✅ | Tron signer |
| `spark` | ✅ | Spark signer |
| `fil` | ✅ | Filecoin signer |
| `ton` | ✅ | TON signer |
| `sui` | ✅ | Sui signer |
| `xrpl` | ✅ | XRP Ledger signer |
| `aptos` | ✅ | Aptos signer |
| `kobe` | | Enable [kobe](https://github.com/qntx/kobe) HD wallet bridging for all chains |

## Cryptography Libraries

| Curve | Library | Chains |
| --- | --- | --- |
| secp256k1 | [k256](https://docs.rs/k256) 0.13 | EVM, BTC, Cosmos, Tron, Spark, Filecoin, XRPL |
| Ed25519 | [ed25519-dalek](https://docs.rs/ed25519-dalek) 2.2 | Solana, Sui, TON, Aptos |

| Hash | Library | Chains |
| --- | --- | --- |
| SHA-256 / SHA-512 | [sha2](https://docs.rs/sha2) 0.10 | BTC, Cosmos, Tron, Spark, Sui, XRPL |
| Keccak-256 / SHA3-256 | [sha3](https://docs.rs/sha3) 0.10 | EVM, Tron, Sui, Aptos |
| BLAKE2b-256 | [blake2](https://docs.rs/blake2) 0.10 | Filecoin, Sui |

[signer-crate]: https://img.shields.io/crates/v/signer.svg
[signer-crate-url]: https://crates.io/crates/signer
[signer-primitives-crate]: https://img.shields.io/crates/v/signer-primitives.svg
[signer-primitives-crate-url]: https://crates.io/crates/signer-primitives
[signer-evm-crate]: https://img.shields.io/crates/v/signer-evm.svg
[signer-evm-crate-url]: https://crates.io/crates/signer-evm
[signer-btc-crate]: https://img.shields.io/crates/v/signer-btc.svg
[signer-btc-crate-url]: https://crates.io/crates/signer-btc
[signer-svm-crate]: https://img.shields.io/crates/v/signer-svm.svg
[signer-svm-crate-url]: https://crates.io/crates/signer-svm
[signer-cosmos-crate]: https://img.shields.io/crates/v/signer-cosmos.svg
[signer-cosmos-crate-url]: https://crates.io/crates/signer-cosmos
[signer-tron-crate]: https://img.shields.io/crates/v/signer-tron.svg
[signer-tron-crate-url]: https://crates.io/crates/signer-tron
[signer-sui-crate]: https://img.shields.io/crates/v/signer-sui.svg
[signer-sui-crate-url]: https://crates.io/crates/signer-sui
[signer-ton-crate]: https://img.shields.io/crates/v/signer-ton.svg
[signer-ton-crate-url]: https://crates.io/crates/signer-ton
[signer-fil-crate]: https://img.shields.io/crates/v/signer-fil.svg
[signer-fil-crate-url]: https://crates.io/crates/signer-fil
[signer-spark-crate]: https://img.shields.io/crates/v/signer-spark.svg
[signer-spark-crate-url]: https://crates.io/crates/signer-spark
[signer-cli-crate]: https://img.shields.io/crates/v/signer-cli.svg
[signer-cli-crate-url]: https://crates.io/crates/signer-cli
[signer-doc]: https://img.shields.io/docsrs/signer.svg
[signer-doc-url]: https://docs.rs/signer
[signer-primitives-doc]: https://img.shields.io/docsrs/signer-primitives.svg
[signer-primitives-doc-url]: https://docs.rs/signer-primitives
[signer-evm-doc]: https://img.shields.io/docsrs/signer-evm.svg
[signer-evm-doc-url]: https://docs.rs/signer-evm
[signer-btc-doc]: https://img.shields.io/docsrs/signer-btc.svg
[signer-btc-doc-url]: https://docs.rs/signer-btc
[signer-svm-doc]: https://img.shields.io/docsrs/signer-svm.svg
[signer-svm-doc-url]: https://docs.rs/signer-svm
[signer-cosmos-doc]: https://img.shields.io/docsrs/signer-cosmos.svg
[signer-cosmos-doc-url]: https://docs.rs/signer-cosmos
[signer-tron-doc]: https://img.shields.io/docsrs/signer-tron.svg
[signer-tron-doc-url]: https://docs.rs/signer-tron
[signer-sui-doc]: https://img.shields.io/docsrs/signer-sui.svg
[signer-sui-doc-url]: https://docs.rs/signer-sui
[signer-ton-doc]: https://img.shields.io/docsrs/signer-ton.svg
[signer-ton-doc-url]: https://docs.rs/signer-ton
[signer-fil-doc]: https://img.shields.io/docsrs/signer-fil.svg
[signer-fil-doc-url]: https://docs.rs/signer-fil
[signer-spark-doc]: https://img.shields.io/docsrs/signer-spark.svg
[signer-spark-doc-url]: https://docs.rs/signer-spark
[signer-xrpl-crate]: https://img.shields.io/crates/v/signer-xrpl.svg
[signer-xrpl-crate-url]: https://crates.io/crates/signer-xrpl
[signer-xrpl-doc]: https://img.shields.io/docsrs/signer-xrpl.svg
[signer-xrpl-doc-url]: https://docs.rs/signer-xrpl
[signer-aptos-crate]: https://img.shields.io/crates/v/signer-aptos.svg
[signer-aptos-crate-url]: https://crates.io/crates/signer-aptos
[signer-aptos-doc]: https://img.shields.io/docsrs/signer-aptos.svg
[signer-aptos-doc-url]: https://docs.rs/signer-aptos
