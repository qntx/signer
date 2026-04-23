---
name: signer
description: >-
  Multi-chain transaction signing CLI tool for 12 chains: Ethereum, Bitcoin,
  Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Aptos, and
  Nostr. Use when the user asks to sign messages, sign hashes, sign
  transactions, sign Nostr events, or look up addresses / public keys /
  NIP-19 npub / nsec from private keys. Supports JSON output via --json
  flag for programmatic/agent consumption.
---

# Signer CLI — Multi-Chain Transaction Signing Tool

`signer` is a single binary CLI for cryptographic signing operations across **12 chains**: Ethereum, Bitcoin, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Aptos, and Nostr. It uses lightweight, battle-tested cryptographic libraries (k256 for secp256k1 ECDSA and BIP-340 Schnorr, ed25519-dalek, sha2, sha3, blake2, bech32).

## Installation

### One-line install (recommended)

**macOS / Linux:**

```sh
curl -fsSL https://sh.qntx.fun/signer | sh
```

**Windows (PowerShell):**

```powershell
irm https://sh.qntx.fun/signer/ps | iex
```

### Via Cargo

```bash
cargo install signer-cli
```

### Verify installation

```sh
signer --version
```

## CLI Structure

```text
signer [--json] <chain> <subcommand> [options]
```

The `--json` flag is **global** and must appear **before** the chain subcommand. When set, all output (including errors) is a single JSON object on stdout with no ANSI colors.

### Chain subcommands and aliases

| Chain      | Primary  | Aliases           |
| ---------- | -------- | ----------------- |
| Ethereum   | `evm`    | `eth`, `ethereum` |
| Bitcoin    | `btc`    | `bitcoin`         |
| Solana     | `svm`    | `sol`, `solana`   |
| Cosmos     | `cosmos` | `atom`            |
| Tron       | `tron`   | `trx`             |
| Sui        | `sui`    | —                 |
| TON        | `ton`    | —                 |
| Filecoin   | `fil`    | `filecoin`        |
| Spark      | `spark`  | —                 |
| XRP Ledger | `xrpl`   | `xrp`, `ripple`   |
| Aptos      | `aptos`  | `apt`             |
| Nostr      | `nostr`  | —                 |

### Subcommands per chain

#### secp256k1 ECDSA chains (evm, btc, cosmos, tron, spark, fil, xrpl)

| Subcommand     | Description                                     |
| -------------- | ----------------------------------------------- |
| `sign-hash`    | Sign a raw 32-byte hash                         |
| `sign-message` | Sign a message (chain-specific preprocessing)   |
| `sign-tx`      | Sign transaction bytes (chain-specific hashing) |
| `address`      | Show address and/or public key                  |

#### Ed25519 chains (svm, sui, ton, aptos)

| Subcommand     | Description                      |
| -------------- | -------------------------------- |
| `sign`         | Sign a message (SVM, TON, Aptos) |
| `sign-message` | Sign a message with intent (SUI) |
| `sign-tx`      | Sign transaction bytes           |
| `address`      | Show address and/or public key   |

#### BIP-340 Schnorr chains (nostr)

| Subcommand     | Description                                                           |
| -------------- | --------------------------------------------------------------------- |
| `sign-hash`    | Sign a 32-byte NIP-01 `event.id` (use `-x` / `--event-id` / `--hash`) |
| `sign-message` | Sign arbitrary UTF-8 text (raw BIP-340 Schnorr — no implicit hashing) |
| `sign-tx`      | Sign a serialized NIP-01 event (computes `sha256(event)` then signs)  |
| `address`      | Show the NIP-19 `npub1…` address and x-only public key                |

## Common Flags

| Flag         | Short | Scope              | Description                                                            |
| ------------ | ----- | ------------------ | ---------------------------------------------------------------------- |
| `--json`     |       | Global             | JSON output (must come before chain subcommand)                        |
| `--key`      | `-k`  | All                | Private key in hex (0x-prefixed or plain); Nostr also accepts `nsec1…` |
| `--message`  | `-m`  | sign, sign-message | Message to sign                                                        |
| `--hash`     | `-x`  | sign-hash          | 32-byte hash in hex (Nostr also accepts `--event-id`)                  |
| `--event-id` | `-x`  | nostr sign-hash    | Alias for `--hash` — the 32-byte NIP-01 event id                       |
| `--tx`       | `-t`  | sign-tx            | Hex-encoded transaction bytes (Nostr: serialized NIP-01 event)         |

### Solana-specific flags

| Flag    | Scope  | Description                        |
| ------- | ------ | ---------------------------------- |
| `--hex` | `sign` | Treat message as hex-encoded bytes |

## Chain-Specific Hashing

| Chain      | `sign-message` hash                           | `sign-tx` hash                   |
| ---------- | --------------------------------------------- | -------------------------------- |
| Ethereum   | Keccak-256 (EIP-191 prefix)                   | Keccak-256                       |
| Bitcoin    | double-SHA256 (Bitcoin Signed Message prefix) | double-SHA256                    |
| Solana     | Ed25519 direct                                | Ed25519 direct                   |
| Cosmos     | SHA-256                                       | SHA-256                          |
| Tron       | Keccak-256 (TRON Signed Message prefix)       | SHA-256                          |
| Sui        | BLAKE2b-256 (BCS + intent)                    | BLAKE2b-256 (intent)             |
| TON        | Ed25519 direct                                | Ed25519 direct                   |
| Filecoin   | Blake2b-256                                   | Blake2b-256                      |
| Spark      | double-SHA256                                 | double-SHA256                    |
| XRP Ledger | Not supported (no canonical message standard) | SHA-512-half + DER               |
| Aptos      | Ed25519 direct                                | SHA3-256 domain prefix + Ed25519 |
| Nostr      | BIP-340 Schnorr (raw, no implicit hashing)    | SHA-256 then BIP-340 Schnorr     |

## Usage Examples

### Ethereum

```bash
# Sign a message (EIP-191)
signer evm sign-message -k "0x4c0883a6..." -m "Hello, Ethereum!"

# Sign a raw 32-byte hash
signer evm sign-hash -k "0x4c0883a6..." -x "0xabcdef..."

# Sign transaction bytes
signer evm sign-tx -k "0x4c0883a6..." -t "0x02f8..."

# Show address and public key
signer evm address -k "0x4c0883a6..."

# JSON output
signer --json evm sign-message -k "0x4c0883a6..." -m "test"
```

### Bitcoin

```bash
# Sign a message (Bitcoin Signed Message)
signer btc sign-message -k "4c0883a6..." -m "Hello, Bitcoin!"

# Sign a raw hash
signer btc sign-hash -k "4c0883a6..." -x "abcdef..."

# Sign transaction bytes
signer btc sign-tx -k "4c0883a6..." -t "0200000001..."

# Show compressed public key
signer btc address -k "4c0883a6..."

# JSON output
signer --json btc sign-message -k "4c0883a6..." -m "test"
```

### Solana

```bash
# Sign a message
signer svm sign -k "9d61b19d..." -m "Hello, Solana!"

# Sign hex-encoded bytes
signer svm sign -k "9d61b19d..." -m "0a0b0c..." --hex

# Sign transaction bytes
signer svm sign-tx -k "9d61b19d..." -t "01000103..."

# Show address and public key
signer svm address -k "9d61b19d..."
```

### Cosmos / Tron / Spark / Filecoin / XRP Ledger

```bash
# All secp256k1 chains follow the same pattern
signer cosmos sign-message -k "4c0883a6..." -m "Hello"
signer tron sign-message -k "4c0883a6..." -m "Hello"
signer spark sign-tx -k "4c0883a6..." -t "deadbeef..."
signer fil sign-hash -k "4c0883a6..." -x "abcdef..."

# XRP Ledger (no sign-message, only sign-hash and sign-tx)
signer xrpl sign-hash -k "4c0883a6..." -x "abcdef..."
signer xrpl sign-tx -k "4c0883a6..." -t "535458..."
signer xrpl address -k "4c0883a6..."
```

### Sui

```bash
# Sign a message (BCS + BLAKE2b intent)
signer sui sign-message -k "9d61b19d..." -m "Hello, Sui!"

# Sign transaction bytes (BLAKE2b intent)
signer sui sign-tx -k "9d61b19d..." -t "0000..."

# Show Sui address
signer sui address -k "9d61b19d..."
```

### TON

```bash
# Sign a message
signer ton sign -k "9d61b19d..." -m "Hello, TON!"

# Sign transaction bytes
signer ton sign-tx -k "9d61b19d..." -t "b5ee9c72..."

# Show public key
signer ton address -k "9d61b19d..."
```

### Aptos

```bash
# Sign a message (raw Ed25519)
signer aptos sign -k "9d61b19d..." -m "Hello, Aptos!"

# Sign BCS-serialized RawTransaction (with APTOS:: domain prefix)
signer aptos sign-tx -k "9d61b19d..." -t "0000..."

# Show Aptos address (SHA3-256 derived)
signer aptos address -k "9d61b19d..."
```

### Nostr

Nostr uses **BIP-340 Taproot Schnorr** signatures over secp256k1 (NIP-01).
Keys and identifiers are exchanged in **NIP-19 bech32** form: `nsec1…`
(private key), `npub1…` (public key).

```bash
# Show the NIP-19 npub and x-only pubkey (accepts either hex or nsec1…)
signer nostr address -k "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"
signer nostr address -k "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp"

# Sign a NIP-01 event.id (32-byte SHA-256 of the canonical event serialization)
signer nostr sign-hash -k "nsec10allq0g..." -x "5e6ea04f9e5c8a5e38b9a8d99e41dbd5c43c9a8abba4e3bda91a5b1f34c3a7d1"

# Sign a serialized event (hex of the NIP-01 JSON array `[0,pubkey,created_at,kind,tags,content]`)
# The CLI computes sha256(event) then BIP-340 Schnorr signs it.
signer nostr sign-tx -k "nsec10allq0g..." -t "5b302c2237652e2e2e225d"

# Sign arbitrary UTF-8 text (raw BIP-340 Schnorr — NO implicit hashing)
signer nostr sign-message -k "7f7ff03d..." -m "off-chain authentication challenge"

# JSON output
signer --json nostr sign-hash -k "nsec10allq0g..." -x "5e6ea04f..."
```

## JSON Output Schemas

Always use `--json` for programmatic consumption.

### Sign Output

```json
{
  "chain": "ethereum",
  "operation": "EIP-191 personal_sign",
  "address": "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
  "signature": "a1b2c3...",
  "v": 27,
  "message": "Hello, Ethereum!"
}
```

Fields `address`, `v`, `public_key`, and `message` are optional and omitted when not applicable.

- **secp256k1 ECDSA signatures**: 130-char hex (65 bytes: `r[32] || s[32] || v[1]`), `v` field present (`0`/`1` for raw / `sign-hash` / `sign-tx`; `27`/`28` for `sign-message` on EVM and Tron, EIP-191 wire encoding)
- **Ed25519 signatures**: 128-char hex (64 bytes), no `v`
- **BIP-340 Schnorr signatures (Nostr)**: 128-char hex (64 bytes: `r[32] || s[32]`), no `v`; `public_key` is 32-byte x-only hex; `address` is the `npub1…` bech32 form

### Address Output

```json
{
  "chain": "ethereum",
  "address": "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
  "public_key": "04a1b2c3..."
}
```

The `address` field is present for chains that derive addresses (EVM, SVM, SUI). For other chains, only `public_key` is shown (compressed SEC1 for secp256k1, raw 32-byte hex for Ed25519).

### Error

All errors in JSON mode return exit code 1 with:

```json
{
  "error": "invalid private key: ..."
}
```

## Private Key Formats

| Chain                   | Input Format                                            |
| ----------------------- | ------------------------------------------------------- |
| EVM                     | `0x`-prefixed or plain 64-char hex                      |
| BTC, Cosmos, Tron, etc. | 64-char hex (32 bytes)                                  |
| SVM                     | 64-char hex or Base58 keypair (64 bytes: secret+public) |
| SUI, TON, Aptos         | 64-char hex (Ed25519 secret key)                        |
| XRP Ledger              | 64-char hex (32 bytes secp256k1 key)                    |
| Nostr                   | 64-char hex _or_ NIP-19 `nsec1…` bech32 (auto-detected) |

## Agent Best Practices

1. **Always use `--json`** for programmatic consumption to avoid ANSI escape codes.
2. **`--json` placement**: Must appear before the chain subcommand: `signer --json evm sign-message ...`
3. **Parse output by `chain` field** to determine the format of signatures and addresses.
4. **Errors** in JSON mode return `{"error": "..."}` with exit code 1.
5. **Solana keys** accept both hex and base58 keypair formats — the CLI auto-detects.
6. **Nostr keys** accept both 64-char hex and NIP-19 `nsec1…` bech32 — the CLI auto-detects.
7. **Signature length discriminator**: `v` present ⇒ secp256k1 ECDSA (65-byte sig); `public_key` present with no `v` and 64-byte sig ⇒ Ed25519 (SUI/Nostr/Aptos wire) or BIP-340 Schnorr (Nostr). Use the `chain` field to disambiguate. The `v` byte is `0`/`1` for raw signing (`sign-hash`, `sign-tx`) and `27`/`28` for EIP-191 `sign-message` on EVM / Tron.
8. **Nostr `sign-message` does NOT hash** the input — it passes bytes straight into BIP-340. For NIP-01 events, compute `sha256(serialized_event)` first (or use `sign-tx` which does it for you) and feed the 32-byte result to `sign-hash`.
9. **Address derivation** is limited: use `kobe` CLI for full HD wallet derivation with mnemonics (Nostr uses NIP-06 path `m/44'/1237'/<account>'/0/0`).
10. **Pair with `kobe` for mnemonic-based flows**: `kobe <chain> new --json` outputs `accounts[].private_key` as hex (plus `nsec` for Nostr); pipe it into `signer <chain> sign-* -k <hex>` to sign. The `kobe` library crate can also be wired in at the code level via the `kobe` feature of each `signer-X` crate (`Signer::from_derived(&kobe_X::DerivedAccount)`).
