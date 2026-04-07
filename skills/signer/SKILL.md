---
name: signer
description: >-
  Multi-chain transaction signing CLI tool for 11 chains: Ethereum, Bitcoin,
  Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, and Aptos. Use when the user asks
  to sign messages, sign hashes, sign transactions, or look up addresses/public
  keys from private keys. Supports JSON output via --json flag for
  programmatic/agent consumption.
---

# Signer CLI — Multi-Chain Transaction Signing Tool

`signer` is a single binary CLI for cryptographic signing operations across **11 chains**: Ethereum, Bitcoin, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, and Aptos. It uses lightweight, battle-tested cryptographic libraries (k256, ed25519-dalek, sha2, sha3, blake2).

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

### Subcommands per chain

#### secp256k1 chains (evm, btc, cosmos, tron, spark, fil)

| Subcommand     | Description                                     |
| -------------- | ----------------------------------------------- |
| `sign-hash`    | Sign a raw 32-byte hash                         |
| `sign-message` | Sign a message (chain-specific preprocessing)   |
| `sign-tx`      | Sign transaction bytes (chain-specific hashing) |
| `address`      | Show address and/or public key                  |

#### Ed25519 chains (svm, sui, ton, aptos)

| Subcommand     | Description                                     |
| -------------- | ----------------------------------------------- |
| `sign`         | Sign a message (SVM, TON, Aptos)                |
| `sign-message` | Sign a message with intent (SUI)                |
| `sign-tx`      | Sign transaction bytes                          |
| `address`      | Show address and/or public key                  |

## Common Flags

| Flag        | Short | Scope       | Description                                          |
| ----------- | ----- | ----------- | ---------------------------------------------------- |
| `--json`    |       | Global      | JSON output (must come before chain subcommand)      |
| `--key`     | `-k`  | All         | Private key in hex (with or without 0x prefix)       |
| `--message` | `-m`  | sign        | Message to sign                                      |
| `--hash`    | `-x`  | sign-hash   | 32-byte hash in hex                                  |
| `--tx`      | `-t`  | sign-tx     | Hex-encoded transaction bytes                        |

### Solana-specific flags

| Flag    | Scope  | Description                        |
| ------- | ------ | ---------------------------------- |
| `--hex` | `sign` | Treat message as hex-encoded bytes |

## Chain-Specific Hashing

| Chain      | `sign-message` hash                            | `sign-tx` hash       |
| ---------- | ---------------------------------------------- | -------------------- |
| Ethereum   | Keccak-256 (EIP-191 prefix)                    | Keccak-256           |
| Bitcoin    | double-SHA256 (Bitcoin Signed Message prefix)  | double-SHA256        |
| Solana     | Ed25519 direct                                 | Ed25519 direct       |
| Cosmos     | SHA-256                                        | SHA-256              |
| Tron       | Keccak-256 (TRON Signed Message prefix)        | SHA-256              |
| Sui        | BLAKE2b-256 (BCS + intent)                     | BLAKE2b-256 (intent) |
| TON        | Ed25519 direct                                 | Ed25519 direct       |
| Filecoin   | Blake2b-256                                    | Blake2b-256          |
| Spark      | double-SHA256                                  | double-SHA256        |
| XRP Ledger | Not supported (no canonical message standard)  | SHA-512-half + DER   |
| Aptos      | Ed25519 direct                                 | SHA3-256 domain prefix + Ed25519 |

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

## JSON Output Schemas

Always use `--json` for programmatic consumption.

### Sign Output

```json
{
  "chain": "ethereum",
  "operation": "EIP-191 personal_sign",
  "address": "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
  "signature": "a1b2c3...",
  "recovery_id": 27,
  "message": "Hello, Ethereum!"
}
```

Fields `address`, `recovery_id`, `public_key`, and `message` are optional and omitted when not applicable.

- **secp256k1 signatures**: 130-char hex (65 bytes: `r[32] || s[32] || v[1]`), `recovery_id` present
- **Ed25519 signatures**: 128-char hex (64 bytes), no `recovery_id`

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

| Chain                    | Input Format                                             |
| ------------------------ | -------------------------------------------------------- |
| EVM                      | `0x`-prefixed or plain 64-char hex                       |
| BTC, Cosmos, Tron, etc.  | 64-char hex (32 bytes)                                   |
| SVM                      | 64-char hex or Base58 keypair (64 bytes: secret+public)  |
| SUI, TON, Aptos          | 64-char hex (Ed25519 secret key)                         |
| XRP Ledger               | 64-char hex (32 bytes secp256k1 key)                     |

## Agent Best Practices

1. **Always use `--json`** for programmatic consumption to avoid ANSI escape codes.
2. **`--json` placement**: Must appear before the chain subcommand: `signer --json evm sign-message ...`
3. **Parse output by `chain` field** to determine the format of signatures and addresses.
4. **Errors** in JSON mode return `{"error": "..."}` with exit code 1.
5. **Solana keys** accept both hex and base58 keypair formats — the CLI auto-detects.
6. **secp256k1 signatures** include `recovery_id` (v byte); Ed25519 signatures do not.
7. **Address derivation** is limited: use `kobe` CLI for full HD wallet derivation with mnemonics.
