---
name: signer
description: >-
  Multi-chain transaction signing CLI tool for Bitcoin, Ethereum, and Solana.
  Use when the user asks to sign messages, verify signatures, sign hashes,
  or look up addresses from private keys. Supports JSON output via --json flag
  for programmatic/agent consumption.
---

# Signer CLI — Multi-Chain Transaction Signing Tool

`signer` is a single binary CLI for cryptographic signing operations across **Bitcoin**, **Ethereum (EVM)**, and **Solana (SVM)**. It delegates all cryptography to battle-tested upstream libraries (bitcoin, alloy, ed25519-dalek).

## CLI Structure

```text
signer [--json] <chain> <subcommand> [options]
```

The `--json` flag is **global** and must appear **before** the chain subcommand. When set, all output (including errors) is a single JSON object on stdout with no ANSI colors.

### Chain subcommands and aliases

| Chain    | Primary | Aliases           |
| -------- | ------- | ----------------- |
| Bitcoin  | `btc`   | `bitcoin`         |
| Ethereum | `evm`   | `eth`, `ethereum` |
| Solana   | `svm`   | `sol`, `solana`   |

### Subcommands per chain

#### Bitcoin (`btc`)

| Subcommand       | Description                                 |
| ---------------- | ---------------------------------------     |
| `sign-message`   | BIP-137 message signing                     |
| `verify-message` | BIP-137 message verification                |
| `sign-ecdsa`     | Raw ECDSA signature on a 32-byte hash       |
| `sign-schnorr`   | BIP-340 Schnorr signature on a 32-byte hash |
| `address`        | Show all address types for a private key    |

#### Ethereum (`evm`)

| Subcommand       | Description                          |
| ---------------- | ------------------------------------ |
| `sign-message`   | EIP-191 personal_sign                |
| `sign-hash`      | Raw hash signing                     |
| `verify-message` | Verify EIP-191 signed message        |
| `address`        | Show address for a private key       |

#### Solana (`svm`)

| Subcommand | Description                          |
| ---------- | ------------------------------------ |
| `sign`     | Ed25519 signature                    |
| `verify`   | Ed25519 signature verification       |
| `address`  | Show address for a private key       |

## Common Flags

| Flag          | Short | Scope        | Description                                                        |
| ------------- | ----- | ------------ | ---------------------------------------------------------------    |
| `--json`      |       | Global       | JSON output mode (must come before chain subcommand)               |
| `--key`       | `-k`  | All signing  | Private key (WIF for BTC, hex for EVM, hex/base58 keypair for SVM) |
| `--message`   | `-m`  | sign/verify  | Message to sign or verify                                          |
| `--signature` | `-s`  | verify       | Signature to verify                                                |
| `--hash`      | `-x`  | sign-hash    | 32-byte hash in hex                                                |
| `--address`   | `-a`  | verify       | Expected address for verification                                  |

### Bitcoin-specific flags

| Flag             | Short | Values                                         | Default         |
| ---------------- | ----- | ---------------------------------------------- | --------------- |
| `--testnet`      | `-t`  | (flag)                                         | mainnet         |
| `--address-type` | `-a`  | `legacy`, `segwit`, `native-segwit`            | `native-segwit` |

### Solana-specific flags

| Flag    | Scope         | Description                        |
| ------- | ------------- | ------------------------------     |
| `--hex` | `sign/verify` | Treat message as hex-encoded bytes |

## Usage Examples

### Bitcoin

```bash
# Sign a message (BIP-137, default P2WPKH)
signer btc sign-message --key "L1a..." --message "Hello, Bitcoin!"

# Sign with specific address type
signer btc sign-message --key "L1a..." --message "test" --address-type legacy

# Verify a signed message
signer btc verify-message --signature "H..." --message "Hello" --address "bc1q..." 

# Sign a raw hash with ECDSA
signer btc sign-ecdsa --key "L1a..." --hash "abcdef..."

# Sign a raw hash with Schnorr (Taproot)
signer btc sign-schnorr --key "L1a..." --hash "abcdef..."

# Show all address types
signer btc address --key "L1a..."

# JSON output
signer --json btc sign-message --key "L1a..." --message "test"
```

### Ethereum

```bash
# Sign a message (EIP-191)
signer evm sign-message --key "0xabc..." --message "Hello, Ethereum!"

# Sign a raw hash
signer evm sign-hash --key "0xabc..." --hash "0xdef..."

# Verify a signed message
signer evm verify-message --signature "0x..." --message "Hello" --address "0x..."

# Show address
signer evm address --key "0xabc..."

# JSON output
signer --json evm sign-message --key "0xabc..." --message "test"
```

### Solana

```bash
# Sign a message
signer svm sign --key "deadbeef..." --message "Hello, Solana!"

# Sign hex-encoded bytes (e.g., serialized transaction)
signer svm sign --key "deadbeef..." --message "0a0b0c..." --hex

# Verify a signature
signer svm verify --signature "abcdef..." --message "Hello" --pubkey "Base58Address..."

# Show address
signer svm address --key "deadbeef..."

# JSON output
signer --json svm sign --key "deadbeef..." --message "test"
```

## JSON Output Schemas

Always use `--json` for programmatic consumption.

### Sign Output

```json
{
  "chain": "bitcoin",
  "operation": "BIP-137 message",
  "address": "bc1q...",
  "signature": "H...",
  "message": "Hello, Bitcoin!"
}
```

### Verify Output

```json
{
  "chain": "ethereum",
  "valid": true,
  "address": "0x...",
  "message": "Hello"
}
```

### Address Output (Bitcoin)

```json
{
  "chain": "bitcoin",
  "network": "mainnet",
  "address": "bc1q...",
  "public_key": "02...",
  "addresses": [
    { "kind": "P2WPKH", "address": "bc1q..." },
    { "kind": "P2TR", "address": "bc1p..." },
    { "kind": "P2SH-P2WPKH", "address": "3..." },
    { "kind": "P2PKH", "address": "1..." }
  ]
}
```

### Error

All errors in JSON mode return exit code 1 with:

```json
{
  "error": "invalid private key: ..."
}
```

## Private Key Formats by Chain

| Chain    | Format                                                   |
| -------- | -------------------------------------------------------- |
| Bitcoin  | WIF (e.g. `L1a...`) or hex (32 bytes)                    |
| Ethereum | `0x`-prefixed or plain 64-char hex                       |
| Solana   | 64-char hex or Base58 keypair (64 bytes: secret+public)  |

## Agent Best Practices

1. **Always use `--json`** for programmatic consumption to avoid ANSI escape codes.
2. **Parse output by `chain` field** to determine the format of signatures and addresses.
3. **`--json` placement**: Must appear before the chain subcommand: `signer --json btc sign-message ...`
4. **Errors** in JSON mode return `{"error": "..."}` with exit code 1.
5. **Bitcoin keys** accept both WIF and hex formats — the CLI auto-detects.
6. **Solana keys** accept both hex and base58 keypair formats — the CLI auto-detects.
7. **Verify commands** return `{"valid": true/false}` — always check the `valid` field.
