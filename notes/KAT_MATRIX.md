# KAT strength matrix (signer)

Cross-implementation known-answer tests are required for claimed interop.
This matrix is honesty-first: **smoke/shape is not gold**.

| Strength | Meaning |
| --- | --- |
| **gold** | Fixed vector vs independent reference (RFC/BIP/EIP/@noble/official docs) |
| **shape** | Length / `v` range / round-trip verify only |
| **smoke** | Compiles + basic call succeeds |
| **none** | No dedicated KAT (caller-owned preimage) |

| Chain | `sign_digest` | `sign_message` | `sign_transaction` / inherent | Notes |
| --- | --- | --- | --- | --- |
| primitives secp | gold (RFC 6979) | — | — | recoverable + DER |
| primitives ed25519 | gold (RFC 8032) | — | — | |
| primitives schnorr | gold (BIP-340 CSV) | — | — | |
| evm | shape | gold (EIP-191 / EIP-712 Mail) | shape | typed-tx RLP encode covered |
| btc | shape | gold (BIP-137 four headers) | shape | |
| spark | shape | gold (shares BTC digest) | shape | |
| tron | shape | gold (prefix + recover) | shape | |
| cosmos | shape | — | shape | SignDoc caller-owned |
| fil | shape | — | shape | |
| xrpl | shape | — | shape | DER path |
| svm | shape | shape (`nacl` equivalence) | shape | compact-u16 extract |
| sui | shape | shape (intent) | shape | |
| ton | shape | — | shape | no personal-message standard |
| aptos | shape | — | shape | domain prefix on tx |
| nostr | gold (event id path) | shape (raw schnorr) | shape | NIP-01 |
| casper | shape | shape | none (no deploy builder) | dual-curve; deploy hash caller-owned |
| arweave | shape | — | shape (`sign_payload` / format2 segment) | address **gold** vs kobe-arweave abandon; deep-hash empty-list gold; no SignMessage |

New chains **must** add a row before merge (`CONTRIBUTING.md`).
