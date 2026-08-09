# Security

This project has **not** been independently audited.

## Scope

- Libraries perform cryptographic signing with `k256` / `ed25519-dalek`.
- HD derivation and multi-path address policy live in [kobe](https://github.com/qntx/kobe), not here.
- Full transaction / deploy serialization is often **caller-owned** (see per-chain docs).

## Reporting

Report vulnerabilities privately to the maintainers when possible. Do not open
public issues that expose exploit details before a fix is available.

## Secrets

Private keys must be handled with `Zeroizing` / redacted `Debug`. Prefer CLI
`-k -` (stdin) or `-k @path` over argv on shared hosts.
