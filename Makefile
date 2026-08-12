# Makefile for Rust project using Cargo
# Kept in sync with Justfile (same targets / same check suite).

.PHONY: all default list build check check-no-std update run test bench clippy clippy-fix fmt fmt-check doc deny clean

# Default: run the standard local check suite (includes tests; mirrors CI).
default: all
all: fmt clippy-fix check-no-std deny test

list:
	@echo "Targets: all build check check-no-std update run test bench clippy clippy-fix fmt fmt-check doc deny clean"

build:
	cargo build --workspace --release --all-features

check:
	cargo check --workspace --all-features

check-no-std:
	cargo check -p signer-primitives --no-default-features
	cargo check -p signer-primitives --no-default-features --features alloc
	cargo check -p signer-btc --no-default-features --features alloc
	cargo check -p signer-evm --no-default-features --features alloc
	cargo check -p signer-svm --no-default-features --features alloc
	cargo check -p signer-cosmos --no-default-features --features alloc
	cargo check -p signer-tron --no-default-features --features alloc
	cargo check -p signer-spark --no-default-features --features alloc
	cargo check -p signer-fil --no-default-features --features alloc
	cargo check -p signer-ton --no-default-features --features alloc
	cargo check -p signer-sui --no-default-features --features alloc
	cargo check -p signer-xrpl --no-default-features --features alloc
	cargo check -p signer-aptos --no-default-features --features alloc
	cargo check -p signer-nostr --no-default-features --features alloc
	cargo check -p signer-casper --no-default-features --features alloc
	cargo check -p signer-arweave --no-default-features --features alloc
	cargo check -p signer --no-default-features --features alloc
	cargo check -p signer --no-default-features --features "alloc,all-chains"

update:
	cargo update

run:
	cargo run --release --all-features

test:
	cargo test --workspace --all-features

bench:
	cargo bench --all-features

clippy:
	cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings

clippy-fix:
	cargo +nightly clippy --workspace --fix --all-targets --all-features --allow-dirty --allow-staged -- -D warnings

fmt:
	cargo +nightly fmt --all -- \
		--config unstable_features=true,group_imports=StdExternalCrate,imports_granularity=Module

fmt-check:
	cargo +nightly fmt --all -- \
		--check \
		--config unstable_features=true,group_imports=StdExternalCrate,imports_granularity=Module

doc:
	cargo doc --workspace --all-features --open

# all-features is set in deny.toml [graph]; the CLI has no --all-features flag.
deny:
	cargo deny check

clean:
	cargo clean
