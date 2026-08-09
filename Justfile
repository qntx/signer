# justfile for Rust project using Cargo
# Kept in sync with Makefile (same targets / same check suite).

# Default: run the standard local check suite.
# Use `just list` to print recipes instead of running them.
default: all

# Run the most common checks (includes tests; mirrors CI coverage locally).
all: fmt clippy-fix check-no-std deny test

# List available recipes
list:
    @just --list

# Build the project with all features enabled in release mode
build:
    cargo build --workspace --release --all-features

# Check the project for compilation errors without producing binaries
check:
    cargo check --workspace --all-features

# Verify no_std compilation (all crates use #![cfg_attr(not(feature = "std"), no_std)])
# CI uses thumbv7m-none-eabi for strict bare-metal verification
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
    cargo check -p signer --no-default-features --features alloc
    cargo check -p signer --no-default-features --features "alloc,all-chains"

# Update dependencies to their latest compatible versions
update:
    cargo update

# Run the project with all features enabled in release mode
run:
    cargo run --release --all-features

# Run all tests with all features enabled
test:
    cargo test --workspace --all-features

# Run benchmarks with all features enabled
bench:
    cargo bench --all-features

# Run Clippy linter (nightly is only required for a few unstable lints).
# Uses workspace lints from Cargo.toml. Falls back to stable cleanly.
# Prerequisites: `rustup toolchain install nightly --component clippy`
clippy:
    cargo +nightly clippy --workspace \
        --all-targets \
        --all-features \
        -- -D warnings

# Run Clippy linter with auto-fix (for development).
# Prerequisites: `rustup toolchain install nightly --component clippy`
clippy-fix:
    cargo +nightly clippy --workspace \
        --fix \
        --all-targets \
        --all-features \
        --allow-dirty \
        --allow-staged \
        -- -D warnings

# Format the code using rustfmt (nightly provides import grouping).
fmt:
    cargo +nightly fmt --all

# Check formatting without writing
fmt-check:
    cargo +nightly fmt --all -- --check

# Generate documentation for all crates and open it in the browser.
doc:
    cargo doc --workspace --all-features --open

# cargo-deny (advisories / licenses / bans / sources)
# `all-features` is set in deny.toml [graph]; the CLI has no --all-features flag.
deny:
    cargo deny check

# Clean build artifacts
clean:
    cargo clean
