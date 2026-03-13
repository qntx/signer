# Makefile for signer workspace

.PHONY: all
all: pre-commit

# Build the project with all features enabled in release mode
.PHONY: build
build:
	cargo build --release --all-features

# Update dependencies to their latest compatible versions
.PHONY: update
update:
	cargo update

# Run all tests with all features enabled
.PHONY: test
test:
	cargo test --all-features

# Run benchmarks with all features enabled
.PHONY: bench
bench:
	cargo bench --all-features

# Run Clippy linter with nightly toolchain, fixing issues automatically
# and applying strict linting rules (uses workspace lints from Cargo.toml)
.PHONY: clippy
clippy:
	cargo +nightly clippy --fix \
		-p signer -p signer-btc -p signer-evm -p signer-svm \
		--all-targets \
		--all-features \
		--allow-dirty \
		--allow-staged \
		-- -D warnings

# Format the code using rustfmt with nightly toolchain
.PHONY: fmt
fmt:
	cargo +nightly fmt

# Generate documentation for all crates and open it in the browser
.PHONY: doc
doc:
	cargo +nightly doc --all-features --no-deps --open

# Generate CHANGELOG.md using git-cliff
.PHONY: cliff
cliff:
	git-cliff
	git cliff --output CHANGELOG.md

# Check for unused dependencies using cargo-udeps with nightly toolchain
.PHONY: udeps
udeps:
	cargo +nightly udeps --all-features

# Run pre-commit hooks on all files
.PHONY: pre-commit
pre-commit:
	$(MAKE) build
	$(MAKE) test
	$(MAKE) clippy
	$(MAKE) fmt
