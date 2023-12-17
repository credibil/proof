-include .env
export AZURE_TENANT_ID := $(value AZURE_TENANT_ID)
export AZURE_CLIENT_ID := $(value AZURE_CLIENT_ID)
export AZURE_CLIENT_SECRET := $(value AZURE_CLIENT_SECRET)
export AZURE_KEY_VAULT := $(value AZURE_KEY_VAULT)
export AZURE_ION_CHALLENGE_URL := $(value AZURE_ION_CHALLENGE_URL)
export AZURE_ION_SOLUTION_URL := $(value AZURE_ION_SOLUTION_URL)
export AZURE_ION_RESOLUTION_URL := $(value AZURE_ION_RESOLUTION_URL)
export RUST_LOG := $(value RUST_LOG)

.PHONY: build clean test test-kv test-e2e docs style lint dev egion

build:
	@cargo build --release

clean:
	@cargo clean

TESTS = ""
test:
	cargo nextest run --workspace --all-features --no-capture

test-kv:
	cargo nextest run --all-features --run-ignored ignored-only -E 'package(azure-kv)' --no-capture

test-e2e:
	cargo nextest run --all-features --run-ignored ignored-only -E 'package(test)' --no-capture

docs: build
	cargo doc --no-deps

style:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

dev:
	cargo run

# Run the did-ion example (examples/ion)
ex-ion:
	cargo run --bin ion
