.PHONY: all check lint fmt fmt-check test build release clean

all: check lint test

check:
	cargo check --workspace --all-targets --all-features

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

test:
	cargo test --workspace --all-features

build:
	cargo build

release:
	cargo build --release --bin gatee

clean:
	cargo clean
