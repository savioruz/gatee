.PHONY: all help build test lint fmt fmt-check audit check release clean setup

all: check lint test

help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_.-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

setup: ## One-time setup (git hooks)
	git config core.hooksPath .githooks

##@ Build

build: ## Build (debug, default features)
	cargo build

check: ## Check-only (fast feedback, all features)
	cargo check --workspace --all-targets --all-features

release: ## Build release binary (bin gatee)
	cargo build --release --bin gatee

##@ Tests

test: ## Run workspace tests
	cargo test --workspace --all-features

##@ Code quality

lint: ## Lint with clippy (warnings are errors)
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt: ## Format code
	cargo fmt --all

fmt-check: ## Check formatting
	cargo fmt --all -- --check

audit: ## Scan dependencies for known vulnerabilities
	cargo audit

clean: ## Clean build artifacts
	cargo clean
