.PHONY: all build release test test-tui lint fmt clean docker docker-run help setup
.PHONY: build-tui release-tui build-no-default release-no-default build-all-features release-all-features
.PHONY: fuzz semgrep
.PHONY: install install-tui install-all-features uninstall
.PHONY: build-mcp test-mcp
.PHONY: dashboard dashboard-dev

# Variables
BINARY_NAME := netcidr
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
DOCKER_IMAGE := netcidr
DOCKER_TAG := $(VERSION)

# Default target
all: build

# Build React dashboard (produces dashboard/dist/index.html)
dashboard:
	cd dashboard && npm ci --silent && npm run build

# Run dashboard dev server with HMR (proxies API to localhost:8080)
dashboard-dev:
	cd dashboard && npm run dev

# Build debug binary (default features: swagger)
build: dashboard
	cargo build

# Build release binary (default features: swagger)
release: dashboard
	cargo build --release

# Build debug binary with TUI feature
build-tui:
	cargo build --features tui

# Build release binary with TUI feature
release-tui:
	cargo build --release --features tui

# Build debug binary without default features (no swagger, no dashboard)
build-no-default:
	cargo build --no-default-features

# Build release binary without default features (no swagger, no dashboard)
release-no-default:
	cargo build --release --no-default-features

# Build debug binary with all features (swagger + tui + dashboard)
build-all-features: dashboard
	cargo build --all-features

# Build release binary with all features (swagger + tui + dashboard)
release-all-features: dashboard
	cargo build --release --all-features

# Run all tests
test:
	cargo test

# Run TUI tests (requires tui feature)
test-tui:
	cargo test --features tui

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Run clippy linter
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting without modifying
fmt-check:
	cargo fmt -- --check

# Clean build artifacts
clean:
	cargo clean

# Build Docker image
docker:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .

# Run Docker container (API server)
docker-run:
	docker run --rm -p 8080:8080 $(DOCKER_IMAGE):latest serve --address 0.0.0.0

# Install locally (default features: swagger)
install:
	cargo install --path .

# Install locally with TUI feature
install-tui:
	cargo install --path . --features tui

# Install locally with all features
install-all-features:
	cargo install --path . --all-features

# Uninstall
uninstall:
	cargo uninstall $(BINARY_NAME)

# Run the API server locally
serve:
	cargo run -- serve

# Run with debug logging
serve-debug:
	cargo run -- serve --log-level debug

# Run fuzz testing (requires nightly + cargo-fuzz)
FUZZ_TARGET ?= fuzz_cidr_parsing
FUZZ_DURATION ?= 60

fuzz:
	cargo +nightly fuzz run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_DURATION)

# Build with MCP feature
build-mcp:
	cargo build --features mcp

# Run MCP server tests
test-mcp:
	cargo test --features mcp mcp::

# Run semgrep security scanning
semgrep:
	semgrep scan --config=p/owasp-top-ten --config=p/rust --error .

# Check everything (format, lint, tests, semgrep security scan)
check: fmt-check lint test test-tui test-mcp semgrep

# CI pipeline target
ci: check
	cargo build --release

# Setup development environment (install git hooks)
setup:
	git config core.hooksPath .githooks
	@echo "Git hooks installed. Pre-commit will run fmt and clippy."

# Print version
version:
	@echo $(VERSION)

# Help
help:
	@echo "netcidr Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build Targets:"
	@echo "  build                  Build debug binary (default features: swagger)"
	@echo "  release                Build release binary (default features: swagger)"
	@echo "  build-tui              Build debug binary with TUI feature"
	@echo "  release-tui            Build release binary with TUI feature"
	@echo "  build-no-default       Build without defaults (no swagger/dashboard)"
	@echo "  release-no-default     Release without defaults (no swagger/dashboard)"
	@echo "  build-all-features     Build debug binary with all features"
	@echo "  release-all-features   Build release binary with all features"
	@echo "  build-mcp              Build with MCP feature"
	@echo ""
	@echo "Test Targets:"
	@echo "  test                   Run all tests"
	@echo "  test-tui               Run TUI tests (requires tui feature)"
	@echo "  test-mcp               Run MCP server tests"
	@echo "  test-verbose           Run tests with output"
	@echo "  lint                   Run clippy linter"
	@echo "  fmt                    Format code"
	@echo "  fmt-check              Check formatting"
	@echo "  check                  Run fmt-check, lint, test, and semgrep"
	@echo "  semgrep                Run semgrep security scanning"
	@echo ""
	@echo "Docker Targets:"
	@echo "  docker                 Build Docker image"
	@echo "  docker-run             Run API server in Docker"
	@echo ""
	@echo "Install Targets:"
	@echo "  install                Install binary locally (default features: swagger)"
	@echo "  install-tui            Install binary locally with TUI feature"
	@echo "  install-all-features   Install binary locally with all features"
	@echo "  uninstall              Uninstall binary"
	@echo ""
	@echo "Fuzz Targets:"
	@echo "  fuzz                   Run fuzz testing (FUZZ_TARGET=name FUZZ_DURATION=secs)"
	@echo ""
	@echo "Dashboard Targets:"
	@echo "  dashboard              Build React dashboard (requires Node.js)"
	@echo "  dashboard-dev          Run dashboard dev server with HMR"
	@echo ""
	@echo "Development Targets:"
	@echo "  serve                  Run API server locally"
	@echo "  serve-debug            Run API server with debug logging"
	@echo "  setup                  Setup git hooks for development"
	@echo "  clean                  Clean build artifacts"
	@echo ""
	@echo "Other Targets:"
	@echo "  ci                     Full CI pipeline"
	@echo "  version                Print version"
	@echo "  help                   Show this help"
