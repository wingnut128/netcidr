set shell := ["bash", "-euo", "pipefail", "-c"]

binary_name := "netcidr"
docker_image := "netcidr"
version := `grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'`
docker_tag := version

# Fuzz defaults (override: `just fuzz fuzz_contains 30`)
fuzz_target_default := "fuzz_cidr_parsing"
fuzz_duration_default := "60"

# List recipes
default:
    @just --list

# ──────────────────────────────── Build ─────────────────────────────────

# Build React dashboard (dashboard/dist/index.html)
dashboard:
    cd dashboard && bun install --frozen-lockfile && bun run build

# Run dashboard dev server with HMR (proxies API to localhost:8080)
dashboard-dev:
    cd dashboard && bun run dev

# Build debug binary (default features: swagger + dashboard)
build: dashboard
    cargo build

# Build release binary (default features: swagger + dashboard)
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

# Build debug binary with all features (swagger + tui + dashboard + mcp)
build-all-features: dashboard
    cargo build --all-features

# Build release binary with all features (swagger + tui + dashboard + mcp)
release-all-features: dashboard
    cargo build --release --all-features

# Build with MCP feature
build-mcp:
    cargo build --features mcp

# ──────────────────────────────── Test ──────────────────────────────────

# Run all tests
test:
    cargo test

# Run TUI tests (requires tui feature)
test-tui:
    cargo test --features tui

# Run MCP server tests
test-mcp:
    cargo test --features mcp mcp::

# Run tests with captured output visible
test-verbose:
    cargo test -- --nocapture

# ──────────────────────────────── Quality ───────────────────────────────

# Run clippy linter (fail on warnings)
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt -- --check

# Run semgrep security scanning
semgrep:
    semgrep scan --config=p/owasp-top-ten --config=p/rust --error .

# Run everything: fmt-check + lint + test + test-tui + test-mcp + semgrep
check: fmt-check lint test test-tui test-mcp semgrep

# Full CI pipeline (check + release build)
ci: check
    cargo build --release

# ──────────────────────────────── Fuzz ──────────────────────────────────

# Run fuzz testing (e.g. `just fuzz fuzz_contains 30`)
fuzz target=fuzz_target_default duration=fuzz_duration_default:
    cargo +nightly fuzz run {{target}} -- -max_total_time={{duration}}

# ──────────────────────────────── Docker ────────────────────────────────

# Build Docker image (tagged :<version> and :latest)
docker:
    docker build -t {{docker_image}}:{{docker_tag}} -t {{docker_image}}:latest .

# Run Docker container (API server on :8080)
docker-run:
    docker run --rm -p 8080:8080 {{docker_image}}:latest serve --address 0.0.0.0

# ──────────────────────────────── Install ───────────────────────────────

# Install binary locally (default features: swagger)
install:
    cargo install --path .

# Install binary locally with TUI feature
install-tui:
    cargo install --path . --features tui

# Install binary locally with all features
install-all-features:
    cargo install --path . --all-features

# Uninstall binary
uninstall:
    cargo uninstall {{binary_name}}

# ──────────────────────────────── Develop ───────────────────────────────

# Run API server locally
serve:
    cargo run -- serve

# Run API server with debug logging
serve-debug:
    cargo run -- serve --log-level debug

# Setup development environment (install git hooks)
setup:
    git config core.hooksPath .githooks
    @echo "Git hooks installed. Pre-commit will run fmt and clippy."

# Clean build artifacts
clean:
    cargo clean

# Print version (from Cargo.toml)
version:
    @echo {{version}}
