# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Engineering Mindset — Senior Rust Developer

- Think through every implementation before writing code. Reason about ownership, lifetimes, error paths, and async boundaries up front.
- Small bites only. Break every task into the smallest meaningful, independently verifiable steps.
- If a design is non-obvious, state the reason before implementing.
- Write idiomatic, safe Rust. Favor clarity over cleverness. Use standard library types and traits where possible. Follow Rust API guidelines and community conventions.

## No Unsafe Code

Do NOT use `unsafe` blocks anywhere in this codebase. If a problem seems to require `unsafe`, find a safe alternative or raise it for discussion. No exceptions.

## Input Scrubbing

All external inputs must be validated before use. Use the shared validation module (`src/validation.rs`) so rules are consistent across CLI, API, and IPAM layers:

- Validate and normalize CIDR strings, IP addresses, prefix lengths
- Reject path traversal sequences, null bytes, and control characters in string inputs
- Enforce length limits on freeform text fields
- Use allowlists for enum-like values (status, format, backend names)

## Git Commit Rules

- Write concise, conventional commit messages (e.g., `fix:`, `feat:`, `refactor:`, `docs:`, `test:`).

## Security Filters

NEVER read, write, edit, list, display, copy, move, or otherwise access the following:

- `~/.ssh/` or any `.ssh/` directory and its contents (keys, config, known_hosts, etc.)
- `.env`, `.env.*`, `*.env` files (e.g., `.env.local`, `.env.production`, `prod.env`)
- `credentials.json`, `service-account*.json`, `*-credentials.*`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks` (private keys and keystores)
- `~/.aws/`, `~/.config/gcloud/`, `~/.azure/` (cloud provider credentials)
- `~/.gnupg/` (GPG keys)
- `*secret*`, `*token*` files (unless they are clearly source code, e.g., `token.rs`)
- `~/.netrc`, `~/.npmrc` with auth tokens, `~/.docker/config.json`

If the user asks you to access any of these, refuse and explain why.

## Workflow

When working on a ticket:

1. Create a GitHub issue for the work
2. Open a feature branch
3. Implement, commit, and push the branch
4. Update `CHANGELOG.md` with the changes (add to `[Unreleased]`)
5. Update `README.md` when changes affect user-facing behavior: new features, changed commands, new build targets, deprecations, or removed functionality
6. Create a PR — branch protection requires CI to pass before merge (no review required for solo maintainer)
7. After creating the PR, poll CI status with `gh pr checks <pr-number>`. Once all checks pass, merge immediately with `gh pr merge <pr-number> --squash --delete-branch` and prune local refs. Do not wait for manual approval.

### Post-commit documentation rules

After every commit (whether from a Linear ticket or not):

- **CHANGELOG.md**: Always add an entry under `[Unreleased]` for any meaningful change (features, fixes, refactors, CI changes, dependency updates). Only skip for typo fixes or whitespace-only changes.
- **README.md**: Update whenever there are important changes to the codebase — new or changed CLI commands, new build targets, new features, deprecation warnings, removed functionality, or changes to setup/install instructions. Do not update README for purely internal refactors or CI-only changes unless they affect the developer workflow (e.g., new `just` recipes).
- **SECURITY.md**: Update the supported versions table whenever a new version is released. Only the two most recent minor versions are supported (e.g., 0.13.x and 0.12.x). All older versions should be marked as unsupported.

### Versioning

This project uses semantic versioning. Version bumps happen **in the same PR** as the change when a release is intended:

- Bump `version` in `Cargo.toml`, move `[Unreleased]` entries to a dated `[X.Y.Z]` section in `CHANGELOG.md`, and update `SECURITY.md` if the minor version changed — all in the feature/fix PR
- After merging, trigger the release workflow immediately
- Not every PR needs a version bump — batch small changes under `[Unreleased]` and bump when ready to ship

### Task completion checklist

Every task is only "done" when ALL of the following are true:

1. **Tests exist and pass** — new functionality must have unit tests and/or integration tests. Run `just check` (or at minimum `cargo test`) and confirm zero failures before committing.
2. **Documentation updated** — CHANGELOG.md and README.md updated per the rules above.
3. **Plan/PRD checkboxes marked** — if the task comes from a plan, PRD, or TODO document with checkboxes, mark completed items as done (`- [x]`) in the same commit or immediately after.
4. **No regressions** — all pre-existing tests still pass. Do not merge if any test is broken.

## Release Process

Releases auto-trigger when a PR merged to `main` changes `Cargo.toml`. The workflow's `detect` job compares the old and new version; if the version bumped to a new `X.Y.Z` and no `vX.Y.Z` tag exists yet, the `release` job runs automatically. Manual `workflow_dispatch` is still available as a fallback (Actions → Release → Run workflow, enter the version without leading `v`).

The release job validates `Cargo.toml` version matches, confirms a CHANGELOG entry exists, extracts release notes, builds the release binary, and creates a GitHub release with tag `vX.Y.Z`. So the full release flow for a maintainer is: bump `Cargo.toml` + CHANGELOG in the PR, merge, done.

## Build & Development Commands

```bash
# Essential commands
just check          # Run fmt-check, lint, test, test-tui, test-mcp, and semgrep (use before commits)
just test           # Run all tests
just test-tui       # Run TUI tests (requires tui feature)
just lint           # Run clippy with -D warnings
just fmt            # Format code

# Build
just build          # Debug build (builds dashboard first)
just release        # Release build (builds dashboard first)
just dashboard      # Build React dashboard only (requires Node.js)
just dashboard-dev  # Run dashboard dev server with HMR
cargo install --path .  # Install binary locally

# Run single test
cargo test test_name

# API server
just serve          # Run on localhost:8080
just serve-debug    # Run with debug logging

# API server with config file and overrides
netcidr serve --config netcidr.toml
netcidr serve --enable-swagger --max-batch-size 500 --timeout 60

# Fuzz testing (requires: rustup toolchain install nightly && cargo install cargo-fuzz)
just fuzz                                      # Run fuzz_cidr_parsing for 60s
just fuzz fuzz_contains 30                     # Run specific target for 30s

# CLI usage
netcidr 192.168.1.0/24                  # IPv4 subnet info
netcidr 2001:db8::/48                   # IPv6 prefix info
netcidr split 10.0.0.0/8 -p 16 -n 10   # Generate 10 /16 subnets
netcidr split 10.0.0.0/8 -p 16 --max   # Generate all possible /16 subnets

# IPAM commands
netcidr ipam cidr_block create 10.0.0.0/8 --name "Corp"
netcidr ipam allocate <cidr_block-id> 10.0.1.0/24 --name "Web"
netcidr ipam auto-allocate <cidr_block-id> -p 24 -n 3
netcidr ipam utilization <cidr_block-id> --format text
netcidr ipam find-ip 10.0.1.50
netcidr ipam --db /path/to/db cidr_block list   # Custom DB path
```

Global options: `--format json|text|csv|yaml`, `--output <file>`

**Important**: Run `just setup` after cloning to install git hooks that enforce formatting and linting on commits.

## Architecture

This is a Rust CLI/API/MCP server for IPv4 and IPv6 subnet calculations with IPAM (IP Address Management).

**Core flow**: CLI (`main.rs`) parses args via clap (`cli.rs`) → routes to calculation modules (`ipv4.rs`, `ipv6.rs`, `subnet_generator.rs`) or IPAM operations (`ipam_cli.rs` → `ipam/operations.rs`) → formats output (`output.rs`).

**Key modules**:
- `ipv4.rs` / `ipv6.rs` - Subnet calculation logic using bitwise operations (u32/u128)
- `subnet_generator.rs` - Splits cidr_blocks into smaller subnets (supports `--count` or `--max`)
- `validation.rs` - Shared input validation (CIDR, IP, text fields, identifiers, status allowlist)
- `api.rs` - Axum HTTP server with REST endpoints sharing the same data structures as CLI
- `ipam/` - IPAM persistence layer: `operations.rs` (business logic), `store.rs` (trait), `sqlite/` (backend), `models.rs`, `config.rs`
- `ipam_cli.rs` - CLI handler for `netcidr ipam` subcommands
- `mcp.rs` - Rust-native MCP server using `rmcp` SDK (feature-gated: `mcp`), supports local or remote IPAM backend
- `mcp_client.rs` - HTTP client that proxies IPAM operations to a remote `netcidr serve` API (feature-gated: `mcp`)
- `error.rs` - Custom `NetcidrError` enum with `Result<T>` type alias used throughout
- `output.rs` - `TextOutput` / `CsvOutput` traits for JSON/text/CSV/YAML formatting

**Dashboard** (`dashboard/`): React + Vite + TypeScript SPA with Tailwind CSS. Built to a single `dashboard/dist/index.html` via `vite-plugin-singlefile`, embedded in the Rust binary with `include_str!`.

**Data structures** (`Ipv4Subnet`, `Ipv6Subnet`, IPAM models) are serializable and shared between CLI, API, and MCP server.

## Code Patterns

- Error handling: `thiserror` derive macros, all functions return `Result<T>`
- Logging: `tracing` with `#[instrument]` on API handlers
- CLI: clap derive with subcommands (`split`, `contains`, `from-range`, `summarize`, `completions`, `ipam`, `serve`, `mcp-serve`)
- Tests: Unit tests in modules, integration tests in `tests/` call binary via subprocess
