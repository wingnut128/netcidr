# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Legacy Node.js MCP server (`mcp-server/`) — fully superseded by Rust-native implementation in `src/mcp.rs`

### Fixed

- CI and CodeQL workflows now run on all PRs, fixing deadlock where docs-only PRs could never satisfy required checks
- Removed stale `javascript-typescript` language from CodeQL matrix (no JS/TS source remains)

### Changed

- Reorganized planning and PRD documents into `.context/` directory
- Removed obsolete `TODO-ipam.md` and `prd/` directory
- Updated SECURITY.md supported versions table
- Added SECURITY.md update rule to CLAUDE.md post-commit documentation guidelines
## [0.13.1] - 2026-03-07

### Added

- IPAM persistence layer with SQLite backend for tracking IP address allocations
  - `IpamStore` async trait defining a pluggable storage backend interface
  - `SqliteStore` implementation with r2d2 connection pooling and WAL mode
  - Supernet management (create, list, get, delete with active-allocation guard)
  - Allocation lifecycle (create, auto-allocate, update, release with conflict detection)
  - Free space discovery and utilization reporting
  - IP address and resource ID reverse lookup
  - Immutable audit log for all mutations
  - Flexible key-value tags on allocations
  - DB path resolution: CLI flag > env var > config file > XDG default
  - Embedded schema migrations with version tracking
- IPAM CLI integration via `ipcalc ipam` subcommand with full command suite:
  - `ipam supernet create/list/get/delete` — manage top-level address spaces
  - `ipam allocate` / `ipam auto-allocate` — specific or next-available allocation
  - `ipam allocation get/list/update` — query and update allocations
  - `ipam release` — mark allocations as released
  - `ipam utilization` / `ipam free-blocks` — capacity reporting
  - `ipam find-ip` / `ipam find-resource` — reverse lookup
  - `ipam audit` — query the immutable audit log
- IPAM REST API endpoints via `ipcalc serve --ipam-enabled`:
  - `POST /ipam/supernets` — create supernet; `GET` — list all
  - `GET /ipam/supernets/{id}` — get supernet; `DELETE` — delete (guarded by active allocations)
  - `POST /ipam/supernets/{id}/allocate` — auto-allocate next-available blocks
  - `POST /ipam/supernets/{id}/allocate-specific` — allocate a specific CIDR
  - `GET /ipam/supernets/{id}/allocations` — list allocations with filters
  - `GET /ipam/supernets/{id}/free` — free block discovery
  - `GET /ipam/supernets/{id}/utilization` — utilization report
  - `GET /ipam/allocations/{id}` — get allocation; `PATCH` — update metadata
  - `POST /ipam/allocations/{id}/release` — release allocation
  - `PUT /ipam/allocations/{id}/tags` — set tags
  - `GET /ipam/find-ip/{address}` — reverse lookup by IP
  - `GET /ipam/find-resource/{resource_id}` — reverse lookup by resource
  - `GET /ipam/audit` — query audit log
- OpenAPI/Swagger documentation for all IPAM REST endpoints (requires `--enable-swagger`)
  - `ipam tags get/set` — manage key-value tags on allocations
  - `--db <path>` flag for database location override
  - All output formats supported (JSON, text, CSV, YAML)
- Rust-native MCP (Model Context Protocol) server replacing the Node.js implementation
  - Uses `rmcp` (official Rust SDK) with `#[tool]` macros for zero-overhead tool definitions
  - Calls library functions directly instead of shelling out to the binary
  - 5 calculator tools: `subnet_calc`, `subnet_split`, `contains_check`, `from_range`, `summarize`
  - 10 IPAM tools: `ipam_create_supernet`, `ipam_list_supernets`, `ipam_allocate`, `ipam_allocate_specific`, `ipam_release`, `ipam_list_allocations`, `ipam_free_blocks`, `ipam_utilization`, `ipam_find_ip`, `ipam_find_resource`
  - IPAM tools enabled via `ipcalc mcp-serve --ipam-db <path>`
  - Runs via `ipcalc mcp-serve` subcommand over stdio transport
  - Enabled with `--features mcp` cargo feature flag
  - 15 unit tests covering all tools and error paths
- Full web application dashboard replacing the IPAM-only dashboard
  - 7-page SPA using Alpine.js with hash-based routing
  - Subnet Calculator with bit-grid visualization for IPv4/IPv6
  - Subnet Splitter, Contains Check, Summarize, From Range tools
  - IPAM Dashboard with utilization charts (Chart.js), search, tag management
  - Subnet Visualizer with address space map and split distribution chart
  - Brutalist Industrial design: monospace everything, high-contrast dark theme, thick borders
  - Dashboard always served at `/` and `/dashboard` (no longer requires IPAM)
  - `GET /features` endpoint for frontend feature detection (IPAM, Swagger)
  - Responsive layout with sidebar collapsing to bottom bar on mobile
- Shared input validation module (`src/validation.rs`) for CIDR, IP, text field, and identifier scrubbing
  - Centralized length checks, control character rejection, and path traversal detection
- PostgreSQL IPAM storage backend (feature-gated behind `ipam-postgres`)
  - `PostgresStore` implementing the `IpamStore` trait using `sqlx` with `PgPool`
  - Embedded schema migrations matching the SQLite schema (uses `SMALLINT`, `BIGINT`, `BIGSERIAL`)
  - Backend selection via `--ipam-backend postgres` CLI flag
  - Connection URL via `--ipam-db-url`, `IPCALC_IPAM_DB_URL` env var, or `[ipam.postgres]` config
  - Configurable connection pool (`max_connections`, `min_connections`)
  - `Backend` enum and `PostgresConfig` in IPAM config module
  - Docker-based PostgreSQL integration tests
  - Replaces inline `MAX_INPUT_LENGTH` in `ipv4.rs` and `ipv6.rs`
  - Wired into all IPAM `IpamOps` public methods

## [0.12.0] - 2026-03-02

### Removed

- **BREAKING**: Removed deprecated `v4` and `v6` CLI subcommands — use `ipcalc <cidr>` directly (deprecated since v0.1.7)
- Removed unused `tower_governor` dependency from `Cargo.toml`

### Refactored

- Extracted `ipv4_mask()` and `ipv6_mask()` helpers to eliminate duplicated mask calculation across `ipv4.rs`, `ipv6.rs`, `contains.rs`, and `summarize.rs`
- Deduplicated `TextOutput` implementations for `SummaryResult` and `FromRangeResult` pairs via macros
- Simplified `logging.rs` initialization from 4 near-identical subscriber blocks to 2 (JSON vs plain) with shared writer setup
- Extracted `handle_result` helper in `main.rs` to collapse 10 repetitive match/Ok/Err blocks
- Unified `count_subnets` IPv4/IPv6 branches into a single validation flow in `subnet_generator.rs`
- Extracted `validate_and_summarize` helper to deduplicate `summarize_ipv4_with_limit` / `summarize_ipv6_with_limit`
- Simplified `init_logging` return type from `Option<WorkerGuard>` to `WorkerGuard`

## [0.11.1] - 2026-02-27

### Added

- `make semgrep` target for security scanning with Semgrep (p/owasp-top-ten and p/rust rulesets)
- Semgrep added to `make check` pipeline

### Fixed

- Release workflow: fixed 6 shell injection findings by routing `inputs.version` through environment variable instead of inline `${{ }}` interpolation in `run:` steps
- Fixed nosemgrep annotation in `config.rs` to use full rule ID so suppression takes effect

### Changed

- CI: replaced tag-triggered release workflow with `workflow_dispatch` release workflow that validates Cargo.toml version, extracts CHANGELOG release notes, and creates GitHub release with cross-platform binaries
- CI: removed `mcp-server/**` from `paths-ignore` in CI and CodeQL workflows
- CI: added `mcp-server` job with TypeScript lint, build, and test steps
- CodeQL: added `javascript-typescript` to language scanning matrix
- CodeQL: upgraded `github/codeql-action` from v3 to v4 ahead of v3 deprecation

## [0.11.0] - 2026-02-25

### Added

- MCP (Model Context Protocol) server for AI assistant integration via stdio transport
  - TypeScript implementation in `mcp-server/` using `@modelcontextprotocol/sdk`
  - 5 tools: `subnet_calc`, `subnet_split`, `contains_check`, `from_range`, `summarize`
  - Delegates all calculations to the `ipcalc` binary (JSON output)
  - Auto-detects IPv4 vs IPv6 from input
  - 13 unit tests covering all tools and error paths
- MCP server setup instructions in README for Claude Code and Claude Desktop
- `make build-mcp` / `make test-mcp` targets
- `test-mcp` added to `make check` pipeline

## [0.10.0] - 2026-02-20

### Changed

- Restructured `Ipv4Subnet` to store IP addresses as native `Ipv4Addr` instead of `String`, eliminating parse-format-reparse overhead
- Restructured `Ipv6Subnet` to store `network`/`last` as native `Ipv6Addr` instead of `String`
- JSON API output unchanged — backward compatibility preserved via `#[serde(rename)]` attributes
- Replaced `split('/').collect::<Vec<&str>>()` with `split_once('/')` in CIDR parsing for both IPv4 and IPv6
- Optimized `Ipv6Subnet::format_full` from `Vec<String>` intermediate allocation to a single `format!()` call
- Improved error-masking tests across all modules to assert specific `IpCalcError` variants instead of generic `is_err()` checks

### Fixed

- TUI: `c`/`C` and `m`/`M` keys were unconditionally captured by shortcut handlers, preventing IPv6 hex address entry in the CIDR input field

## [0.9.0] - 2026-02-19

### Added

- TOML config file support (`--config path`) for server settings
- CLI flags for all configurable limits (`--max-batch-size`, `--max-range-cidrs`, `--max-summarize-inputs`, `--max-body-size`, `--rate-limit-per-second`, `--rate-limit-burst`, `--timeout`)
- `--enable-swagger` flag to opt-in to Swagger UI (disabled by default)
- CSV output format (`--format csv`, `?format=csv`) for spreadsheet-importable subnet data
- YAML output format (`--format yaml`, `?format=yaml`) for IaC workflow integration
- `format` query parameter on all API endpoints supporting `json`, `text`, `csv`, and `yaml`
- Batch CIDR processing via multiple positional arguments
- `--stdin` flag for reading CIDRs from standard input
- `POST /batch` API endpoint with mixed IPv4/IPv6 auto-detection
- Partial failure tolerance for invalid CIDRs in batch operations
- Fuzz testing with `cargo-fuzz` and `libfuzzer-sys` for CIDR parsing, address containment, range conversion, and subnet operations
- `make fuzz` target with configurable `FUZZ_TARGET` and `FUZZ_DURATION`

### Security

- Request body size limit (default 1 MB), configurable via `max_body_size`
- Batch size cap (default 10K), from-range output cap (default 1M), summarize input cap (default 10K)
- Per-IP rate limiting support via `tower_governor` (configurable burst/sustained)
- Request timeout (default 30s), configurable via `timeout_seconds`
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`
- Restrictive CORS policy (no origins allowed by default)
- Swagger UI disabled by default, opt-in via `--enable-swagger` flag
- Graceful shutdown on SIGTERM/SIGINT
- Response builder `.unwrap()` replaced with safe fallbacks
- Bind-address warning when using non-loopback addresses
- Input length validation (256 byte max) on CIDR parsing
- Dockerfile HEALTHCHECK directive

### Changed

- Added Rust build caching (`Swatinem/rust-cache@v2`) to CodeQL CI workflow for faster analysis runs

## [0.8.1] - 2026-02-11

### Added

- 29 unit tests for TUI `AppState` methods, gated behind `#[cfg(all(test, feature = "tui"))]`
- `make test-tui` target and added it to `make check` for CI coverage

### Changed

- Organized `lib.rs` with crate-level documentation and module grouping by domain
- Removed unused `IpCalcError` re-export from public API
- Updated CLAUDE.md with `test-tui` build command and workflow instructions

## [0.8.0] - 2026-02-10

### Added

- `from-range` CLI subcommand to convert arbitrary IP address ranges to minimal CIDR notation
- `GET /v4/from-range` and `GET /v6/from-range` API endpoints with OpenAPI documentation
- Automatic IPv4/IPv6 detection for range-to-CIDR conversion
- JSON and text output formats for range conversion results
- Unit and integration tests for IP range to CIDR conversion

## [0.7.0] - 2026-02-10

### Added

- `summarize` CLI subcommand to aggregate adjacent/overlapping CIDR ranges into the minimal covering set
- `GET /v4/summarize` and `GET /v6/summarize` API endpoints with OpenAPI documentation
- Automatic IPv4/IPv6 detection for summarize command
- JSON and text output formats for summarization results
- Unit and integration tests for CIDR summarization

## [0.6.1] - 2026-02-10

### Added

- IPv4 `address_type` field classifying network addresses into 16 RFC-referenced special-use ranges (RFC 1918, RFC 6598, RFC 5737, RFC 1122, RFC 3927, RFC 6890, RFC 7526, RFC 2544, RFC 5771, RFC 1112)
- IPv6 Documentation range detection for `2001:db8::/32` → `Documentation (RFC 3849)`
- RFC references added to all IPv6 address type strings (e.g., `Loopback` → `Loopback (RFC 4291)`)

## [0.6.0] - 2026-02-10

### Added

- `count-only=true` hyphenated query parameter alias for API split endpoints (web-friendly convention alongside `count_only=true`)
- TUI count-only mode: press `C` in Split mode to show available subnet count without generating subnets
- API test for hyphenated `count-only` query parameter

## [0.5.0] - 2026-02-10

### Added

- `--count-only` CLI flag and `count_only=true` API query parameter to return the available subnet count via pure math with zero allocation
- `SplitSummary` struct for count-only responses (JSON and text output)
- Hard limit of 1,000,000 on generated subnets to prevent out-of-memory on large splits
- `SubnetLimitExceeded` error variant with descriptive message guiding users to `--count-only` or `-n`
- 5 new CLI integration tests and 3 new API integration tests for count-only and limit enforcement

### Fixed

- Out-of-memory crash when splitting large IPv6 supernets (e.g., /64 → /96 = 4.3B subnets)

## [0.4.1] - 2026-02-09

### Added

- 15 in-process API integration tests covering all 8 HTTP endpoints using tower's `oneshot()` pattern
- `tower` and `http-body-util` dev-dependencies for API test infrastructure

## [0.4.0] - 2026-02-09

### Added

- `contains` CLI subcommand to check if an IP address belongs to a CIDR range (IPv4 and IPv6)
- `GET /v4/contains` and `GET /v6/contains` API endpoints for address containment checks
- New `ContainsResult` data structure shared between CLI and API
- Unit and integration tests for containment checks

## [0.3.2] - 2026-02-07

### Security

- Updated `bytes` from 1.11.0 to 1.11.1 — fixes integer overflow in `BytesMut::reserve`
- Updated `time` from 0.3.45 to 0.3.47 — fixes stack exhaustion Denial of Service
- Deprecated v0.3.1 release due to vulnerable transitive dependencies

### Changed

- Added personality, commit rules, and security filters to CLAUDE.md

## [0.3.1] - 2026-01-20

### Added

- Optional `?pretty=true` query parameter for API endpoints to format JSON output with indentation
- Improved API readability for browser and debugging use cases

### Security

- Fixed RUSTSEC-2026-0002 / GHSA-rhfx-m35p-ff5j: Updated `ratatui` from 0.26 to 0.30, which resolves low severity vulnerability in `lru` crate (IterMut Stacked Borrows violation)
- Updated `lru` transitive dependency from 0.12.5 to 0.16.3 (patched version)

### Changed

- Updated deprecated `Frame::size()` call to `Frame::area()` for ratatui 0.30 compatibility
- API responses default to compact JSON for optimal performance

## [0.3.0] - 2026-01-20 [YANKED]

**This version has been yanked due to a security vulnerability in a transitive dependency. Please use 0.3.1 or later.**

### Added

- Interactive Terminal User Interface (TUI) mode with dual-mode operation (optional `tui` feature)
  - Calculate mode for real-time subnet information display
  - Split mode for interactive subnet generation with scrollable results
  - TAB key to switch between Calculate and Split modes
  - Support for MAX mode to generate all possible subnets
  - Arrow key navigation for scrolling through generated subnet lists
  - Color-coded input fields with active field highlighting
  - Real-time validation and error messages
  - Automatic IPv4/IPv6 detection
- `--tui` command-line flag to launch TUI mode (only available when built with `tui` feature)
- Optional dependencies: `ratatui`, `crossterm`, and `ipnet` for TUI functionality

### Changed

- TUI feature is opt-in and not included in default builds to maintain smaller binary size
- Module structure reorganized: `tui` module now part of `lib.rs` instead of `main.rs`

## [0.2.1] - 2026-01-16

### Fixed

- Swagger endpoints now only appear in help text when swagger feature is enabled

## [0.2.0] - 2026-01-16

### Added

- OpenAPI 3.0 documentation for all API endpoints via optional `swagger` feature (enabled by default)
- New `/api-docs/openapi.json` endpoint to retrieve OpenAPI specification
- Comprehensive schema documentation for all request/response types
- Support for importing API spec into Swagger Editor, Postman, Insomnia, and other tools

### Changed

- API documentation is now machine-readable and can be consumed by API tooling
- Binary can be built without swagger support using `--no-default-features` for smaller size

## [0.1.8] - 2026-01-16

### Changed

- CLI now displays help message when run without arguments instead of showing an error
- Improved user experience with exit code 0 (success) when showing help

## [0.1.7] - 2026-01-16

### Added

- Direct CIDR notation support: use `ipcalc <cidr>` instead of subcommands
- Auto-detection of IPv4 vs IPv6 based on input format
- Integration tests for direct CIDR input and deprecation warnings

### Changed

- Simplified CLI interface - CIDR can now be passed directly as a positional argument
- Users should now use `ipcalc 192.168.1.0/24` instead of `ipcalc v4 192.168.1.0/24`

### Deprecated

- `v4` subcommand - use `ipcalc <cidr>` instead
- `v6` subcommand - use `ipcalc <cidr>` instead

## [0.1.6] - 2026-01-16

### Fixed

- Broken pipe panic when output is piped to commands like `head`

## [0.1.5] - 2025-01-16

### Changed

- Updated axum from 0.7 to 0.8
- Updated thiserror from 1 to 2
- Updated tower-http from 0.5 to 0.6

## [0.1.4] - 2025-01-16

### Added

- `--max` (`-m`) option for split command to generate maximum number of subnets possible
- API support for `max=true` query parameter on `/v4/split` and `/v6/split` endpoints

### Changed

- IPv6 help text now uses "prefix" terminology instead of "CIDR" for consistency with IPv6 conventions
- IPv6 example in help changed from `/32` to `/48` (more typical enterprise allocation)
- Split command now requires either `--count` or `--max` (mutually exclusive)

## [0.1.3] - 2025-01-16

### Added

- CI and license status badges to README

### Fixed

- Code formatting to comply with rustfmt standards

## [0.1.2] - 2025-01-16

### Added

- Pre-commit git hook for automated linting and format checks
- `make setup` command to install git hooks for development

## [0.1.1] - 2025-01-16

### Added

- CI workflow with automated testing, linting, and format checks
- CodeQL security scanning (on push, PR, and weekly schedule)
- cargo-audit for dependency vulnerability scanning

## [0.1.0] - 2025-01-16

### Added

- IPv4 subnet calculation with network address, broadcast, subnet mask, wildcard mask, host ranges
- IPv4 network class detection (A, B, C, D, E) and private address identification
- IPv6 prefix calculation with full hextet expansion
- IPv6 address type detection (global unicast, link-local, ULA, multicast, loopback)
- Subnet generator to split supernets into smaller subnets
- CLI interface with `v4`, `v6`, `split`, and `serve` commands
- JSON output format (default)
- Plain text output format (`--format text`)
- File output option (`-o, --output`)
- HTTP API server with REST endpoints
- API endpoints: `/health`, `/v4`, `/v6`, `/v4/split`, `/v6/split`
- Structured logging with tracing (stdout, file output, JSON format)
- Configurable log levels (trace, debug, info, warn, error)
- HTTP request tracing via tower-http
- Unit tests for IPv4, IPv6, and subnet generation
- Integration tests for CLI
- Dockerfile for containerized deployment
- Makefile for common development tasks

[Unreleased]: https://github.com/wingnut128/ipcalc/compare/v0.13.1...HEAD
[0.13.1]: https://github.com/wingnut128/ipcalc/compare/v0.12.0...v0.13.1
[0.12.0]: https://github.com/wingnut128/ipcalc/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/wingnut128/ipcalc/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/wingnut128/ipcalc/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/wingnut128/ipcalc/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/wingnut128/ipcalc/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/wingnut128/ipcalc/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/wingnut128/ipcalc/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/wingnut128/ipcalc/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/wingnut128/ipcalc/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/wingnut128/ipcalc/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/wingnut128/ipcalc/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/wingnut128/ipcalc/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/wingnut128/ipcalc/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/wingnut128/ipcalc/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/wingnut128/ipcalc/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/wingnut128/ipcalc/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/wingnut128/ipcalc/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/wingnut128/ipcalc/compare/v0.1.8...v0.2.0
[0.1.8]: https://github.com/wingnut128/ipcalc/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/wingnut128/ipcalc/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/wingnut128/ipcalc/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wingnut128/ipcalc/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wingnut128/ipcalc/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wingnut128/ipcalc/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wingnut128/ipcalc/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wingnut128/ipcalc/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wingnut128/ipcalc/releases/tag/v0.1.0
