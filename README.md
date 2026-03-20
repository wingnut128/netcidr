# ipcalc

[![CI](https://github.com/wingnut128/ipcalc/actions/workflows/ci.yml/badge.svg)](https://github.com/wingnut128/ipcalc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/wingnut128/ipcalc/actions/workflows/codeql.yml/badge.svg)](https://github.com/wingnut128/ipcalc/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast IPv4 and IPv6 subnet calculator written in Rust. Available as a CLI tool, HTTP API, and MCP server for AI assistants.

## Features

- **IPv4 subnet calculations**: network address, broadcast, subnet mask, wildcard mask, host ranges, network class detection
- **IPv6 prefix calculations**: network address, address ranges, hextet breakdown, address type detection (global unicast, link-local, ULA, etc.)
- **Subnet splitting**: generate N subnets of a given prefix from a supernet, or count available subnets
- **Subnet summarization**: aggregate multiple CIDRs into the minimal covering set
- **Range to CIDR**: convert an arbitrary IP range (start–end) into the minimal set of CIDR blocks
- **Address containment**: check if an IP address belongs to a CIDR range
- **Interactive TUI**: Terminal user interface with real-time calculations and split mode (optional feature)
- **Batch processing**: process multiple CIDRs via positional arguments, `--stdin`, or the `POST /batch` API endpoint
- **Multiple output formats**: JSON (default), plain text, CSV, and YAML
- **File output**: write results directly to a file
- **Web dashboard**: Full SPA at `http://localhost:8080/` with subnet calculator, splitter, contains check, summarize, from-range, IPAM dashboard, and subnet visualizer — served automatically when running `ipcalc serve`
- **HTTP API**: REST endpoints for all calculations
- **OpenAPI documentation**: Machine-readable API specification for easy integration with tools like Swagger Editor, Postman, and Insomnia
- **MCP server**: [Model Context Protocol](https://modelcontextprotocol.io) server for AI assistant integration (Claude, etc.) over stdio
- **IPAM (IP Address Management)**: IPv4 and IPv6 allocation tracking with conflict detection, audit trail, utilization reporting, reservation TTL/expiry, and JSON export/import — available via CLI (`ipcalc ipam`) and REST API (`ipcalc serve --ipam-enabled`)
- **Configurable security**: rate limiting, request size limits, timeouts, restrictive CORS, and security headers
- **TOML configuration**: server settings via config file with CLI flag overrides

## Installation

### From Source

```bash
git clone https://github.com/wingnut128/ipcalc.git
cd ipcalc
cargo build --release
```

The binary will be at `target/release/ipcalc`.

### Using Cargo

```bash
cargo install --path .
```

## Usage

### Subnet Calculation

The CLI auto-detects IPv4 or IPv6 based on the CIDR notation:

```bash
# JSON output (default)
ipcalc 192.168.1.0/24

# Plain text output
ipcalc 192.168.1.0/24 --format text

# CSV output (spreadsheet-importable)
ipcalc 192.168.1.0/24 --format csv

# YAML output (IaC-friendly)
ipcalc 192.168.1.0/24 --format yaml

# Output to file
ipcalc 10.0.0.0/8 -o results.json

# IPv6 prefix
ipcalc 2001:db8::/32
ipcalc fe80::1/64 --format text
```

Example JSON output:
```json
{
  "input": "192.168.1.0/24",
  "network_address": "192.168.1.0",
  "broadcast_address": "192.168.1.255",
  "subnet_mask": "255.255.255.0",
  "wildcard_mask": "0.0.0.255",
  "prefix_length": 24,
  "first_host": "192.168.1.1",
  "last_host": "192.168.1.254",
  "total_hosts": 256,
  "usable_hosts": 254,
  "network_class": "C",
  "is_private": true
}
```

### Subnet Splitting

Generate smaller subnets from a larger supernet:

```bash
# Generate 10 /27 subnets from a /22
ipcalc split 192.168.0.0/22 -p 27 -n 10

# Generate all possible /27 subnets from a /22
ipcalc split 192.168.0.0/22 -p 27 --max

# Show only how many /27 subnets fit in a /22 (no generation)
ipcalc split 192.168.0.0/22 -p 27 --count-only

# Generate 5 /48 subnets from a /32
ipcalc split 2001:db8::/32 -p 48 -n 5
```

### Subnet Summarization

Aggregate multiple CIDRs into the minimal covering set:

```bash
# Summarize adjacent IPv4 subnets
ipcalc summarize 192.168.0.0/24 192.168.1.0/24

# Summarize IPv6 prefixes
ipcalc summarize 2001:db8::/48 2001:db8:1::/48

# Text output
ipcalc summarize 10.0.0.0/24 10.0.1.0/24 10.0.2.0/23 --format text
```

### Range to CIDR

Convert an arbitrary IP range into the minimal set of CIDR blocks:

```bash
# IPv4 range
ipcalc from-range 192.168.1.10 192.168.1.20

# IPv6 range
ipcalc from-range 2001:db8::1 2001:db8::ff

# Text output
ipcalc from-range 192.168.1.10 192.168.1.20 --format text
```

### Address Containment

Check if an IP address is contained within a subnet:

```bash
# IPv4 — JSON output
ipcalc contains 192.168.1.0/24 192.168.1.100

# IPv4 — text output
ipcalc contains 192.168.1.0/24 10.0.0.1 --format text

# IPv6
ipcalc contains 2001:db8::/32 2001:db8::1
```

### Batch Processing

Process multiple CIDRs in a single invocation:

```bash
# Multiple CIDRs as positional arguments
ipcalc 192.168.1.0/24 10.0.0.0/8 172.16.0.0/12

# Read CIDRs from stdin (one per line, blank lines and # comments skipped)
cat cidrs.txt | ipcalc --stdin

# Combine with any output format
echo -e "192.168.1.0/24\n10.0.0.0/8" | ipcalc --stdin --format yaml
```

Invalid CIDRs in a batch are reported per-entry without failing the entire operation.

### Interactive TUI

Launch an interactive terminal user interface for real-time subnet calculations and splitting:

```bash
# Build with TUI support
cargo build --release --features tui

# Run the TUI
ipcalc --tui
```

**TUI Features:**

- **Calculate Mode**: Enter any CIDR notation for instant subnet information display
  - Network address, netmask, broadcast address
  - First/last host, total hosts
  - Real-time validation and updates

- **Split Mode**: Interactive subnet splitting with live results
  - Press **TAB** to switch between Calculate and Split modes
  - Enter CIDR, target prefix length, and count
  - Press **M** to toggle MAX mode for generating all possible subnets
  - Use **↑↓** arrow keys to scroll through generated subnet lists
  - Press **ENTER** to cycle through input fields

- **Keyboard Controls**:
  - `TAB` - Switch between Calculate and Split modes
  - `ENTER` - Move to next input field (Split mode)
  - `M` - Toggle MAX mode for subnet count (Split mode)
  - `↑↓` - Scroll through results
  - `ESC` - Quit

The TUI automatically detects IPv4/IPv6 and provides color-coded input fields with real-time error messages.

**Note:** The TUI feature is optional and must be enabled at build time with the `tui` feature flag. It is not included in the default build to keep the binary size smaller.

### Shell Completions

Generate tab-completion scripts for your shell:

```bash
# Bash (add to ~/.bashrc)
eval "$(ipcalc completions bash)"

# Zsh (add to ~/.zshrc)
eval "$(ipcalc completions zsh)"

# Fish (add to ~/.config/fish/config.fish)
ipcalc completions fish | source

# Elvish
eval (ipcalc completions elvish | slurp)

# PowerShell (add to $PROFILE)
ipcalc completions powershell | Out-String | Invoke-Expression
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

### MCP Server (AI Assistant Integration)

The MCP server lets AI assistants like Claude use ipcalc as a tool for subnet calculations. It communicates over stdio using the [Model Context Protocol](https://modelcontextprotocol.io). Built natively in Rust using the official `rmcp` SDK — no Node.js required.

```bash
# Build with MCP support
cargo build --release --features mcp

# Or use make
make build-mcp
```

**Calculator tools** (always available):

| Tool | Description |
|------|-------------|
| `subnet_calc` | Calculate IPv4/IPv6 subnet details from CIDR notation |
| `subnet_split` | Split a supernet into smaller subnets |
| `contains_check` | Check if an IP address is within a CIDR range |
| `from_range` | Convert an IP address range to minimal CIDR blocks |
| `summarize` | Aggregate CIDRs into the minimal covering set |

**IPAM tools** (enabled with `--ipam-db`):

| Tool | Description |
|------|-------------|
| `ipam_create_supernet` | Create a new supernet (top-level address space) |
| `ipam_list_supernets` | List all supernets |
| `ipam_allocate` | Auto-allocate next-available CIDR block(s) |
| `ipam_allocate_specific` | Allocate a specific CIDR block |
| `ipam_release` | Release an allocation |
| `ipam_list_allocations` | List allocations (filterable by status/env/owner) |
| `ipam_free_blocks` | Find free blocks in a supernet |
| `ipam_utilization` | Get utilization statistics |
| `ipam_find_ip` | Find allocations containing an IP |
| `ipam_find_resource` | Find allocations by resource ID |

#### Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "ipcalc": {
      "command": "/absolute/path/to/ipcalc",
      "args": ["mcp-serve"]
    }
  }
}
```

With IPAM enabled (local database):

```json
{
  "mcpServers": {
    "ipcalc": {
      "command": "/absolute/path/to/ipcalc",
      "args": ["mcp-serve", "--ipam-db", "/path/to/ipam.db"]
    }
  }
}
```

With IPAM via remote API server (connects to a running `ipcalc serve`):

```json
{
  "mcpServers": {
    "ipcalc": {
      "command": "/absolute/path/to/ipcalc",
      "args": ["mcp-serve", "--api-url", "http://localhost:8080"]
    }
  }
}
```

> **Note:** `--ipam-db` and `--api-url` are mutually exclusive. Use `--api-url` when IPAM state must be shared across multiple MCP clients or when the MCP server runs on a different host.

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "ipcalc": {
      "command": "/absolute/path/to/ipcalc",
      "args": ["mcp-serve"]
    }
  }
}
```

### HTTP API Server

```bash
# Start server on default port 8080
ipcalc serve

# Custom address and port
ipcalc serve --address 0.0.0.0 --port 3000

# With logging
ipcalc serve --log-level debug --log-file /var/log/ipcalc.log

# With TOML config file
ipcalc serve --config ipcalc.toml

# With CLI overrides
ipcalc serve --enable-swagger --max-batch-size 500 --timeout 60
```

#### Server Configuration

The server can be configured via a TOML file (`--config`) and/or CLI flags. CLI flags override config file values, and unspecified options use defaults.

Example `ipcalc.toml`:

```toml
max_batch_size = 10000        # Max CIDRs per batch request (default: 10,000)
max_generated_cidrs = 1000000 # Max CIDRs from from-range (default: 1,000,000)
max_summarize_inputs = 10000  # Max input CIDRs for summarize (default: 10,000)
max_body_size = 1048576       # Max request body in bytes (default: 1 MB)
rate_limit_per_second = 20    # Sustained rate limit per IP (default: 20; 0 = disabled)
rate_limit_burst = 50         # Burst allowance per IP (default: 50)
timeout_seconds = 30          # Request timeout (default: 30s)
enable_swagger = false        # Swagger UI at /swagger-ui (default: false)
```

**Security defaults**: All endpoints are protected by per-IP rate limiting, request body size limits, request timeouts, restrictive CORS (no origins allowed by default), and security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`).

#### API Endpoints

| Endpoint | Description | Example |
|----------|-------------|---------|
| `GET /health` | Health check | `/health` |
| `GET /version` | Version information | `/version` |
| `GET /v4?cidr=<cidr>` | IPv4 calculation | `/v4?cidr=192.168.1.0/24` |
| `GET /v6?cidr=<cidr>` | IPv6 calculation | `/v6?cidr=2001:db8::/32` |
| `GET /v4/split?cidr=<cidr>&prefix=<n>&count=<n>` | Split IPv4 supernet | `/v4/split?cidr=10.0.0.0/8&prefix=16&count=5` |
| `GET /v6/split?cidr=<cidr>&prefix=<n>&count=<n>` | Split IPv6 supernet | `/v6/split?cidr=2001:db8::/32&prefix=48&count=10` |
| `GET /v4/split?cidr=<cidr>&prefix=<n>&count_only=true` | Count available IPv4 subnets | `/v4/split?cidr=10.0.0.0/8&prefix=16&count_only=true` |
| `GET /v6/split?cidr=<cidr>&prefix=<n>&count_only=true` | Count available IPv6 subnets | `/v6/split?cidr=2001:db8::/32&prefix=48&count_only=true` |
| `GET /v4/contains?cidr=<cidr>&address=<ip>` | Check IPv4 containment | `/v4/contains?cidr=192.168.1.0/24&address=192.168.1.100` |
| `GET /v6/contains?cidr=<cidr>&address=<ip>` | Check IPv6 containment | `/v6/contains?cidr=2001:db8::/32&address=2001:db8::1` |
| `GET /v4/summarize?cidrs=<cidr>,<cidr>` | Summarize IPv4 CIDRs | `/v4/summarize?cidrs=192.168.0.0/24,192.168.1.0/24` |
| `GET /v6/summarize?cidrs=<cidr>,<cidr>` | Summarize IPv6 CIDRs | `/v6/summarize?cidrs=2001:db8::/48,2001:db8:1::/48` |
| `GET /v4/from-range?start=<ip>&end=<ip>` | IPv4 range to CIDRs | `/v4/from-range?start=192.168.1.10&end=192.168.1.20` |
| `GET /v6/from-range?start=<ip>&end=<ip>` | IPv6 range to CIDRs | `/v6/from-range?start=2001:db8::1&end=2001:db8::ff` |
| `POST /batch` | Batch CIDR processing | See example below |
| `GET /swagger-ui` | Interactive Swagger UI (requires `--enable-swagger`) | `/swagger-ui` |
| `GET /api-docs/openapi.json` | OpenAPI 3.0 specification (requires `--enable-swagger`) | `/api-docs/openapi.json` |

All GET endpoints accept an optional `format` query parameter (`json`, `text`, `csv`, `yaml`) and `pretty=true` for indented JSON.

#### Example API Requests

```bash
# IPv4 calculation
curl "http://localhost:8080/v4?cidr=192.168.1.0/24"

# IPv6 calculation
curl "http://localhost:8080/v6?cidr=2001:db8::/32"

# Split a /22 into /27 subnets
curl "http://localhost:8080/v4/split?cidr=192.168.0.0/22&prefix=27&count=10"

# Check if address is in subnet
curl "http://localhost:8080/v4/contains?cidr=192.168.1.0/24&address=192.168.1.100"

# Count available subnets without generating them
curl "http://localhost:8080/v4/split?cidr=10.0.0.0/8&prefix=16&count_only=true"

# Summarize CIDRs
curl "http://localhost:8080/v4/summarize?cidrs=192.168.0.0/24,192.168.1.0/24"

# Convert IP range to CIDRs
curl "http://localhost:8080/v4/from-range?start=192.168.1.10&end=192.168.1.20"

# Batch processing (mixed IPv4/IPv6, auto-detected)
curl -X POST "http://localhost:8080/batch" \
  -H "Content-Type: application/json" \
  -d '{"cidrs": ["192.168.1.0/24", "2001:db8::/32"]}'

# Any endpoint with CSV or YAML output
curl "http://localhost:8080/v4?cidr=192.168.1.0/24&format=csv"
curl "http://localhost:8080/v4?cidr=192.168.1.0/24&format=yaml"

# Get OpenAPI specification (requires --enable-swagger)
curl "http://localhost:8080/api-docs/openapi.json"
```

#### OpenAPI Documentation

The API provides interactive Swagger UI documentation and a complete OpenAPI 3.0 specification. Swagger UI is disabled by default and must be enabled with `--enable-swagger`:

```bash
# Start server with Swagger UI enabled
ipcalc serve --enable-swagger

# Access interactive Swagger UI in your browser
open http://localhost:8080/swagger-ui

# Get the OpenAPI spec
curl http://localhost:8080/api-docs/openapi.json > openapi.json

# Import into Postman
# Import the openapi.json file into Postman to generate a collection

# Import into Swagger Editor
# Visit https://editor.swagger.io and import the openapi.json file

# Use with other tools
# The spec is compatible with Insomnia, API clients, and code generators
```

**Interactive Features:**
- Try out API endpoints directly from the browser at `/swagger-ui`
- View request/response schemas with examples
- Execute requests and see live responses

**Building with PostgreSQL IPAM backend:**

```bash
cargo build --release --features ipam-postgres
```

**Building without OpenAPI support:**

The OpenAPI documentation feature is optional and enabled by default. To build a smaller binary without it:

```bash
cargo build --release --no-default-features
```

## CLI Reference

```
ipcalc [OPTIONS] [CIDR]... [COMMAND]

Arguments:
  [CIDR]...  IP address(es) in CIDR notation (e.g., 192.168.1.0/24 or 2001:db8::/48)

Commands:
  split       Generate subnets from a supernet
  from-range  Convert an IP range (start–end) into minimal CIDR blocks
  contains    Check if an IP address is contained in a subnet
  summarize   Summarize/aggregate CIDRs into the minimal covering set
  ipam        IP Address Management — track allocations, supernets, and free space
  completions Generate shell completions for the given shell
  serve       Start the HTTP API server
  help        Print help for a command

Options:
  -f, --format <FORMAT>  Output format [default: json] [possible values: json, text, csv, yaml]
  -o, --output <OUTPUT>  Output file path (prints to stdout if not specified)
      --stdin            Read CIDRs from standard input (one per line)
      --tui              Launch interactive TUI mode (requires tui feature)
  -h, --help             Print help
  -V, --version          Print version
```

**Notes:**
- Multiple CIDRs can be passed as positional arguments for batch processing
- The `--stdin` flag reads CIDRs from stdin (blank lines and `#` comments are skipped)
- The legacy `v4` and `v6` CLI subcommands have been removed; use `ipcalc <cidr>` directly
- The `--tui` flag is only available when built with the `tui` feature: `cargo build --features tui`

## Docker

```bash
# Build the image
docker build -t ipcalc .

# Run CLI
docker run --rm ipcalc 192.168.1.0/24

# Run API server
docker run --rm -p 8080:8080 ipcalc serve --address 0.0.0.0
```

## Development

```bash
# Setup git hooks (required for development)
make setup

# Build
make build

# Run tests
make test

# Run linter
make lint

# Build release binary
make release

# Build with MCP feature
make build-mcp

# Run MCP tests
make test-mcp

# Run semgrep security scanning
make semgrep

# Build Docker image
make docker
```

The `make setup` command installs a pre-commit hook that automatically runs `cargo fmt --check` and `cargo clippy` before each commit.

`make check` runs formatting, linting, all tests (including TUI and MCP), and Semgrep security scanning.

### Fuzz Testing

Fuzz tests use [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) with libFuzzer to verify that all parsing functions return `Result` errors (never panic) on arbitrary input.

**Prerequisites:**

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

**Running fuzz tests:**

```bash
# Run the default target (fuzz_cidr_parsing) for 60 seconds
make fuzz

# Run a specific target for a custom duration
make fuzz FUZZ_TARGET=fuzz_contains FUZZ_DURATION=30
```

**Available targets:**

| Target | What it fuzzes |
|--------|---------------|
| `fuzz_cidr_parsing` | `Ipv4Subnet::from_cidr`, `Ipv6Subnet::from_cidr` |
| `fuzz_contains` | `check_ipv4_contains`, `check_ipv6_contains` |
| `fuzz_from_range` | `from_range_ipv4`, `from_range_ipv6` |
| `fuzz_subnet_ops` | `count_subnets`, `generate_ipv4_subnets`, `generate_ipv6_subnets` |

## IPAM (IP Address Management)

The IPAM module provides library-level IP address allocation tracking with a pluggable storage backend.

**Current capabilities:**

- **Supernet management** — define top-level address spaces (e.g. `10.0.0.0/8`) with overlap detection
- **Allocation lifecycle** — allocate specific CIDRs or auto-allocate next-available blocks, update metadata, release
- **Conflict detection** — prevents overlapping allocations within a supernet
- **Free space discovery** — find available blocks by prefix length, with utilization reporting
- **Reverse lookup** — find allocations by IP address or resource ID
- **Audit trail** — immutable log of all mutations (create, update, release)
- **Tags** — flexible key-value metadata on allocations

**Storage backends:**

- **SQLite** (default) — zero-config, WAL mode, r2d2 connection pooling, embedded schema migrations
- **PostgreSQL** — opt-in via `--features ipam-postgres`, uses `sqlx` with async connection pooling; configure with `--ipam-backend postgres --ipam-db-url <url>`
- **Pluggable design** — the `IpamStore` async trait allows additional backends via feature flags

**CLI usage:**

```bash
# Create a supernet
ipcalc ipam supernet create 10.0.0.0/8 --name "Corporate Network"

# List supernets
ipcalc ipam supernet list --format text

# Allocate a specific block
ipcalc ipam allocate <supernet-id> 10.0.1.0/24 --name "Web Tier" --environment production

# Auto-allocate next available /24s
ipcalc ipam auto-allocate <supernet-id> -p 24 -n 3 --name "App Tier"

# Check utilization
ipcalc ipam utilization <supernet-id> --format text

# Find free blocks
ipcalc ipam free-blocks <supernet-id> -p 24

# Look up which allocation contains an IP
ipcalc ipam find-ip 10.0.1.50

# View audit log
ipcalc ipam audit --limit 10

# IPv6 IPAM — same commands, IPv6 CIDRs
ipcalc ipam supernet create 2001:db8::/32 --name "IPv6 Space"
ipcalc ipam allocate <supernet-id> 2001:db8:1::/48 --name "Site A"
ipcalc ipam auto-allocate <supernet-id> -p 48 -n 5
ipcalc ipam find-ip 2001:db8:1::50

# Use a specific database file
ipcalc ipam --db /path/to/my.db supernet list
```

**Database location** (precedence order): `--db` flag > `IPCALC_DB` env var > `db_path` in config file > `~/.local/share/ipcalc/ipcalc.db`

**REST API:**

Enable IPAM endpoints on the HTTP server with `--ipam-enabled`:

```bash
# Start server with IPAM enabled
ipcalc serve --ipam-enabled

# Use a specific database file
ipcalc serve --ipam-enabled --ipam-db /path/to/ipam.db
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ipam/supernets` | `POST` | Create a supernet |
| `/ipam/supernets` | `GET` | List all supernets |
| `/ipam/supernets/{id}` | `GET` | Get supernet details |
| `/ipam/supernets/{id}` | `DELETE` | Delete supernet (must have no active allocations) |
| `/ipam/supernets/{id}/allocate` | `POST` | Auto-allocate next-available block(s) |
| `/ipam/supernets/{id}/allocate-specific` | `POST` | Allocate a specific CIDR |
| `/ipam/supernets/{id}/allocations` | `GET` | List allocations (filterable by status, owner, etc.) |
| `/ipam/supernets/{id}/free` | `GET` | Find free blocks (optional `?prefix=N` filter) |
| `/ipam/supernets/{id}/utilization` | `GET` | Utilization report |
| `/ipam/allocations/{id}` | `GET` | Get allocation details |
| `/ipam/allocations/{id}` | `PATCH` | Update allocation metadata |
| `/ipam/allocations/{id}/release` | `POST` | Release an allocation |
| `/ipam/allocations/{id}/tags` | `PUT` | Set tags on an allocation |
| `/ipam/find-ip/{address}` | `GET` | Find allocations containing an IP |
| `/ipam/find-resource/{resource_id}` | `GET` | Find allocations by resource ID |
| `/ipam/audit` | `GET` | Query audit log (filterable) |

**Status:** Fully integrated — available via CLI (`ipcalc ipam`), REST API (`ipcalc serve --ipam-enabled`), and MCP server (`ipcalc mcp-serve --ipam-db <path>`).

## License

MIT License - see [LICENSE](LICENSE) for details.
