# PRD: IPAM Persistence Layer

**Status:** Draft
**Created:** 2026-03-02
**Author:** mlapane

---

## 1. Problem Statement

netcidr currently operates as a stateless calculator — it computes subnet details, splits, containment checks, and summarizations on demand but retains no knowledge of prior allocations. The VPC allocation trial against `100.64.0.0/10` demonstrated that while the MCP server can generate allocation plans, there is no mechanism to:

- Track which blocks have been allocated vs. free
- Prevent overlapping or conflicting allocations
- Record metadata (VPC ID, environment, owner, purpose)
- Audit allocation history over time
- Reclaim deallocated space

Without persistence, every planning session starts from scratch and relies on the operator to maintain external records. This limits netcidr's usefulness as a lightweight IPAM tool.

## 2. Goals

1. **Allocation tracking** — Persist supernet definitions and individual block allocations with metadata
2. **Conflict detection** — Reject allocations that overlap with existing ones within the same supernet
3. **Free space visibility** — Query what's available in a supernet without manual calculation
4. **Audit trail** — Record when allocations were created, modified, and released
5. **Multi-interface parity** — Expose IPAM operations through CLI, API, and MCP server equally
6. **Zero-config default** — Work out of the box with an embedded database; no external services required
7. **Pluggable storage backend** — Define a trait-based abstraction so the persistence layer is not locked to a single database engine; SQLite ships as the default, PostgreSQL can be added without changing business logic

## 3. Non-Goals

- RBAC or authentication (defer to API layer / reverse proxy)
- DHCP or DNS integration
- Real-time sync with cloud provider APIs (AWS, GCP, Azure)
- IPv6 IPAM in v1 (design for it, but implement IPv4 first)
- GUI or web dashboard

## 4. Background

### Current Architecture

```
CLI (clap) ──┐
API (axum) ──┼──> Core Library (ipv4.rs, ipv6.rs, subnet_generator.rs, ...)
MCP (node) ──┘         │
                   Pure computation — no state
```

### Key Observations from VPC Trial

| Metric | Value |
|--------|-------|
| Supernet | `100.64.0.0/10` (4.19M IPs) |
| Allocated | 10 x /20 VPCs (40,960 IPs) |
| Per-VPC | 3 pub /23 + 3 priv /23 + 1 free /22 |
| Utilization | 0.98% |
| Free capacity | 1,014 more /20s available |

The trial produced a static HTML snapshot. A persistence layer would make this a living, queryable allocation registry.

## 5. Proposed Architecture

### Pluggable Storage Backend

The persistence layer is defined by an `IpamStore` trait. All IPAM business logic programs against this trait, never against a concrete database driver. Backend implementations are selected at startup via configuration and compiled in via Cargo features.

```
CLI (clap) ──┐                                    ┌─ SqliteStore (default)
API (axum) ──┼──> Core Library ──> ipam module ──> IpamStore trait ──┼─ PostgresStore (feature: "ipam-postgres")
MCP (node) ──┘    (existing)       (new)                             │
                       │
               Pure computation
               (unchanged)
```

The existing stateless calculation modules remain untouched. A new `ipam` module sits alongside them and uses them internally for validation and computation. The `IpamStore` trait boundary ensures that adding a new backend never requires changes to business logic, CLI wiring, API handlers, or MCP tools.

### Backend: SQLite (Default)

**Rationale for default:**
- Embedded — no external services, no Docker dependency, no network config
- Single-file database — easy to backup, version, and migrate
- Well-supported in Rust via `rusqlite` (or `sqlx` with SQLite driver)
- WAL mode gives good read concurrency for the API server
- Fits the "zero-config default" goal — database file auto-created on first use

**SQLite database location (precedence order):**
1. `--db <path>` CLI flag
2. `NETCIDR_DB` environment variable
3. `db_path` in `netcidr.toml` config
4. Default: `$XDG_DATA_HOME/netcidr/netcidr.db` (or `~/.local/share/netcidr/netcidr.db`)

### Backend: PostgreSQL (Optional)

**When to use:** Teams that already run PostgreSQL and want row-level locking, multi-writer concurrency, or integration with existing infrastructure.

**Driver:** `sqlx` with `postgres` feature, or `tokio-postgres`.

### Storage Trait Design

```rust
/// Core storage abstraction. All methods take &self and return
/// Result<T> — backends manage their own connection pooling internally.
#[async_trait]
pub trait IpamStore: Send + Sync {
    // --- lifecycle ---
    async fn initialize(&self) -> Result<()>;
    async fn migrate(&self) -> Result<()>;

    // --- supernets ---
    async fn create_supernet(&self, input: CreateSupernet) -> Result<Supernet>;
    async fn get_supernet(&self, id: &str) -> Result<Supernet>;
    async fn list_supernets(&self) -> Result<Vec<Supernet>>;
    async fn delete_supernet(&self, id: &str) -> Result<()>;

    // --- allocations ---
    async fn create_allocation(&self, input: CreateAllocation) -> Result<Allocation>;
    async fn get_allocation(&self, id: &str) -> Result<Allocation>;
    async fn list_allocations(&self, filter: AllocationFilter) -> Result<Vec<Allocation>>;
    async fn update_allocation(&self, id: &str, input: UpdateAllocation) -> Result<Allocation>;
    async fn release_allocation(&self, id: &str) -> Result<Allocation>;
    async fn find_allocations_in_supernet(&self, supernet_id: &str, status: &[&str]) -> Result<Vec<Allocation>>;

    // --- tags ---
    async fn set_tags(&self, allocation_id: &str, tags: &[(String, String)]) -> Result<()>;
    async fn get_tags(&self, allocation_id: &str) -> Result<Vec<(String, String)>>;

    // --- audit ---
    async fn append_audit(&self, entry: AuditEntry) -> Result<()>;
    async fn query_audit(&self, filter: AuditFilter) -> Result<Vec<AuditEntry>>;
}
```

**Key design decisions:**
- `async_trait` — all backends can be async (SQLite can use `spawn_blocking` internally)
- `Send + Sync` — safe to share across Axum handler tasks and Tokio threads
- Input/output types are backend-agnostic Rust structs defined in `ipam::models`
- Conflict detection lives in the `ipam::operations` layer *above* the trait — it reads existing allocations via the trait, runs overlap logic in pure Rust, then calls back into the trait to persist. This keeps validation identical across all backends.
- Each backend owns its own migration strategy (embedded SQL, `sqlx` migrations, etc.)

### Backend Construction

A factory function selects the backend at startup based on configuration:

```rust
pub async fn create_store(config: &IpamConfig) -> Result<Arc<dyn IpamStore>> {
    match config.backend {
        Backend::Sqlite => {
            let store = SqliteStore::new(&config.sqlite).await?;
            store.migrate().await?;
            Ok(Arc::new(store))
        }
        #[cfg(feature = "ipam-postgres")]
        Backend::Postgres => {
            let store = PostgresStore::new(&config.postgres).await?;
            store.migrate().await?;
            Ok(Arc::new(store))
        }
    }
}
```

The resulting `Arc<dyn IpamStore>` is injected into Axum state, passed to CLI command handlers, and used by the IPAM operations layer.

## 6. Data Model

### Tables

#### `supernets`

Defines the top-level address pools that IPAM manages.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | TEXT | PK | UUID v4 |
| `cidr` | TEXT | NOT NULL, UNIQUE | e.g. `100.64.0.0/10` |
| `network_address` | TEXT | NOT NULL | e.g. `100.64.0.0` |
| `broadcast_address` | TEXT | NOT NULL | e.g. `100.127.255.255` |
| `prefix_length` | INTEGER | NOT NULL | e.g. `10` |
| `total_hosts` | INTEGER | NOT NULL | Total IP count |
| `name` | TEXT | | Human-readable label |
| `description` | TEXT | | Purpose or notes |
| `ip_version` | INTEGER | NOT NULL | `4` or `6` |
| `created_at` | TEXT | NOT NULL | ISO 8601 timestamp |
| `updated_at` | TEXT | NOT NULL | ISO 8601 timestamp |

#### `allocations`

Individual CIDR block allocations within a supernet.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | TEXT | PK | UUID v4 |
| `supernet_id` | TEXT | FK → supernets.id | Parent supernet |
| `cidr` | TEXT | NOT NULL | Allocated block, e.g. `100.64.0.0/20` |
| `network_address` | TEXT | NOT NULL | Computed network address |
| `broadcast_address` | TEXT | NOT NULL | Computed broadcast address |
| `prefix_length` | INTEGER | NOT NULL | Prefix length |
| `total_hosts` | INTEGER | NOT NULL | Total IP count in allocation |
| `resource_id` | TEXT | | External reference (e.g. `vpc-a1f04e01`) |
| `resource_type` | TEXT | | Type tag (e.g. `vpc`, `subnet`, `transit-gw`) |
| `name` | TEXT | | Human-readable label |
| `description` | TEXT | | Notes |
| `environment` | TEXT | | e.g. `production`, `staging`, `development` |
| `owner` | TEXT | | Team or individual |
| `status` | TEXT | NOT NULL DEFAULT 'active' | `active`, `reserved`, `released` |
| `parent_allocation_id` | TEXT | FK → allocations.id, NULLABLE | For hierarchical allocations (VPC → subnets) |
| `created_at` | TEXT | NOT NULL | ISO 8601 |
| `updated_at` | TEXT | NOT NULL | ISO 8601 |
| `released_at` | TEXT | | Set when status → released |

**Indexes:**
- `idx_allocations_supernet` on `(supernet_id, status)`
- `idx_allocations_resource` on `(resource_id)`
- `idx_allocations_parent` on `(parent_allocation_id)`
- `idx_allocations_cidr` on `(cidr)`

#### `allocation_tags`

Flexible key-value metadata for allocations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `allocation_id` | TEXT | FK → allocations.id | |
| `key` | TEXT | NOT NULL | Tag key |
| `value` | TEXT | NOT NULL | Tag value |

**Composite PK:** `(allocation_id, key)`

#### `audit_log`

Immutable record of all IPAM mutations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK AUTOINCREMENT | |
| `timestamp` | TEXT | NOT NULL | ISO 8601 |
| `action` | TEXT | NOT NULL | `create_supernet`, `allocate`, `release`, `update`, `delete_supernet` |
| `entity_type` | TEXT | NOT NULL | `supernet` or `allocation` |
| `entity_id` | TEXT | NOT NULL | UUID of affected record |
| `details` | TEXT | | JSON blob with before/after or contextual data |

## 7. Core Operations

### 7.1 Supernet Management

| Operation | Description |
|-----------|-------------|
| `create_supernet(cidr, name?, description?)` | Register a new address pool. Validates CIDR. Rejects if it overlaps an existing supernet. |
| `list_supernets()` | List all registered supernets with utilization summary. |
| `get_supernet(id)` | Get supernet details including allocation count and free space. |
| `delete_supernet(id)` | Remove supernet. Fails if it has active allocations. |

### 7.2 Allocation Lifecycle

| Operation | Description |
|-----------|-------------|
| `allocate(supernet_id, prefix, count?, resource_id?, resource_type?, name?, env?, owner?, tags?, parent_id?)` | Allocate the next available block(s) of the given prefix length. Returns allocated CIDRs. |
| `allocate_specific(supernet_id, cidr, ...)` | Allocate a specific CIDR block. Fails if it overlaps an existing active allocation. |
| `release(allocation_id)` | Mark allocation as released. Sets `released_at`. Does not delete — preserves audit trail. |
| `get_allocation(id)` | Get full allocation details including tags and child allocations. |
| `list_allocations(supernet_id?, status?, resource_type?, env?, owner?)` | Filtered listing of allocations. |
| `update_allocation(id, name?, description?, env?, owner?, tags?)` | Update mutable metadata fields. Cannot change CIDR or supernet. |

### 7.3 Query Operations

| Operation | Description |
|-----------|-------------|
| `free_blocks(supernet_id, prefix?)` | List available free blocks. If prefix specified, show how many /N blocks can fit. |
| `utilization(supernet_id)` | Return allocated vs. total IPs, percentage, allocation count. |
| `find_by_ip(address)` | Find which allocation(s) contain a given IP address. |
| `find_by_resource(resource_id)` | Look up allocation by external resource ID. |

### 7.4 Conflict Detection Algorithm

On every `allocate` or `allocate_specific`:

1. Parse and validate the candidate CIDR
2. Verify it falls within the target supernet (`contains_check`)
3. Query all `active` or `reserved` allocations in the supernet
4. For each existing allocation, check bidirectional containment:
   - Does the candidate contain the existing block?
   - Does the existing block contain the candidate?
   - Do they overlap at all? (compare network ranges)
5. Reject with a clear error if any overlap is found, naming the conflicting allocation

For `allocate` (auto-assign), the algorithm walks the supernet's address space, skipping over allocated regions, and finds the first gap large enough for the requested prefix.

## 8. Interface Specifications

### 8.1 CLI

New subcommand: `netcidr ipam <action>`

```
netcidr ipam init                                 # Initialize DB (auto on first use)
netcidr ipam supernet add 100.64.0.0/10 --name "CGN Pool"
netcidr ipam supernet list
netcidr ipam supernet show <id>
netcidr ipam supernet remove <id>

netcidr ipam allocate <supernet-id> --prefix 20 --count 10 \
    --resource-type vpc --env production --owner platform-team
netcidr ipam allocate-specific <supernet-id> --cidr 100.64.0.0/20 \
    --resource-id vpc-a1f04e01 --resource-type vpc
netcidr ipam release <allocation-id>
netcidr ipam list [--supernet <id>] [--status active] [--env production]
netcidr ipam show <allocation-id>
netcidr ipam update <allocation-id> --owner new-team --env staging

netcidr ipam free <supernet-id> [--prefix 20]
netcidr ipam utilization <supernet-id>
netcidr ipam find-ip 100.64.5.42
netcidr ipam find-resource vpc-a1f04e01
netcidr ipam audit [--entity <id>] [--action allocate] [--limit 50]
```

All commands respect `--format json|text|csv|yaml` and `--output <file>`.

### 8.2 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ipam/supernets` | Create supernet |
| GET | `/ipam/supernets` | List supernets |
| GET | `/ipam/supernets/:id` | Get supernet detail |
| DELETE | `/ipam/supernets/:id` | Delete supernet |
| POST | `/ipam/supernets/:id/allocate` | Auto-allocate block(s) |
| POST | `/ipam/supernets/:id/allocate-specific` | Allocate specific CIDR |
| GET | `/ipam/supernets/:id/allocations` | List allocations in supernet |
| GET | `/ipam/supernets/:id/free` | List free blocks |
| GET | `/ipam/supernets/:id/utilization` | Utilization stats |
| GET | `/ipam/allocations/:id` | Get allocation detail |
| PATCH | `/ipam/allocations/:id` | Update allocation metadata |
| POST | `/ipam/allocations/:id/release` | Release allocation |
| GET | `/ipam/find-ip/:address` | Find allocation by IP |
| GET | `/ipam/find-resource/:resource_id` | Find allocation by resource |
| GET | `/ipam/audit` | Query audit log |

### 8.3 MCP Tools

New tools exposed through the MCP server, following the existing pattern of wrapping CLI invocations:

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ipam_create_supernet` | cidr, name?, description? | Register address pool |
| `ipam_list_supernets` | — | List all supernets with utilization |
| `ipam_allocate` | supernet_id, prefix, count?, resource_id?, resource_type?, name?, env?, owner? | Auto-allocate blocks |
| `ipam_allocate_specific` | supernet_id, cidr, resource_id?, resource_type?, name?, env?, owner? | Allocate specific CIDR |
| `ipam_release` | allocation_id | Release an allocation |
| `ipam_list_allocations` | supernet_id?, status?, resource_type?, env? | Query allocations |
| `ipam_free_blocks` | supernet_id, prefix? | Show available space |
| `ipam_utilization` | supernet_id | Utilization stats |
| `ipam_find_ip` | address | Reverse-lookup an IP |
| `ipam_find_resource` | resource_id | Lookup by external ID |

## 9. Implementation Approach

### Phase 1: Storage Trait & SQLite Backend (Foundation)

- Create `src/ipam/` module directory:
  - `mod.rs` — public API surface and `create_store` factory
  - `store.rs` — `IpamStore` trait definition
  - `models.rs` — backend-agnostic Rust structs (Supernet, Allocation, AuditEntry, filter/input types)
  - `operations.rs` — business logic layer (allocate, release, conflict detection) that calls `&dyn IpamStore`
  - `sqlite/mod.rs` — `SqliteStore` implementation
  - `sqlite/migrations.rs` — embedded schema migrations for SQLite
- Add `rusqlite` dependency with `bundled` feature (zero system deps, always compiled)
- Implement `IpamStore` for `SqliteStore` with WAL mode, connection pooling via `r2d2`
- Implement conflict detection in `operations.rs` using existing `contains` module — backend-agnostic
- Unit tests for all operations using in-memory SQLite behind `&dyn IpamStore`
- Integration tests verifying the trait contract (these become reusable for future backends)

### Phase 2: CLI Integration

- Add `ipam` subcommand tree to `cli.rs`
- Wire subcommands to `ipam::operations`
- Implement `TextOutput` and `CsvOutput` for all IPAM response types
- Integration tests exercising CLI → DB round-trips

### Phase 3: API Integration

- Add `/ipam/` route group to `api.rs`
- Inject `Arc<dyn IpamStore>` into Axum state (backend-agnostic)
- Request-scoped transactions for write operations (each backend handles internally)
- Swagger/OpenAPI schema generation for new endpoints

### Phase 4: MCP Integration

- Add new tool registrations in `src/mcp.rs` (Rust-native MCP server)
- Each tool calls library functions directly (no subprocess overhead)
- Type-safe input validation via `schemars` and `rmcp` derive macros
- Integration tests

### Phase 5: Free Space & Utilization Engine

- Implement the free-block-finder algorithm:
  1. Load all active allocations for a supernet, sorted by network address
  2. Walk the address space, identifying gaps
  3. For each gap, compute the largest aligned CIDR blocks that fit
  4. If a target prefix is requested, count how many fit
- Utilization rollup: allocated IPs / total IPs with breakdown by status

### Phase 6: Additional Storage Backends

- **PostgreSQL** (`src/ipam/postgres/`):
  - Feature-gated behind `ipam-postgres` Cargo feature
  - `sqlx` with `postgres` runtime for async connection pooling
  - Native `INET`/`CIDR` column types where beneficial
  - Row-level locking for multi-writer concurrency
  - `sqlx` migrations embedded in binary
  - Reuse Phase 1 trait-contract tests against a PostgreSQL testcontainer
- Each backend ships as an opt-in feature — only SQLite compiles by default to keep the dependency tree lean

## 10. Migration Strategy

Each backend owns its own migration mechanism, but all follow the same contract:

1. On startup, the backend's `migrate()` method is called
2. It checks the current schema version
3. Applies any pending migrations in order
4. Records each applied migration

### SQLite

A `schema_version` table with embedded migrations as Rust constants:

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
```

Migrations are compiled into the binary — no external SQL files to manage.

### PostgreSQL

Use `sqlx::migrate!()` macro with SQL files in `migrations/postgres/`. The macro embeds them at compile time, so deployments are still single-binary with no runtime file dependencies. The migration directory contains dialect-specific SQL (e.g., PostgreSQL `INET` types).

## 11. Configuration Additions

New fields in `netcidr.toml`:

```toml
[ipam]
enabled = true
backend = "sqlite"                 # "sqlite" | "postgres"
auto_init = true                   # create/migrate DB on first use

[ipam.sqlite]
db_path = "/path/to/netcidr.db"    # optional; default: $XDG_DATA_HOME/netcidr/netcidr.db
wal_mode = true                    # WAL for read concurrency

[ipam.postgres]
url = "postgresql://user:pass@host:5432/netcidr"
max_connections = 10
min_connections = 2

```

New CLI flags on `netcidr serve`:

```
--ipam-backend <name>  Storage backend: sqlite, postgres (default: sqlite)
--ipam-db <path>       Override SQLite database path
--ipam-db-url <url>    Connection URL for postgres backend
--ipam-enabled         Enable IPAM endpoints (default: true if DB exists)
```

Environment variables (override config file, overridden by CLI flags):

```
NETCIDR_IPAM_BACKEND=sqlite|postgres
NETCIDR_IPAM_DB=/path/to/netcidr.db          # sqlite
NETCIDR_IPAM_DB_URL=postgresql://...         # postgres
```

## 12. Observability

- All IPAM operations logged via `tracing` with `#[instrument]`
- Audit log queryable via CLI, API, and MCP
- Utilization endpoint provides at-a-glance health metrics
- Structured error responses consistent with existing `NetcidrError` pattern

New error variants:

```rust
pub enum NetcidrError {
    // ... existing variants ...
    DatabaseError(String),
    AllocationConflict { existing: String, candidate: String },
    SupernetNotFound(String),
    AllocationNotFound(String),
    SupernetHasActiveAllocations(String),
    NoFreeSpace { supernet: String, prefix: u8 },
}
```

## 13. Testing Strategy

| Layer | Approach |
|-------|----------|
| Trait contract | A shared test suite written against `&dyn IpamStore` — run once per backend to verify behavioral parity. SQLite (in-memory) runs in CI by default; Postgres runs via testcontainers when the feature is enabled. |
| Unit | In-memory SQLite for `ipam::operations` business logic tests |
| Integration | Temp-file DB, exercise CLI subcommands via subprocess |
| Conflict detection | Property-based tests: random CIDR pairs, verify no false negatives |
| Migration | Test upgrade path from v0 → vN with sample data, per backend |
| MCP | TypeScript integration tests mirroring existing `netcidr.test.ts` pattern |
| Fuzz | Fuzz CIDR inputs to allocation functions |

## 14. Success Criteria

- [ ] Can register a supernet and allocate 100 non-overlapping /20 blocks without conflict
- [ ] Attempting to allocate an overlapping block returns a clear conflict error naming the existing allocation
- [ ] `free_blocks` accurately reflects remaining space after allocations and releases
- [ ] Full VPC trial (as performed on 2026-03-02) can be reproduced via MCP with persistent state
- [ ] Audit log captures every mutation with timestamps
- [ ] Database survives `netcidr` process restarts — state is durable
- [ ] All three interfaces (CLI, API, MCP) can perform the same operations
- [ ] Switching `backend = "postgres"` produces identical behavior to SQLite (trait contract tests pass on both)
- [ ] `make check` passes with IPAM module included (SQLite default, additional backends with feature flags)

## 15. Open Questions

1. **Hierarchical allocations** — Should child allocations (VPC → subnets) enforce that children fit within the parent? Proposed: yes, validate containment on creation.
2. **Reservation expiry** — Should `reserved` status have a TTL? Proposed: defer to v2; v1 reservations are indefinite.
3. **Export/import** — Should there be a `dump` / `load` command for migration between instances? Proposed: yes, JSON export in a later phase.
4. **Multi-DB** — Should the API server support multiple named databases (e.g., per-tenant)? Proposed: no, single DB for v1.
5. **IPv6 timeline** — When to extend IPAM to IPv6? Proposed: schema supports it from day one (ip_version column), implementation in a follow-up PRD.
6. **Backend-specific features** — Should PostgreSQL use native `INET`/`CIDR` types for indexed range queries, or stick to `TEXT` columns for maximum portability? Proposed: use native types where the backend supports them — the trait abstracts the difference, and performance matters more than SQL portability.
7. **Async vs sync trait** — `async_trait` adds a heap allocation per call. Is `spawn_blocking` for SQLite acceptable, or should there be a separate sync trait path? Proposed: `async_trait` is fine for v1; the overhead is negligible relative to actual I/O.
