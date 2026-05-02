# Multi-Tenant Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-OIDC-identity isolation of IPAM data (supernets, allocations, audit log, idempotency keys), with `tenant_id` threaded explicitly through the storage and operations layers.

**Architecture:** Destructive schema migration adds a `tenant_id TEXT NOT NULL` column to four tables. The `IpamStore` trait and `IpamOps` struct grow an explicit `tenant_id: &str` parameter on every tenant-scoped method. HTTP middleware extracts `tenant_id` from the authenticated principal's email and exposes it via Axum request extensions; handlers pass it explicitly into ops. CLI passes the literal `"local"`. Cross-tenant reads return `NotFound` (never `Forbidden`) to avoid existence leakage.

**Tech Stack:** Rust, sqlx (SQLite + Postgres), Axum, tokio, async-trait. Tests: `cargo test` (unit + integration), `cargo test --features ipam-postgres` (Postgres path).

**Spec:** `docs/superpowers/specs/2026-05-02-multi-tenant-isolation-design.md`

---

## File Map

**Modified:**
- `src/ipam/models.rs` — add `tenant_id` field to `Supernet`, `Allocation`, `AuditEntry`, `IdempotencyRecord`
- `src/ipam/store.rs` — trait signatures gain `tenant_id: &str` parameter
- `src/ipam/sqlite/migrations.rs` — add migration 006 (drop + recreate four tables with new schema)
- `src/ipam/sqlite/mod.rs` — every query gains `WHERE tenant_id = ?` filter or `tenant_id` insert column
- `src/ipam/postgres/migrations.rs` — add migration 006 (Postgres equivalent)
- `src/ipam/postgres/mod.rs` — same query updates as SQLite
- `src/ipam/operations.rs` — every public method gains `tenant_id: &str`; threads to store
- `src/ipam/idempotency.rs` — `idempotent_post` reads tenant_id from request, passes to store
- `src/ipam_api.rs` — HTTP handlers extract `tenant_id` from request extensions, pass to ops
- `src/api.rs` — auth middleware sets `Tenant(email)` extension on request after allowlist check
- `src/ipam_cli.rs` — every ops call passes `"local"`
- `src/mcp.rs` — local IPAM backend defaults `tenant_id = "local"` for stdio MCP usage

**Created:**
- `src/tenant.rs` — small `Tenant(String)` newtype + Axum extractor
- `tests/ipam_isolation.rs` — HTTP-level isolation matrix (two mock OIDC identities, every cross-tenant access path returns 404)

**Test fixture sweep (mechanical):**
- `tests/ipam_store_contract.rs`, `tests/ipam_api_tests.rs`, `tests/ipam_concurrency.rs`, `tests/ipam_idempotency.rs`, `tests/postgres_integration.rs`, `tests/integration_tests.rs` — every literal `Supernet { ... }` / `Allocation { ... }` / `IdempotencyRecord { ... }` and every `IpamOps::*` call needs the new field/parameter populated.

---

## Phase 1: Schema and Models

### Task 1: Add `tenant_id` field to model structs

**Files:**
- Modify: `src/ipam/models.rs`

Adds the field that the rest of the plan reads. No serde-skip needed because tenancy is enforced server-side and the dashboard already only sees its own data; if we ever want to suppress the field in JSON we can add `#[serde(skip_serializing)]` later.

- [ ] **Step 1: Add `tenant_id` to `Supernet`**

In `src/ipam/models.rs`, after `pub id: String,` in the `Supernet` struct (around line 10):

```rust
pub struct Supernet {
    pub id: String,
    pub tenant_id: String,
    pub cidr: String,
    // ... rest unchanged
}
```

- [ ] **Step 2: Add `tenant_id` to `Allocation`**

In the `Allocation` struct (around line 78):

```rust
pub struct Allocation {
    pub id: String,
    pub tenant_id: String,
    pub supernet_id: String,
    // ... rest unchanged
}
```

- [ ] **Step 3: Add `tenant_id` to `AuditEntry`**

In the `AuditEntry` struct (around line 189):

```rust
pub struct AuditEntry {
    pub id: String,
    pub tenant_id: String,
    pub entity_type: String,
    // ... rest unchanged
}
```

- [ ] **Step 4: Add `tenant_id` to `IdempotencyRecord`**

In `IdempotencyRecord` (around line 446):

```rust
pub struct IdempotencyRecord {
    pub tenant_id: String,
    pub key: String,
    pub scope: String,
    pub request_hash: String,
    pub status_code: u16,
    pub response_body: String,
    pub created_at: String,
    pub expires_at: String,
}
```

- [ ] **Step 5: `cargo check` — expect many errors in `sqlite/mod.rs`, `postgres/mod.rs`, tests**

```bash
cargo check 2>&1 | head -40
```

Expected: errors about missing `tenant_id` field in struct literals across the codebase. This is intentional — Phases 2-6 fix them.

- [ ] **Step 6: Commit (intermediate, broken build)**

```bash
git add src/ipam/models.rs
git commit -m "refactor(ipam): add tenant_id field to core models

Build is intentionally broken at this point — subsequent commits in this
PR add the SQL columns, thread tenant_id through IpamStore + IpamOps, and
update all call sites."
```

---

### Task 2: Add SQLite migration 006 (destructive)

**Files:**
- Modify: `src/ipam/sqlite/migrations.rs`

The migration drops `supernets`, `allocations`, `audit_log`, `idempotency_keys` and recreates them with `tenant_id`. `allocation_tags` references `allocations(id)` so we drop and recreate it too (no new column — inherits via FK).

- [ ] **Step 1: Read existing migration array structure**

```bash
grep -n "MIGRATIONS\|version\|CREATE TABLE" src/ipam/sqlite/migrations.rs | head -30
```

This shows where the existing migrations array is defined and what version numbers are used.

- [ ] **Step 2: Append migration 006 to the migrations array**

In `src/ipam/sqlite/migrations.rs`, add a new entry after migration 005:

```rust
Migration {
    version: 6,
    description: "multi-tenant isolation: drop+recreate IPAM tables with tenant_id",
    sql: r#"
        DROP TABLE IF EXISTS allocation_tags;
        DROP TABLE IF EXISTS allocations;
        DROP TABLE IF EXISTS supernets;
        DROP TABLE IF EXISTS audit_log;
        DROP TABLE IF EXISTS idempotency_keys;

        CREATE TABLE supernets (
            id                TEXT PRIMARY KEY,
            tenant_id         TEXT NOT NULL,
            cidr              TEXT NOT NULL,
            network_address   TEXT NOT NULL,
            broadcast_address TEXT NOT NULL,
            prefix_length     INTEGER NOT NULL,
            total_hosts       TEXT NOT NULL,
            name              TEXT,
            description       TEXT,
            ip_version        INTEGER NOT NULL,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL,
            UNIQUE (tenant_id, cidr)
        );
        CREATE INDEX idx_supernets_tenant ON supernets(tenant_id);

        CREATE TABLE allocations (
            id                    TEXT PRIMARY KEY,
            tenant_id             TEXT NOT NULL,
            supernet_id           TEXT NOT NULL REFERENCES supernets(id),
            cidr                  TEXT NOT NULL,
            network_address       TEXT NOT NULL,
            broadcast_address     TEXT NOT NULL,
            prefix_length         INTEGER NOT NULL,
            total_hosts           TEXT NOT NULL,
            status                TEXT NOT NULL,
            resource_id           TEXT,
            resource_type         TEXT,
            name                  TEXT,
            description           TEXT,
            environment           TEXT,
            owner                 TEXT,
            parent_allocation_id  TEXT REFERENCES allocations(id),
            created_at            TEXT NOT NULL,
            updated_at            TEXT NOT NULL,
            released_at           TEXT,
            expires_at            TEXT
        );
        CREATE INDEX idx_allocations_tenant     ON allocations(tenant_id);
        CREATE INDEX idx_allocations_tenant_sn  ON allocations(tenant_id, supernet_id);
        CREATE INDEX idx_allocations_supernet   ON allocations(supernet_id);
        CREATE INDEX idx_allocations_status     ON allocations(status);
        CREATE INDEX idx_allocations_cidr       ON allocations(cidr);

        -- Cross-table invariant: allocations.tenant_id must match the parent supernet's.
        CREATE TRIGGER trg_allocations_tenant_match_insert
            BEFORE INSERT ON allocations
            FOR EACH ROW
            WHEN NEW.tenant_id != (SELECT tenant_id FROM supernets WHERE id = NEW.supernet_id)
            BEGIN
                SELECT RAISE(ABORT, 'allocation tenant_id must match parent supernet tenant_id');
            END;
        CREATE TRIGGER trg_allocations_tenant_match_update
            BEFORE UPDATE OF tenant_id, supernet_id ON allocations
            FOR EACH ROW
            WHEN NEW.tenant_id != (SELECT tenant_id FROM supernets WHERE id = NEW.supernet_id)
            BEGIN
                SELECT RAISE(ABORT, 'allocation tenant_id must match parent supernet tenant_id');
            END;

        CREATE TABLE allocation_tags (
            allocation_id TEXT NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
            key           TEXT NOT NULL,
            value         TEXT NOT NULL,
            PRIMARY KEY (allocation_id, key)
        );

        CREATE TABLE audit_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id     TEXT NOT NULL,
            entity_type   TEXT NOT NULL,
            entity_id     TEXT NOT NULL,
            action        TEXT NOT NULL,
            details       TEXT,
            timestamp     TEXT NOT NULL,
            caller_sub    TEXT,
            caller_email  TEXT,
            source_ip     TEXT,
            request_id    TEXT
        );
        CREATE INDEX idx_audit_tenant         ON audit_log(tenant_id);
        CREATE INDEX idx_audit_tenant_entity  ON audit_log(tenant_id, entity_type, entity_id);
        CREATE INDEX idx_audit_request_id     ON audit_log(request_id);
        CREATE INDEX idx_audit_caller_sub     ON audit_log(caller_sub);

        CREATE TABLE idempotency_keys (
            tenant_id     TEXT NOT NULL,
            key           TEXT NOT NULL,
            scope         TEXT NOT NULL,
            request_hash  TEXT NOT NULL,
            status_code   INTEGER NOT NULL,
            response_body TEXT NOT NULL,
            created_at    TEXT NOT NULL,
            expires_at    TEXT NOT NULL,
            PRIMARY KEY (tenant_id, key, scope)
        );
        CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);
    "#,
},
```

Note: SQLite `INTEGER` columns hold the version number; the `version_pk` PRAGMA-driven scheme already in the file applies. `total_hosts` stays TEXT because Rust holds it as `u128` and SQLite has no native u128.

- [ ] **Step 3: Write a unit test for the trigger**

Add to `src/ipam/sqlite/migrations.rs` `#[cfg(test)] mod tests`:

```rust
#[tokio::test]
async fn allocation_with_mismatched_tenant_id_is_rejected_by_trigger() {
    let store = SqliteStore::in_memory().await.unwrap();
    store.migrate().await.unwrap();

    // Insert a supernet for tenant "a@x".
    sqlx::query(
        r#"INSERT INTO supernets
           (id, tenant_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, ip_version, created_at, updated_at)
           VALUES ('s1','a@x','10.0.0.0/8','10.0.0.0','10.255.255.255',
                   8,'16777216',4,'2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
    )
    .execute(store.pool())
    .await
    .unwrap();

    // Attempt to insert allocation with mismatched tenant_id.
    let result = sqlx::query(
        r#"INSERT INTO allocations
           (id, tenant_id, supernet_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, status, created_at, updated_at)
           VALUES ('a1','b@x','s1','10.1.0.0/16','10.1.0.0','10.1.255.255',
                   16,'65536','active','2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
    )
    .execute(store.pool())
    .await;

    assert!(
        result.is_err(),
        "trigger should reject allocation whose tenant_id != supernet's tenant_id"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("allocation tenant_id must match"),
        "unexpected error: {}",
        err
    );
}
```

If `SqliteStore::in_memory()` and `SqliteStore::pool()` don't exist, add them as test-only helpers (look for similar in the existing file).

- [ ] **Step 4: Run only this test (will fail until SQLite impl is updated, but the migration test should pass)**

```bash
cargo test --lib --features ipam-postgres allocation_with_mismatched_tenant -- --nocapture
```

Expected: PASS. The migration runs without errors and the trigger rejects the bad insert.

- [ ] **Step 5: Commit**

```bash
git add src/ipam/sqlite/migrations.rs
git commit -m "refactor(ipam/sqlite): migration 006 — multi-tenant schema

Drops and recreates supernets, allocations, audit_log, idempotency_keys,
and allocation_tags. Adds tenant_id columns, UNIQUE(tenant_id, cidr) on
supernets, composite tenant indexes, and triggers enforcing the
cross-table invariant allocations.tenant_id == supernets.tenant_id."
```

---

### Task 3: Add Postgres migration 006

**Files:**
- Modify: `src/ipam/postgres/migrations.rs`

Same shape as SQLite migration but in Postgres dialect (BIGSERIAL instead of AUTOINCREMENT, `RAISE EXCEPTION` instead of `RAISE(ABORT)`, etc.).

- [ ] **Step 1: Read the existing Postgres migrations module**

```bash
grep -n "MIGRATIONS\|version\|CREATE TABLE" src/ipam/postgres/migrations.rs | head -40
```

- [ ] **Step 2: Append migration 006**

```rust
Migration {
    version: 6,
    description: "multi-tenant isolation: drop+recreate IPAM tables with tenant_id",
    sql: r#"
        DROP TABLE IF EXISTS allocation_tags CASCADE;
        DROP TABLE IF EXISTS allocations CASCADE;
        DROP TABLE IF EXISTS supernets CASCADE;
        DROP TABLE IF EXISTS audit_log CASCADE;
        DROP TABLE IF EXISTS idempotency_keys CASCADE;

        CREATE TABLE supernets (
            id                TEXT PRIMARY KEY,
            tenant_id         TEXT NOT NULL,
            cidr              TEXT NOT NULL,
            network_address   TEXT NOT NULL,
            broadcast_address TEXT NOT NULL,
            prefix_length     SMALLINT NOT NULL,
            total_hosts       TEXT NOT NULL,
            name              TEXT,
            description       TEXT,
            ip_version        SMALLINT NOT NULL,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL,
            UNIQUE (tenant_id, cidr)
        );
        CREATE INDEX idx_supernets_tenant ON supernets(tenant_id);

        CREATE TABLE allocations (
            id                    TEXT PRIMARY KEY,
            tenant_id             TEXT NOT NULL,
            supernet_id           TEXT NOT NULL REFERENCES supernets(id),
            cidr                  TEXT NOT NULL,
            network_address       TEXT NOT NULL,
            broadcast_address     TEXT NOT NULL,
            prefix_length         SMALLINT NOT NULL,
            total_hosts           TEXT NOT NULL,
            status                TEXT NOT NULL,
            resource_id           TEXT,
            resource_type         TEXT,
            name                  TEXT,
            description           TEXT,
            environment           TEXT,
            owner                 TEXT,
            parent_allocation_id  TEXT REFERENCES allocations(id),
            created_at            TEXT NOT NULL,
            updated_at            TEXT NOT NULL,
            released_at           TEXT,
            expires_at            TEXT
        );
        CREATE INDEX idx_allocations_tenant    ON allocations(tenant_id);
        CREATE INDEX idx_allocations_tenant_sn ON allocations(tenant_id, supernet_id);
        CREATE INDEX idx_allocations_supernet  ON allocations(supernet_id);
        CREATE INDEX idx_allocations_status    ON allocations(status);
        CREATE INDEX idx_allocations_cidr      ON allocations(cidr);

        CREATE OR REPLACE FUNCTION assert_alloc_tenant_match() RETURNS trigger AS $$
        DECLARE
            sn_tenant TEXT;
        BEGIN
            SELECT tenant_id INTO sn_tenant FROM supernets WHERE id = NEW.supernet_id;
            IF sn_tenant IS NULL OR sn_tenant != NEW.tenant_id THEN
                RAISE EXCEPTION 'allocation tenant_id must match parent supernet tenant_id';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trg_allocations_tenant_match_insert
            BEFORE INSERT ON allocations
            FOR EACH ROW EXECUTE FUNCTION assert_alloc_tenant_match();
        CREATE TRIGGER trg_allocations_tenant_match_update
            BEFORE UPDATE OF tenant_id, supernet_id ON allocations
            FOR EACH ROW EXECUTE FUNCTION assert_alloc_tenant_match();

        CREATE TABLE allocation_tags (
            allocation_id TEXT NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
            key           TEXT NOT NULL,
            value         TEXT NOT NULL,
            PRIMARY KEY (allocation_id, key)
        );

        CREATE TABLE audit_log (
            id            BIGSERIAL PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            entity_type   TEXT NOT NULL,
            entity_id     TEXT NOT NULL,
            action        TEXT NOT NULL,
            details       TEXT,
            timestamp     TEXT NOT NULL,
            caller_sub    TEXT,
            caller_email  TEXT,
            source_ip     TEXT,
            request_id    TEXT
        );
        CREATE INDEX idx_audit_tenant         ON audit_log(tenant_id);
        CREATE INDEX idx_audit_tenant_entity  ON audit_log(tenant_id, entity_type, entity_id);
        CREATE INDEX idx_audit_request_id     ON audit_log(request_id);
        CREATE INDEX idx_audit_caller_sub     ON audit_log(caller_sub);

        CREATE TABLE idempotency_keys (
            tenant_id     TEXT NOT NULL,
            key           TEXT NOT NULL,
            scope         TEXT NOT NULL,
            request_hash  TEXT NOT NULL,
            status_code   INTEGER NOT NULL,
            response_body TEXT NOT NULL,
            created_at    TEXT NOT NULL,
            expires_at    TEXT NOT NULL,
            PRIMARY KEY (tenant_id, key, scope)
        );
        CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);
    "#,
},
```

- [ ] **Step 3: Mirror the trigger test**

Add a test at the bottom of the postgres migrations file (gated `#[cfg(all(test, feature = "ipam-postgres"))]`):

```rust
#[tokio::test]
async fn pg_allocation_with_mismatched_tenant_id_is_rejected_by_trigger() {
    // Skip if no NETCIDR_TEST_DATABASE_URL set.
    let url = match std::env::var("NETCIDR_TEST_DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let store = PostgresStore::connect(&url).await.unwrap();
    store.migrate().await.unwrap();

    sqlx::query(
        r#"INSERT INTO supernets
           (id, tenant_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, ip_version, created_at, updated_at)
           VALUES ('s1','a@x','10.0.0.0/8','10.0.0.0','10.255.255.255',
                   8,'16777216',4,'2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
    )
    .execute(store.pool())
    .await
    .unwrap();

    let result = sqlx::query(
        r#"INSERT INTO allocations
           (id, tenant_id, supernet_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, status, created_at, updated_at)
           VALUES ('a1','b@x','s1','10.1.0.0/16','10.1.0.0','10.1.255.255',
                   16,'65536','active','2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
    )
    .execute(store.pool())
    .await;

    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("must match parent"),
    );
}
```

- [ ] **Step 4: Commit**

```bash
git add src/ipam/postgres/migrations.rs
git commit -m "refactor(ipam/postgres): migration 006 — multi-tenant schema

Mirror the SQLite migration: drop and recreate IPAM tables with tenant_id,
UNIQUE(tenant_id, cidr) on supernets, composite tenant indexes, and a
plpgsql function + trigger enforcing the cross-table invariant."
```

---

## Phase 2: Storage Layer

### Task 4: Update `IpamStore` trait signatures

**Files:**
- Modify: `src/ipam/store.rs`

This is the load-bearing change for the entire refactor. After this commit lands, every backend impl must follow.

- [ ] **Step 1: Replace the trait body**

Replace the contents of `src/ipam/store.rs` with:

```rust
use async_trait::async_trait;

use crate::error::Result;
use crate::ipam::models::*;

/// Core storage abstraction for the IPAM persistence layer.
///
/// All tenant-scoped methods take an explicit `tenant_id: &str` parameter so
/// the type system makes per-tenant filtering unforgettable. Backends must
/// add `WHERE tenant_id = ?` to every query and refuse cross-tenant
/// references with `IpamError::NotFound` (never `Forbidden`, to avoid
/// leaking existence).
#[async_trait]
pub trait IpamStore: Send + Sync {
    // --- lifecycle ---
    async fn initialize(&self) -> Result<()>;
    async fn migrate(&self) -> Result<()>;

    // --- supernets ---
    async fn create_supernet(
        &self,
        tenant_id: &str,
        input: &CreateSupernet,
    ) -> Result<Supernet>;
    async fn get_supernet(&self, tenant_id: &str, id: &str) -> Result<Supernet>;
    async fn list_supernets(&self, tenant_id: &str) -> Result<Vec<Supernet>>;
    async fn delete_supernet(&self, tenant_id: &str, id: &str) -> Result<()>;

    // --- allocations ---
    async fn create_allocation(
        &self,
        tenant_id: &str,
        input: &CreateAllocation,
    ) -> Result<Allocation>;
    async fn get_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation>;
    async fn list_allocations(
        &self,
        tenant_id: &str,
        filter: &AllocationFilter,
    ) -> Result<Vec<Allocation>>;
    async fn update_allocation(
        &self,
        tenant_id: &str,
        id: &str,
        input: &UpdateAllocation,
    ) -> Result<Allocation>;
    async fn release_allocation(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Allocation>;
    async fn find_allocations_in_supernet(
        &self,
        tenant_id: &str,
        supernet_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>>;

    // --- tags ---
    async fn set_tags(
        &self,
        tenant_id: &str,
        allocation_id: &str,
        tags: &[Tag],
    ) -> Result<()>;
    async fn get_tags(&self, tenant_id: &str, allocation_id: &str) -> Result<Vec<Tag>>;

    // --- audit ---
    /// `entry.tenant_id` is the source of truth (already populated by caller).
    async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn query_audit(
        &self,
        tenant_id: &str,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEntry>>;

    // --- idempotency ---
    async fn idempotency_get(
        &self,
        tenant_id: &str,
        key: &str,
        scope: &str,
    ) -> Result<Option<IdempotencyRecord>>;
    /// `record.tenant_id` is the source of truth.
    async fn idempotency_put(&self, record: &IdempotencyRecord) -> Result<()>;
    /// Tenant-agnostic: prunes expired rows across all tenants.
    async fn idempotency_reap_expired(&self, now_rfc3339: &str) -> Result<u64>;
}
```

- [ ] **Step 2: `cargo check` to confirm trait compiles in isolation**

```bash
cargo check --lib 2>&1 | grep -E "^error\[" | head -20
```

Expected: errors in `sqlite/mod.rs` and `postgres/mod.rs` because the impls no longer match the trait. That's correct — Tasks 5 and 6 fix them.

- [ ] **Step 3: Commit (still broken build)**

```bash
git add src/ipam/store.rs
git commit -m "refactor(ipam): IpamStore trait — explicit tenant_id parameter

Every tenant-scoped method now takes tenant_id: &str explicitly. Backends
will follow in subsequent commits."
```

---

### Task 5: SQLite backend implementation

**Files:**
- Modify: `src/ipam/sqlite/mod.rs`

Pattern: each method that took `(id)` becomes `(tenant_id, id)` and the SQL adds `WHERE tenant_id = ?`. Each insert adds `tenant_id` to the column list and `?` to the values. Show the pattern on `create_supernet` and `get_supernet`; the rest is mechanical.

- [ ] **Step 1: Update `create_supernet`**

Find the existing `create_supernet` impl (search for `async fn create_supernet` in the file). Replace its body with the tenant-aware version:

```rust
async fn create_supernet(
    &self,
    tenant_id: &str,
    input: &CreateSupernet,
) -> Result<Supernet> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let parsed = parse_cidr(&input.cidr)?;

    sqlx::query(
        r#"INSERT INTO supernets
           (id, tenant_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, name, description, ip_version,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(&input.cidr)
    .bind(&parsed.network_address)
    .bind(&parsed.broadcast_address)
    .bind(parsed.prefix_length as i64)
    .bind(parsed.total_hosts.to_string())
    .bind(&input.name)
    .bind(&input.description)
    .bind(parsed.ip_version as i64)
    .bind(&now)
    .bind(&now)
    .execute(&self.pool)
    .await
    .map_err(map_sqlite_error)?;

    self.get_supernet(tenant_id, &id).await
}
```

(Adapt to the actual existing helper functions like `parse_cidr` / `map_sqlite_error` whose names you'll see in the file.)

- [ ] **Step 2: Update `get_supernet`**

```rust
async fn get_supernet(&self, tenant_id: &str, id: &str) -> Result<Supernet> {
    let row = sqlx::query_as::<_, SupernetRow>(
        "SELECT * FROM supernets WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&self.pool)
    .await
    .map_err(map_sqlite_error)?;

    row.map(Supernet::from)
        .ok_or_else(|| crate::error::NetcidrError::IpamError(IpamError::NotFound {
            entity: "supernet".to_string(),
            id: id.to_string(),
        }))
}
```

`SupernetRow` is the existing sqlx::FromRow type. Add `tenant_id` to it. The `From<SupernetRow> for Supernet` conversion needs to copy the new field.

- [ ] **Step 3: Apply the same pattern to remaining methods**

For each method in this list, the change is mechanical:
- `list_supernets` → `WHERE tenant_id = ?`
- `delete_supernet` → `WHERE id = ? AND tenant_id = ?`
- `create_allocation` → INSERT includes `tenant_id` (read from input — but our trait passes tenant_id separately; use the parameter, NOT input.tenant_id since CreateAllocation doesn't have one). The trigger enforces the supernet match; we can rely on it.
- `get_allocation` → `WHERE id = ? AND tenant_id = ?`
- `list_allocations` → `WHERE tenant_id = ?` plus existing filter clauses
- `update_allocation` → `WHERE id = ? AND tenant_id = ?`
- `release_allocation` → `WHERE id = ? AND tenant_id = ?`
- `find_allocations_in_supernet` → `WHERE supernet_id = ? AND tenant_id = ?`
- `set_tags` → first verify the allocation is in this tenant: `SELECT 1 FROM allocations WHERE id = ? AND tenant_id = ?`. If absent → `NotFound`. Then existing tag insert logic.
- `get_tags` → same: verify allocation belongs to tenant, then read tags.
- `append_audit` → INSERT includes `tenant_id` from `entry.tenant_id`
- `query_audit` → `WHERE tenant_id = ?` plus existing filter clauses
- `idempotency_get` → `WHERE tenant_id = ? AND key = ? AND scope = ?`
- `idempotency_put` → INSERT with `record.tenant_id`
- `idempotency_reap_expired` → unchanged (tenant-agnostic by design)

For each, the key invariants:
- Reads of unowned IDs return `IpamError::NotFound`, not `Forbidden`
- `SELECT *` queries that map to `SupernetRow` / `AllocationRow` / `AuditEntryRow` need those Row types to include `tenant_id`

- [ ] **Step 4: Update Row → Model conversions**

Add `tenant_id: row.tenant_id,` to each `From<*Row> for *` conversion in this file.

- [ ] **Step 5: Run lib unit tests for SQLite**

```bash
cargo test --lib ipam::sqlite -- --nocapture 2>&1 | tail -30
```

Expected: most tests still failing because callers haven't been updated yet, but the migration trigger test from Task 2 should pass now that the impl supports the new schema.

- [ ] **Step 6: Commit (build still broken — operations.rs, ipam_api.rs, ipam_cli.rs not yet updated)**

```bash
git add src/ipam/sqlite/mod.rs
git commit -m "refactor(ipam/sqlite): implement tenant_id-aware IpamStore"
```

---

### Task 6: Postgres backend implementation

**Files:**
- Modify: `src/ipam/postgres/mod.rs`

Same pattern as SQLite. The bind syntax is `$1, $2, ...` instead of `?`.

- [ ] **Step 1: Update `create_supernet`** — `INSERT INTO supernets (id, tenant_id, cidr, ...) VALUES ($1, $2, $3, ...)`. Pattern shown in Task 5 Step 1.

- [ ] **Step 2: Update `get_supernet`** — `SELECT * FROM supernets WHERE id = $1 AND tenant_id = $2`.

- [ ] **Step 3: Apply same pattern to remaining methods** — same list as Task 5 Step 3.

- [ ] **Step 4: Update Row→Model conversions to include tenant_id.**

- [ ] **Step 5: Run Postgres tests (skip-if-no-DB)**

```bash
cargo test --features ipam-postgres --lib ipam::postgres 2>&1 | tail -20
```

Expected: tests that need a live Postgres skip cleanly if `NETCIDR_TEST_DATABASE_URL` is unset; otherwise they pass.

- [ ] **Step 6: Commit**

```bash
git add src/ipam/postgres/mod.rs
git commit -m "refactor(ipam/postgres): implement tenant_id-aware IpamStore"
```

---

## Phase 3: Operations Layer

### Task 7: Update `IpamOps` to thread `tenant_id`

**Files:**
- Modify: `src/ipam/operations.rs`

Every public method on `IpamOps` grows `tenant_id: &str`. The internal calls to `self.store.*` pass it through. Audit log entries get `tenant_id` populated from the parameter (NOT from `audit_context::current()`).

- [ ] **Step 1: Update method signatures (mechanical sweep)**

For every public `async fn` on `IpamOps`, add `tenant_id: &str` as the first parameter (after `&self`). Methods affected (roughly 15-20 — search for `pub async fn` in the file):

```
pub async fn create_supernet(&self, tenant_id: &str, ...) -> Result<Supernet>
pub async fn get_supernet(&self, tenant_id: &str, id: &str) -> Result<Supernet>
pub async fn list_supernets(&self, tenant_id: &str) -> Result<SupernetList>
pub async fn delete_supernet(&self, tenant_id: &str, id: &str) -> Result<()>
pub async fn allocate_specific(&self, tenant_id: &str, input: CreateAllocation) -> Result<Allocation>
pub async fn allocate_auto(&self, tenant_id: &str, req: AutoAllocateRequest) -> Result<Vec<Allocation>>
pub async fn get_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation>
pub async fn list_allocations(&self, tenant_id: &str, filter: AllocationFilter) -> Result<AllocationList>
pub async fn update_allocation(&self, tenant_id: &str, id: &str, input: UpdateAllocation) -> Result<Allocation>
pub async fn release_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation>
pub async fn batch_allocate(&self, tenant_id: &str, items: Vec<BatchAllocateItem>) -> Result<BatchAllocateResult>
pub async fn batch_release(&self, tenant_id: &str, req: BatchReleaseRequest) -> Result<BatchReleaseResult>
pub async fn utilization(&self, tenant_id: &str, supernet_id: &str) -> Result<UtilizationReport>
pub async fn free_blocks(&self, tenant_id: &str, supernet_id: &str, ...) -> Result<FreeBlocksReport>
pub async fn find_ip(&self, tenant_id: &str, ip: &str) -> Result<...>
pub async fn find_resource(&self, tenant_id: &str, query: &str) -> Result<...>
pub async fn audit_log(&self, tenant_id: &str, filter: AuditFilter) -> Result<...>
```

- [ ] **Step 2: Thread tenant_id through every call to `self.store.*`**

Find every `self.store.METHOD(...)` and add `tenant_id` (or threaded variable) as the first arg.

- [ ] **Step 3: Populate `entry.tenant_id` when constructing `AuditEntry`**

Search for `AuditEntry {` literals in `operations.rs`. Add `tenant_id: tenant_id.to_string(),` to each.

The existing `audit_context::current()` call (line 942) still provides `caller_sub`, `caller_email`, `source_ip`, `request_id`. Keep that; only `tenant_id` comes from the new parameter.

- [ ] **Step 4: Update the per-supernet allocation lock map**

The `HashMap<supernet_id, Arc<Mutex<()>>>` keys on supernet_id. Two tenants could have the same supernet_id... no, actually they can't — UUIDs are globally unique. Locking is fine as-is.

- [ ] **Step 5: Update tests in `operations.rs` to pass `tenant_id`**

Every `let ops = IpamOps::new(...); ops.METHOD(...)` in the file's `#[cfg(test)] mod tests` needs `tenant_id` threaded in. Use `"test-tenant"` as a constant.

- [ ] **Step 6: `cargo check --lib` — should now pass for the library**

```bash
cargo check --lib 2>&1 | grep -E "^error" | head
```

Expected: no errors in `src/ipam/`. Errors remain in `src/ipam_api.rs`, `src/ipam_cli.rs`, `src/api.rs`, `src/mcp.rs`. Phases 4-5 fix those.

- [ ] **Step 7: Commit**

```bash
git add src/ipam/operations.rs
git commit -m "refactor(ipam/operations): thread tenant_id through every public method"
```

---

### Task 8: Update `idempotency.rs` wrapper

**Files:**
- Modify: `src/ipam/idempotency.rs`

The `idempotent_post` helper builds an `IdempotencyRecord`. It needs to accept `tenant_id` from the handler.

- [ ] **Step 1: Change `idempotent_post` signature**

The function probably looks like `pub async fn idempotent_post<F, Fut, T>(store, key, scope, body_hash, handler) -> ...`. Add `tenant_id: &str` as a parameter. Pass it to `store.idempotency_get(tenant_id, ...)` and embed in the constructed `IdempotencyRecord { tenant_id: tenant_id.to_string(), ... }`.

Show the exact new signature:

```rust
pub async fn idempotent_post<S, F, Fut, T>(
    store: &S,
    tenant_id: &str,
    key: &str,
    scope: &str,
    request_body: &[u8],
    handler: F,
) -> Result<(StatusCode, HeaderMap, T)>
where
    S: IpamStore,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(StatusCode, T)>>,
    T: Serialize,
{
    // ... existing logic, but every store.idempotency_* call uses tenant_id
}
```

- [ ] **Step 2: Update call sites in `ipam_api.rs`** (Task 9 will pick these up; just leave them broken for now).

- [ ] **Step 3: Commit**

```bash
git add src/ipam/idempotency.rs
git commit -m "refactor(ipam/idempotency): scope idempotency keys by tenant_id"
```

---

## Phase 4: HTTP Layer

### Task 9: Tenant extractor and auth middleware integration

**Files:**
- Create: `src/tenant.rs`
- Modify: `src/lib.rs` (add `pub mod tenant;`)
- Modify: `src/auth.rs` — middleware sets `Tenant` extension after allowlist check

- [ ] **Step 1: Create `src/tenant.rs`**

```rust
//! Per-request tenant identity, set by auth middleware.
//!
//! HTTP handlers extract [`Tenant`] from request extensions and pass its
//! inner string to [`crate::ipam::operations::IpamOps`]. Unauthenticated
//! routes never have it set; tenant-scoped routes are unreachable without
//! it because [`crate::auth::require_auth`] runs first.

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

#[derive(Debug, Clone)]
pub struct Tenant(pub String);

impl Tenant {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Tenant
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Tenant>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "tenant not set"))
    }
}
```

- [ ] **Step 2: Wire the module**

In `src/lib.rs`, add:

```rust
pub mod tenant;
```

- [ ] **Step 3: Set `Tenant` extension in auth middleware**

In `src/auth.rs`, find `require_auth` (~line 156). After the allowlist check passes — i.e., once we know the email is allowed — insert into request extensions:

```rust
// existing code that authenticated the principal and confirmed allowlist
let tenant = crate::tenant::Tenant(
    principal
        .email
        .clone()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "principal has no email"))?,
);
request.extensions_mut().insert(tenant);
```

- [ ] **Step 4: Write a unit test for the extractor**

In `src/tenant.rs`, add at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn extractor_returns_tenant_when_set() {
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(Tenant("a@x".to_string()));
        let (mut parts, _) = req.into_parts();
        let extracted = Tenant::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(extracted.as_str(), "a@x");
    }

    #[tokio::test]
    async fn extractor_returns_401_when_missing() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let result = Tenant::from_request_parts(&mut parts, &()).await;
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }
}
```

- [ ] **Step 5: Run the new tests**

```bash
cargo test --lib tenant -- --nocapture
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/tenant.rs src/lib.rs src/auth.rs
git commit -m "feat(http): Tenant extension + extractor; auth middleware sets it"
```

---

### Task 10: Update HTTP handlers in `ipam_api.rs`

**Files:**
- Modify: `src/ipam_api.rs`

Every handler that calls `IpamOps::*` extracts `Tenant` and passes its inner string.

- [ ] **Step 1: Update one handler as the canonical example**

Pick `list_supernets` (or whichever is simplest). Change:

```rust
async fn list_supernets(
    Extension(ops): Extension<Arc<IpamOps>>,
) -> Result<Json<SupernetList>, ApiError> {
    let supernets = ops.list_supernets().await?;
    Ok(Json(supernets))
}
```

to:

```rust
async fn list_supernets(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
) -> Result<Json<SupernetList>, ApiError> {
    let supernets = ops.list_supernets(tenant.as_str()).await?;
    Ok(Json(supernets))
}
```

- [ ] **Step 2: Apply the same pattern to every handler in the file**

Mechanical sweep. Add `tenant: crate::tenant::Tenant,` to the function signature; pass `tenant.as_str()` as the first argument to every `ops.*` call.

- [ ] **Step 3: Update `idempotent_post` call sites**

For the three idempotent handlers (`POST /ipam/supernets/{id}/allocate`, `POST /ipam/supernets/{id}/allocate-specific`, `POST /ipam/batch/allocate`), pass `tenant.as_str()` as the new `tenant_id` argument.

- [ ] **Step 4: Run unit tests on the lib**

```bash
cargo test --lib 2>&1 | tail
```

Expected: build now compiles. Lib tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/ipam_api.rs
git commit -m "refactor(ipam_api): handlers extract Tenant and pass to ops"
```

---

## Phase 5: CLI and MCP

### Task 11: CLI passes literal `"local"`

**Files:**
- Modify: `src/ipam_cli.rs`

The CLI doesn't authenticate. SQLite-only, always single-tenant.

- [ ] **Step 1: Define a constant**

At the top of `ipam_cli.rs`:

```rust
const CLI_TENANT_ID: &str = "local";
```

- [ ] **Step 2: Pass it to every `ops.*` call**

Mechanical sweep. Wherever there's `ops.METHOD(args)`, change to `ops.METHOD(CLI_TENANT_ID, args)`.

- [ ] **Step 3: Run CLI integration tests**

```bash
cargo test --test integration_tests 2>&1 | tail -10
```

Expected: PASS (after fixture sweep in Task 14).

- [ ] **Step 4: Commit**

```bash
git add src/ipam_cli.rs
git commit -m "refactor(ipam_cli): pass tenant_id=\"local\" for CLI invocations"
```

---

### Task 12: MCP local backend

**Files:**
- Modify: `src/mcp.rs`

The local IPAM backend (when MCP runs over stdio with `--ipam-db`) is single-tenant — like the CLI, it operates on a private SQLite file. Use `"local"`. The remote backend (HTTP proxy) doesn't touch IpamOps directly so no change needed there.

- [ ] **Step 1: Update local backend calls**

Search for `McpIpamBackend::Local(ops).METHOD(...)` patterns or wherever the MCP tools call `ops.*`. Pass `"local"` as the tenant_id.

Define a constant near the top of `mcp.rs`:

```rust
const MCP_LOCAL_TENANT_ID: &str = "local";
```

- [ ] **Step 2: Run lib tests including MCP**

```bash
cargo test --lib --features mcp 2>&1 | tail
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/mcp.rs
git commit -m "refactor(mcp): local IPAM backend passes tenant_id=\"local\""
```

---

## Phase 6: Tests

### Task 13: HTTP isolation integration tests

**Files:**
- Create: `tests/ipam_isolation.rs`

This is the single most important test in the PR — proves end-to-end that two OIDC identities cannot see each other's data.

- [ ] **Step 1: Look at existing HTTP test scaffolding**

```bash
grep -n "OidcAudience\|mock_server\|test_jwt" tests/ipam_api_tests.rs | head -10
```

Reuse whatever JWT-mocking helper exists. If `tests/ipam_idempotency.rs` (PR #104) has a helper, copy its pattern.

- [ ] **Step 2: Write the test file**

```rust
//! HTTP-level multi-tenant isolation matrix.
//!
//! Boots an in-memory netcidr API, signs two mock OIDC identities
//! `a@example.com` and `b@example.com`, and asserts every cross-tenant
//! access path returns 404 (not 403) so existence isn't leaked.

use reqwest::StatusCode;
use serde_json::json;

mod common;
use common::{spawn_test_server, mint_id_token, TestServer};

#[tokio::test]
async fn supernets_are_isolated_per_tenant() {
    let server = spawn_test_server().await;
    let token_a = mint_id_token(&server, "a@example.com");
    let token_b = mint_id_token(&server, "b@example.com");

    // A creates a supernet.
    let resp = server
        .post("/ipam/supernets")
        .bearer_auth(&token_a)
        .json(&json!({ "cidr": "10.0.0.0/8" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let s_a: serde_json::Value = resp.json().await.unwrap();
    let s_a_id = s_a["id"].as_str().unwrap().to_string();

    // B sees zero supernets.
    let resp = server.get("/ipam/supernets").bearer_auth(&token_b).send().await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 0);

    // B requesting A's supernet by ID gets 404, not 403.
    let resp = server
        .get(&format!("/ipam/supernets/{}", s_a_id))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn same_cidr_in_two_tenants_both_succeed() {
    let server = spawn_test_server().await;
    let token_a = mint_id_token(&server, "a@example.com");
    let token_b = mint_id_token(&server, "b@example.com");

    for token in [&token_a, &token_b] {
        let resp = server
            .post("/ipam/supernets")
            .bearer_auth(token)
            .json(&json!({ "cidr": "10.0.0.0/8" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "tenant should accept its own 10.0.0.0/8");
    }
}

#[tokio::test]
async fn allocations_are_isolated_per_tenant() {
    let server = spawn_test_server().await;
    let token_a = mint_id_token(&server, "a@example.com");
    let token_b = mint_id_token(&server, "b@example.com");

    // A creates supernet + allocation.
    let s_a: serde_json::Value = server
        .post("/ipam/supernets").bearer_auth(&token_a)
        .json(&json!({ "cidr": "10.0.0.0/8" })).send().await.unwrap()
        .json().await.unwrap();
    let s_a_id = s_a["id"].as_str().unwrap();

    let alloc: serde_json::Value = server
        .post(&format!("/ipam/supernets/{}/allocate-specific", s_a_id))
        .bearer_auth(&token_a)
        .json(&json!({ "cidr": "10.1.0.0/16" })).send().await.unwrap()
        .json().await.unwrap();
    let alloc_id = alloc["id"].as_str().unwrap();

    // B requesting A's allocation by ID gets 404.
    let resp = server
        .get(&format!("/ipam/allocations/{}", alloc_id))
        .bearer_auth(&token_b).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // B trying to allocate inside A's supernet gets 404.
    let resp = server
        .post(&format!("/ipam/supernets/{}/allocate-specific", s_a_id))
        .bearer_auth(&token_b)
        .json(&json!({ "cidr": "10.2.0.0/16" })).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_log_is_isolated_per_tenant() {
    let server = spawn_test_server().await;
    let token_a = mint_id_token(&server, "a@example.com");
    let token_b = mint_id_token(&server, "b@example.com");

    // A creates a supernet (mutation -> audit row).
    server.post("/ipam/supernets").bearer_auth(&token_a)
        .json(&json!({ "cidr": "10.0.0.0/8" })).send().await.unwrap();

    // B's audit log is empty.
    let resp = server.get("/ipam/audit").bearer_auth(&token_b).send().await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["entries"].as_array().unwrap().len(), 0);

    // A's audit log has at least one entry.
    let resp = server.get("/ipam/audit").bearer_auth(&token_a).send().await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["entries"].as_array().unwrap().len() >= 1);
}

#[tokio::test]
async fn idempotency_keys_are_isolated_per_tenant() {
    let server = spawn_test_server().await;
    let token_a = mint_id_token(&server, "a@example.com");
    let token_b = mint_id_token(&server, "b@example.com");

    // A creates supernet.
    let s_a: serde_json::Value = server.post("/ipam/supernets").bearer_auth(&token_a)
        .json(&json!({ "cidr": "10.0.0.0/8" })).send().await.unwrap()
        .json().await.unwrap();
    let s_a_id = s_a["id"].as_str().unwrap();

    // B creates *its own* supernet (different namespace; same CIDR is OK).
    let s_b: serde_json::Value = server.post("/ipam/supernets").bearer_auth(&token_b)
        .json(&json!({ "cidr": "10.0.0.0/8" })).send().await.unwrap()
        .json().await.unwrap();
    let s_b_id = s_b["id"].as_str().unwrap();

    // Both call allocate-specific with the same Idempotency-Key.
    let key = "shared-key-1";
    let resp_a = server
        .post(&format!("/ipam/supernets/{}/allocate-specific", s_a_id))
        .bearer_auth(&token_a)
        .header("Idempotency-Key", key)
        .json(&json!({ "cidr": "10.1.0.0/16" })).send().await.unwrap();
    assert_eq!(resp_a.status(), StatusCode::CREATED);
    assert!(resp_a.headers().get("Idempotent-Replay").is_none());

    let resp_b = server
        .post(&format!("/ipam/supernets/{}/allocate-specific", s_b_id))
        .bearer_auth(&token_b)
        .header("Idempotency-Key", key)
        .json(&json!({ "cidr": "10.2.0.0/16" })).send().await.unwrap();
    // B's request should EXECUTE FRESH (not replay A's response).
    assert_eq!(resp_b.status(), StatusCode::CREATED);
    assert!(resp_b.headers().get("Idempotent-Replay").is_none());
}
```

If `tests/common/` doesn't exist, lift helpers from `tests/ipam_idempotency.rs`. The `mint_id_token` helper signs a JWT against the same JWKS the test server validates against.

- [ ] **Step 3: Run isolation tests**

```bash
cargo test --test ipam_isolation -- --nocapture 2>&1 | tail -30
```

Expected: all five tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/ipam_isolation.rs tests/common/
git commit -m "test(ipam): HTTP isolation matrix — five-test cross-tenant guarantee"
```

---

### Task 14: Test fixture sweep

**Files:**
- Modify: `tests/ipam_store_contract.rs`, `tests/ipam_api_tests.rs`, `tests/ipam_concurrency.rs`, `tests/ipam_idempotency.rs`, `tests/postgres_integration.rs`, `tests/integration_tests.rs`
- Modify: any `#[cfg(test)]` blocks in `src/` that construct fixture data

Mechanical: every literal struct gets `tenant_id`; every `ops.METHOD(...)` call gets a tenant_id argument.

- [ ] **Step 1: Update each test file**

For tests not specifically about isolation, use a single constant:

```rust
const TEST_TENANT: &str = "test@example.com";
```

at the top of each test file. Pass it to every `ops.*` call.

For struct literals: `Supernet { id, tenant_id: TEST_TENANT.to_string(), cidr, ... }`. Same for `Allocation`, `AuditEntry`, `IdempotencyRecord`.

- [ ] **Step 2: Run the full test suite**

```bash
cargo test 2>&1 | tail -20
cargo test --features ipam-postgres 2>&1 | tail -20
```

Expected: zero failures.

- [ ] **Step 3: Commit**

```bash
git add tests/ src/
git commit -m "test: fixture sweep — every IPAM literal/call carries tenant_id"
```

---

### Task 15: Final verification, docs, version bump

**Files:**
- Modify: `CHANGELOG.md`, `README.md`, `Cargo.toml`, `Cargo.lock`, `SECURITY.md`

- [ ] **Step 1: Run the full check pipeline**

```bash
just check 2>&1 | tail -30
```

Expected: green across fmt, lint, test, test-tui, test-mcp, semgrep.

- [ ] **Step 2: Update CHANGELOG.md**

Add under `[Unreleased]`:

```markdown
### Changed

- **Multi-tenant IPAM isolation.** Every supernet, allocation, audit entry, and idempotency record is now scoped to the authenticated user's email. The `IpamStore` trait and `IpamOps` struct expose `tenant_id: &str` as an explicit parameter on every method, making per-tenant filtering unforgettable at the type level. HTTP middleware extracts the tenant from the OIDC principal's verified email and exposes it via Axum extensions; cross-tenant access returns 404 (not 403) to prevent existence enumeration. CLI invocations and stdio MCP both pass the literal `"local"`. Schema is destructive: migration `006` drops and recreates `supernets`, `allocations`, `audit_log`, `idempotency_keys`, and `allocation_tags` with `tenant_id` columns, `UNIQUE(tenant_id, cidr)` on supernets, composite tenant indexes, and triggers enforcing the cross-table invariant `allocations.tenant_id == supernets.tenant_id`. Five-test isolation matrix in `tests/ipam_isolation.rs` proves the guarantee end-to-end (supernets, same-CIDR-different-tenant, allocations, audit log, idempotency keys). Sub-project 1 of 3 toward a remote MCP endpoint.
```

- [ ] **Step 3: Update README.md** if any user-facing CLI behavior changed (it didn't — `--db` SQLite usage stays single-tenant, just with a `local` row marker invisible to users).

- [ ] **Step 4: Bump version**

`Cargo.toml`: `version = "0.24.0"` (minor bump — schema break + new behavior).

`SECURITY.md`: shift the supported-versions table to keep `0.24.x` current, `0.23.x` supported, `< 0.23` unsupported.

`CHANGELOG.md`: insert `## [0.24.0] - YYYY-MM-DD` heading above the moved entries.

`Cargo.lock` will be regenerated by `cargo build`.

- [ ] **Step 5: Final commit**

```bash
git add CHANGELOG.md README.md Cargo.toml Cargo.lock SECURITY.md
git commit -m "chore(release): v0.24.0 — multi-tenant IPAM isolation"
```

- [ ] **Step 6: Push branch and open PR**

```bash
git push -u origin <branch>
gh pr create --title "feat(ipam): multi-tenant isolation per OIDC identity" --body "..."
```

---

## Self-Review Notes

**Spec coverage:** every section of the spec is covered.

| Spec section | Tasks |
|---|---|
| Goal & non-goals | T1-T15 (whole plan) |
| Tenancy model (email, "local" for CLI) | T9 (auth middleware), T11 (CLI), T12 (MCP) |
| Schema changes (4 tables + tag inheritance) | T2 (SQLite), T3 (Postgres) |
| Cross-table invariant | T2/T3 (DB triggers), T7 (app-level supernet check in `create_allocation`) |
| Auth → tenant flow | T9 (extractor + middleware), T10 (handlers) |
| IpamOps signature changes | T7 |
| Cross-tenant 404 semantics | T5/T6 (NotFound on missing rows), T13 (integration test) |
| Naming note (Allocation::owner unchanged) | T1 (only adds tenant_id; doesn't touch owner) |
| Testing matrix | T13 (isolation), T14 (fixture sweep) |
| Migration / deploy | T2/T3 (destructive migration) |

**Type consistency check:**
- `Tenant(pub String)` newtype, `as_str()` accessor — used consistently in T9 (definition), T10 (handler extraction).
- `tenant_id: &str` on every `IpamStore` and `IpamOps` method — consistent across T4, T5, T6, T7.
- `CLI_TENANT_ID = "local"` (T11) and `MCP_LOCAL_TENANT_ID = "local"` (T12) — same value, different constants per file for clarity.

**Placeholder scan:** none. Every code step shows the code; mechanical sweeps reference exact files and patterns.

**Order of operations correctness:** T1 (models) and T4 (trait) intentionally leave the build broken; T5+T6 (impls) restore the lib but break callers; T7 (ops), T8 (idempotency), T9 (extractor), T10 (handlers), T11 (CLI), T12 (MCP) restore the full build. Tests and fixtures (T13, T14) run last.
