# Multi-Tenant Isolation for netcidr IPAM

**Status:** Design approved, awaiting implementation plan
**Date:** 2026-05-02
**Sub-project of:** Personal Access Tokens + remote MCP endpoint (this is sub-project 1 of 3)

## Goal

Make IPAM data strictly isolated per OIDC identity (keyed by email). Every read and write is scoped to the caller's tenant. No admin escape hatches. No cross-tenant visibility anywhere. CLI and local SQLite use a constant `tenant_id = "local"` and behave as single-tenant.

## Why

The deployed netcidr Lambda is currently single-tenant: anyone allowed by `NETCIDR_OIDC_ALLOWED_EMAILS` sees and edits all IPAM data. To support multiple users (and as a prerequisite for personal access tokens and a remote `/mcp` endpoint), data must be partitioned by identity.

This sub-project handles isolation only. Personal access tokens (sub-project 2) and `/mcp` mounting (sub-project 3) build on it.

## Non-goals

- Per-org / multi-user-per-tenant ("workspace") tenancy — deferred until usage demands it. Naming and indexing choices avoid painting us into a corner: `tenant_id` is a column whose value happens to be an email today and could become a `tenants.id` UUID later without renaming.
- Admin cross-tenant view, impersonation, or "view as tenant X". Admin role stays scoped to the existing allowlist endpoint.
- Tenant data export / import.
- Soft-delete on allowlist removal. A tenant removed from `NETCIDR_OIDC_ALLOWED_EMAILS` simply can't authenticate; their rows remain in the DB and become accessible again if they're re-added.
- Migrating existing data — there's nothing in production worth preserving; the migration drops and recreates tenant-scoped tables.

## Design

### Tenancy model

- Unit of tenancy: one OIDC identity, keyed by **email** (matches the existing allowlist source of truth).
- Column type: `TEXT NOT NULL` named `tenant_id`. Stores an email today; could store a UUID if per-org tenancy lands later. Callers never assume the format.
- CLI / local SQLite: constant value `"local"` for every row. The schema is identical between deployed Postgres and local SQLite; only the values differ.

### Schema changes

Single migration file `006_multi_tenant_isolation.sql` for both backends. Migration is **destructive** — drops and recreates `supernets`, `allocations`, `audit_log`, `idempotency_keys`. No backfill.

| Table | Change |
|---|---|
| `supernets` | Add `tenant_id TEXT NOT NULL`. Replace `UNIQUE (cidr)` with `UNIQUE (tenant_id, cidr)` so each tenant has its own RFC1918 namespace. |
| `allocations` | Add `tenant_id TEXT NOT NULL`, denormalized from owning supernet. No CIDR uniqueness (allocation overlap is checked logically per-supernet). |
| `audit_log` | Add `tenant_id TEXT NOT NULL` for read-side filtering. |
| `idempotency_keys` (PR #104) | PK becomes `(tenant_id, key, scope)`. Tenant B can never replay tenant A's cached response. |
| `allocation_tags` | **No new column.** Tags inherit tenancy via FK to `allocations`. Every tag read/write goes through the parent allocation's tenant check, so a tenant can never see or attach tags to another tenant's allocation. |

Indexes: `(tenant_id)` on each table. Composite `(tenant_id, supernet_id)` on `allocations` and `audit_log` for per-tenant-per-supernet scans.

### Cross-table invariant

`allocations.tenant_id == supernets.tenant_id` for the linked supernet. Enforced two ways:

1. **Application-level (primary):** `IpamOps::create_allocation` looks up the supernet, refuses if `request.tenant_id != supernet.tenant_id` (returns `IpamError::NotFound`, not `Forbidden` — see "Cross-tenant access" below).
2. **DB-level (defense in depth):** trigger on `allocations` insert/update verifies the join. Same trigger pattern on both backends.

### Auth → tenant flow

Extends the audit-context plumbing from PR #103.

1. `require_auth` middleware (`src/api.rs:372-379`) authenticates via OIDC; sets `caller_sub` and `caller_email` in the existing audit context task-local.
2. After the allowlist check passes, the same middleware sets `tenant_id = principal.email` in the request state. Unallowlisted users never get a `tenant_id`.
3. Handlers read `tenant_id` from request state and pass it as an **explicit argument** to every `IpamOps` method.
4. Unauthenticated endpoints (`/healthz`, dashboard SPA, swagger) don't touch `IpamOps` and don't need a `tenant_id`.
5. CLI instantiates `IpamOps` directly with literal `"local"`.

### IpamOps signature changes

Every method that touches a tenant-scoped table grows a `tenant_id: &str` parameter. No task-local magic from inside `IpamOps` — the type system makes the parameter unforgettable.

**Reads (filter result by tenant):**
`list_supernets`, `get_supernet`, `list_allocations`, `get_allocation`, `audit_log`, `utilization`, `free_blocks`, `find_ip`, `find_resource`.

**Writes (insert/update tagged with tenant; cross-tenant refs rejected):**
`create_supernet`, `create_allocation`, `update_allocation`, `release_allocation`, `batch_allocate`, `batch_release`, `auto_allocate`.

**Idempotency helpers:**
`idempotency_get`, `idempotency_put` — gain `tenant_id`. `idempotency_reap_expired` is tenant-agnostic (just deletes expired rows everywhere).

The `IpamStore` trait (`src/ipam/store.rs`) gets the same signature changes. Both backends implement them with `WHERE tenant_id = ?` added to every query.

### Cross-tenant access semantics

Tenant A requesting a resource owned by tenant B never reveals that the resource exists.

- `GET /ipam/supernets/{id}` for another tenant's UUID → **404 Not Found**, identical body to a non-existent UUID.
- `POST /ipam/supernets/{id}/allocate` against another tenant's supernet → **404**.
- `GET /ipam/allocations/{id}` for another tenant's allocation → **404**.
- Audit log queries: `?supernet_id=<other-tenant's-id>` → empty page.
- Idempotency: PK `(tenant_id, key, scope)` enforces isolation at the DB level.

403 is rejected because it leaks existence — an attacker probing UUIDs would learn which ones are valid in some tenant.

### Naming note

`Allocation::owner` already exists as a free-text label (e.g., "Web team", "billing-prod-VM"). The new tenancy column is named `tenant_id` to avoid collision. Existing `owner` field is unchanged.

## Testing

### Unit tests (per backend)

- **Two-tenant fixture:** supernet S_A under `a@x`, S_B under `b@x`. Assertions:
  - `list_supernets("a@x")` returns only S_A.
  - `get_supernet("a@x", S_B.id)` → `NotFound`.
  - `create_allocation("a@x", S_B.id, ...)` → `NotFound`.
- **Same-CIDR-different-tenant:** both tenants create `10.0.0.0/8`; both succeed. Confirms `UNIQUE (tenant_id, cidr)`.
- **Allocation invariant:** `create_allocation("a@x", S_A.id, cidr)` succeeds; mismatched tenant returns `NotFound`. Direct DB write violating the invariant is rejected by the trigger.
- **Audit isolation:** mutations under tenant A produce audit rows with `tenant_id = "a@x"`; `audit_log("b@x", ...)` returns none of them.
- **Idempotency isolation:** tenant A POSTs with key `K`, response cached. Tenant B POSTs same supernet ID + key `K` with different body → executes fresh; no 409, no replay.

### HTTP integration tests

New file `tests/ipam_isolation.rs`. Two mock OIDC identities (separate JWTs against the test JWKS). Same matrix as unit tests but exercised end-to-end through middleware → handler → ops → DB. Verifies the `email → tenant_id` plumbing.

Every cross-tenant access path returns **404 (not 403)**.

### CLI tests

Existing CLI integration tests stay green with `tenant_id = "local"` threaded in. No new CLI behaviors to test.

### Test fixture sweep

The destructive migration means existing test fixtures need updating. Mechanical sweep: every `Supernet { ... }` and `Allocation { ... }` literal in tests gets a `tenant_id` field. Same for SQL inserts in test setup.

## Migration / deploy

- Single migration file `006_multi_tenant_isolation.sql` per backend.
- Pre-deploy: nothing to back up (no production data of value).
- Post-deploy on cloudreaper.dev: re-create supernets via the dashboard. Trivial — there were only test entries.
- Local development: `just db-reset` (or equivalent) drops and re-runs migrations.

## Risks

- **Forgetting tenant_id in a new query.** Mitigated by the explicit-parameter design — every method signature in `IpamOps` and `IpamStore` requires it; any new query that omits a `WHERE tenant_id = ?` is a code-review red flag rather than silent data leakage.
- **Trigger drift between SQLite and Postgres.** The cross-table invariant trigger has different syntax on each backend. Both implementations are tested in the unit-test matrix; the integration tests run against both backends.
- **CLI / API schema divergence.** Solved by both modes using the same migration file. CLI just passes a constant tenant_id at every call site.

## Out of scope (deferred to follow-on sub-projects)

- **Sub-project 2: Personal Access Tokens.** DB-backed PATs scoped to an OIDC identity. Mint/list/revoke from `/me/tokens`. Auth middleware tries PAT first then OIDC. Audit log records the real human's `sub`/`email` regardless of which mechanism authenticated the request.
- **Sub-project 3: `/mcp` mounting.** Wire `StreamableHttpService` into `api::create_router`, gated by the same auth as `/ipam/*`. Reuses the IPAM ops the API already has, so all tenant filtering is automatic.

Each is its own spec → plan → implementation cycle.
