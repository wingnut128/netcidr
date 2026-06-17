use async_trait::async_trait;

use crate::error::Result;
use crate::ipam::models::*;

/// Build a trailing `LIMIT … OFFSET …` SQL clause for a paginated list query.
///
/// `limit`/`offset` are `u32`, so the values are pure digits — formatting them
/// directly into SQL carries no injection risk and keeps the clause backend
/// agnostic (works for both the rusqlite and sqlx builders). `None`/`None`
/// yields an empty string (unbounded, for CLI and internal callers); an offset
/// without a limit uses `LIMIT -1` as SQLite/Postgres both require a limit
/// before an offset.
pub(crate) fn limit_offset_clause(limit: Option<u32>, offset: Option<u32>) -> String {
    match (limit, offset) {
        (Some(l), Some(o)) => format!(" LIMIT {l} OFFSET {o}"),
        (Some(l), None) => format!(" LIMIT {l}"),
        (None, Some(o)) => format!(" LIMIT -1 OFFSET {o}"),
        (None, None) => String::new(),
    }
}

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

    // --- cidr_blocks ---
    async fn create_cidr_block(
        &self,
        tenant_id: &str,
        input: &CreateCidrBlock,
    ) -> Result<CidrBlock>;
    async fn get_cidr_block(&self, tenant_id: &str, id: &str) -> Result<CidrBlock>;
    async fn list_cidr_blocks(&self, tenant_id: &str) -> Result<Vec<CidrBlock>>;
    /// Like [`list_cidr_blocks`](Self::list_cidr_blocks) but with pagination for
    /// the HTTP list endpoint. `limit`/`offset` of `None` means unbounded.
    async fn list_cidr_blocks_page(
        &self,
        tenant_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<CidrBlock>>;
    async fn delete_cidr_block(&self, tenant_id: &str, id: &str) -> Result<()>;

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
    async fn release_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation>;
    async fn find_allocations_in_cidr_block(
        &self,
        tenant_id: &str,
        cidr_block_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>>;

    // --- tags ---
    async fn set_tags(&self, tenant_id: &str, allocation_id: &str, tags: &[Tag]) -> Result<()>;
    async fn get_tags(&self, tenant_id: &str, allocation_id: &str) -> Result<Vec<Tag>>;

    // --- hostname pointers ---
    /// Upsert a hostname pointer for `(tenant_id, ip, hostname)`. Inserts when
    /// new (recording a `create` history row), otherwise updates `notes`/
    /// `allocation_id` (recording an `update` row). The live mutation and its
    /// history row are written in a single transaction. `actor` is the OIDC
    /// identity or `"cli"`.
    async fn set_hostname_pointer(
        &self,
        tenant_id: &str,
        actor: &str,
        input: &CreateHostnamePointer,
    ) -> Result<HostnamePointer>;
    async fn list_hostname_pointers(
        &self,
        tenant_id: &str,
        filter: &HostnamePointerFilter,
    ) -> Result<Vec<HostnamePointer>>;
    /// Remove the live pointer for `(tenant_id, ip, hostname)` and record a
    /// `delete` history row (with the prior value) in the same transaction.
    /// Returns `CidrBlockNotFound`-style `NotFound` if no such live pointer
    /// exists for the tenant.
    async fn delete_hostname_pointer(
        &self,
        tenant_id: &str,
        actor: &str,
        ip: &str,
        hostname: &str,
    ) -> Result<()>;
    async fn list_hostname_history(
        &self,
        tenant_id: &str,
        filter: &HostnameHistoryFilter,
    ) -> Result<Vec<HostnamePointerHistoryEntry>>;

    // --- role assignments (global; not tenant-scoped) ---
    /// Resolve the role for an email, or `None` if no assignment exists.
    async fn get_role_for_email(&self, email: &str) -> Result<Option<crate::auth::Role>>;
    async fn list_role_assignments(&self) -> Result<Vec<RoleAssignment>>;
    /// Insert or update the role for `email`. `actor` records who made the grant.
    async fn upsert_role_assignment(
        &self,
        email: &str,
        role: crate::auth::Role,
        actor: &str,
    ) -> Result<RoleAssignment>;
    /// Remove an assignment. Returns `HostnamePointerNotFound`-style
    /// `RoleAssignmentNotFound` if no row exists for `email`.
    async fn delete_role_assignment(&self, email: &str) -> Result<()>;
    /// Number of rows whose role is `admin` — used for the last-admin guard.
    async fn count_admin_roles(&self) -> Result<u64>;
    /// Seed the table from `(email, role)` pairs only if it is currently empty.
    /// Returns the number of rows seeded (0 if the table already had rows).
    async fn seed_role_assignments_if_empty(
        &self,
        seeds: &[(String, crate::auth::Role)],
    ) -> Result<u64>;

    // --- audit ---
    /// `entry.tenant_id` is the source of truth (already populated by caller).
    async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn query_audit(&self, tenant_id: &str, filter: &AuditFilter) -> Result<Vec<AuditEntry>>;

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

    // --- personal access tokens ---

    /// Insert a new PAT row. Caller has already computed `prefix` and
    /// `token_hash`; the store trusts those inputs and parameterizes them.
    async fn pat_create(&self, input: &CreatePersonalAccessToken) -> Result<PersonalAccessToken>;

    /// Lookup an active, non-revoked, non-expired PAT by its hash.
    /// `now_rfc3339` is passed in so the caller controls "now" — the SQL
    /// predicate is `revoked_at IS NULL AND expires_at > $now`. Returns
    /// `Ok(None)` for any miss path (revoked, expired, no such hash) so the
    /// verifier's timing surface is uniform.
    async fn pat_get_by_hash(
        &self,
        token_hash: &[u8],
        now_rfc3339: &str,
    ) -> Result<Option<PersonalAccessToken>>;

    /// List every PAT belonging to the given (tenant_id, owner_sub) pair.
    /// Both keys are required as defense-in-depth: a leaked tenant_id alone
    /// shouldn't enumerate another user's tokens.
    async fn pat_list_for_owner(
        &self,
        tenant_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<PersonalAccessToken>>;

    /// Soft-revoke a PAT. Idempotent — if the row is already revoked, returns
    /// the existing row unchanged. Returns `PatNotFound` when the id isn't
    /// owned by `(tenant_id, owner_sub)`.
    async fn pat_revoke(
        &self,
        tenant_id: &str,
        owner_sub: &str,
        id: &str,
        now_rfc3339: &str,
    ) -> Result<PersonalAccessToken>;

    /// Update `last_used_at = now`. Unscoped (no tenant_id arg) because the
    /// verifier has already proven possession of the secret.
    async fn pat_touch_last_used(&self, id: &str, now_rfc3339: &str) -> Result<()>;

    /// Hard-delete every row whose `expires_at < before_rfc3339`. Returns the
    /// number of rows removed. Tenant-agnostic.
    async fn pat_reap_expired(&self, before_rfc3339: &str) -> Result<u64>;
}
