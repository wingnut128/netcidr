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
    async fn create_supernet(&self, tenant_id: &str, input: &CreateSupernet) -> Result<Supernet>;
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
    async fn release_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation>;
    async fn find_allocations_in_supernet(
        &self,
        tenant_id: &str,
        supernet_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>>;

    // --- tags ---
    async fn set_tags(&self, tenant_id: &str, allocation_id: &str, tags: &[Tag]) -> Result<()>;
    async fn get_tags(&self, tenant_id: &str, allocation_id: &str) -> Result<Vec<Tag>>;

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
