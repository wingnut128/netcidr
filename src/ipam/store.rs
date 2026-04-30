use async_trait::async_trait;

use crate::error::Result;
use crate::ipam::models::*;

/// Core storage abstraction for the IPAM persistence layer.
///
/// All methods take `&self` and return `Result<T>`. Backends manage their own
/// connection pooling internally. Conflict detection and business logic live in
/// `ipam::operations`, not here — the store is a thin persistence boundary.
#[async_trait]
pub trait IpamStore: Send + Sync {
    // --- lifecycle ---
    async fn initialize(&self) -> Result<()>;
    async fn migrate(&self) -> Result<()>;

    // --- supernets ---
    async fn create_supernet(&self, input: &CreateSupernet) -> Result<Supernet>;
    async fn get_supernet(&self, id: &str) -> Result<Supernet>;
    async fn list_supernets(&self) -> Result<Vec<Supernet>>;
    async fn delete_supernet(&self, id: &str) -> Result<()>;

    // --- allocations ---
    async fn create_allocation(&self, input: &CreateAllocation) -> Result<Allocation>;
    async fn get_allocation(&self, id: &str) -> Result<Allocation>;
    async fn list_allocations(&self, filter: &AllocationFilter) -> Result<Vec<Allocation>>;
    async fn update_allocation(&self, id: &str, input: &UpdateAllocation) -> Result<Allocation>;
    async fn release_allocation(&self, id: &str) -> Result<Allocation>;
    async fn find_allocations_in_supernet(
        &self,
        supernet_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>>;

    // --- tags ---
    async fn set_tags(&self, allocation_id: &str, tags: &[Tag]) -> Result<()>;
    async fn get_tags(&self, allocation_id: &str) -> Result<Vec<Tag>>;

    // --- audit ---
    async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>>;

    // --- idempotency ---
    async fn idempotency_get(&self, key: &str, scope: &str) -> Result<Option<IdempotencyRecord>>;
    async fn idempotency_put(&self, record: &IdempotencyRecord) -> Result<()>;
    async fn idempotency_reap_expired(&self, now_rfc3339: &str) -> Result<u64>;
}
