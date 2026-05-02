use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Supernet
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Supernet {
    pub id: String,
    pub tenant_id: String,
    pub cidr: String,
    pub network_address: String,
    pub broadcast_address: String,
    pub prefix_length: u8,
    pub total_hosts: u128,
    pub name: Option<String>,
    pub description: Option<String>,
    pub ip_version: u8,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CreateSupernet {
    /// CIDR notation (e.g., 10.0.0.0/8 or 2001:db8::/32)
    pub cidr: String,
    /// Optional name for the supernet
    pub name: Option<String>,
    /// Optional description
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct SupernetList {
    pub supernets: Vec<Supernet>,
    pub count: usize,
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum AllocationStatus {
    Active,
    Reserved,
    Released,
}

impl std::fmt::Display for AllocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Reserved => write!(f, "reserved"),
            Self::Released => write!(f, "released"),
        }
    }
}

impl std::str::FromStr for AllocationStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "reserved" => Ok(Self::Reserved),
            "released" => Ok(Self::Released),
            other => Err(format!("invalid allocation status: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Allocation {
    pub id: String,
    pub tenant_id: String,
    pub supernet_id: String,
    pub cidr: String,
    pub network_address: String,
    pub broadcast_address: String,
    pub prefix_length: u8,
    pub total_hosts: u128,
    pub status: AllocationStatus,
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub parent_allocation_id: Option<String>,
    pub tags: Vec<Tag>,
    pub created_at: String,
    pub updated_at: String,
    pub released_at: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateAllocation {
    pub supernet_id: String,
    pub cidr: String,
    pub status: Option<AllocationStatus>,
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub parent_allocation_id: Option<String>,
    pub tags: Option<Vec<Tag>>,
    /// TTL in seconds — if set, computes `expires_at` from current time.
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoAllocateRequest {
    pub supernet_id: String,
    pub prefix_length: u8,
    pub count: Option<u32>,
    pub status: Option<AllocationStatus>,
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub parent_allocation_id: Option<String>,
    pub tags: Option<Vec<Tag>>,
    /// TTL in seconds — if set, computes `expires_at` from current time.
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct UpdateAllocation {
    /// Updated name
    pub name: Option<String>,
    /// Updated description
    pub description: Option<String>,
    /// Updated resource ID
    pub resource_id: Option<String>,
    /// Updated resource type
    pub resource_type: Option<String>,
    /// Updated environment
    pub environment: Option<String>,
    /// Updated owner
    pub owner: Option<String>,
    /// Updated status
    pub status: Option<AllocationStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllocationFilter {
    pub supernet_id: Option<String>,
    pub status: Option<AllocationStatus>,
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct AllocationList {
    pub allocations: Vec<Allocation>,
    pub count: usize,
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Tag {
    pub key: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct AuditEntry {
    pub id: String,
    pub tenant_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub action: String,
    pub details: Option<String>,
    pub timestamp: String,
    /// Stable subject identifier of the authenticated caller (e.g. Google `sub`).
    /// `None` for CLI invocations or anonymous mutations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_sub: Option<String>,
    /// Verified email of the authenticated caller, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_email: Option<String>,
    /// Source IP that initiated the mutation, as observed by the HTTP server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Per-request correlation ID (UUID v4) generated by HTTP middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditFilter {
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub action: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct AuditList {
    pub entries: Vec<AuditEntry>,
    pub count: usize,
}

// ---------------------------------------------------------------------------
// Utilization / Free Space reports
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct StatusBreakdown {
    pub active_addresses: u128,
    pub active_count: usize,
    pub reserved_addresses: u128,
    pub reserved_count: usize,
    pub released_addresses: u128,
    pub released_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct UtilizationReport {
    pub supernet_id: String,
    pub supernet_cidr: String,
    pub total_addresses: u128,
    pub allocated_addresses: u128,
    pub free_addresses: u128,
    pub utilization_percent: f64,
    pub allocation_count: usize,
    pub by_status: StatusBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct FreeBlock {
    pub cidr: String,
    pub size: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct FreeBlocksReport {
    pub supernet_id: String,
    pub supernet_cidr: String,
    pub blocks: Vec<FreeBlock>,
    pub total_free: u128,
}

// ---------------------------------------------------------------------------
// Compact views (reduced token usage for MCP batch operations)
// ---------------------------------------------------------------------------

/// Minimal allocation view — only essential fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactAllocation {
    pub id: String,
    pub cidr: String,
    pub name: Option<String>,
    pub status: AllocationStatus,
    pub resource_id: Option<String>,
    pub environment: Option<String>,
}

impl From<&Allocation> for CompactAllocation {
    fn from(a: &Allocation) -> Self {
        Self {
            id: a.id.clone(),
            cidr: a.cidr.clone(),
            name: a.name.clone(),
            status: a.status.clone(),
            resource_id: a.resource_id.clone(),
            environment: a.environment.clone(),
        }
    }
}

impl From<Allocation> for CompactAllocation {
    fn from(a: Allocation) -> Self {
        Self::from(&a)
    }
}

/// Minimal supernet view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSupernet {
    pub id: String,
    pub cidr: String,
    pub name: Option<String>,
    pub total_hosts: u128,
}

impl From<&Supernet> for CompactSupernet {
    fn from(s: &Supernet) -> Self {
        Self {
            id: s.id.clone(),
            cidr: s.cidr.clone(),
            name: s.name.clone(),
            total_hosts: s.total_hosts,
        }
    }
}

impl From<Supernet> for CompactSupernet {
    fn from(s: Supernet) -> Self {
        Self::from(&s)
    }
}

// ---------------------------------------------------------------------------
// Batch operation models
// ---------------------------------------------------------------------------

/// A single item in a batch allocate request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAllocateItem {
    pub supernet_id: String,
    pub prefix_length: u8,
    pub count: Option<u32>,
    pub name: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub resource_id: Option<String>,
}

/// Result for a single item in a batch allocate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAllocateItemResult {
    /// Index of the item in the request array
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocations: Option<Vec<CompactAllocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Overall batch allocate response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAllocateResult {
    pub total_requested: usize,
    pub total_allocated: usize,
    pub results: Vec<BatchAllocateItemResult>,
}

/// Request for batch release — at least one selector must be provided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReleaseRequest {
    /// Release by explicit allocation IDs
    pub allocation_ids: Option<Vec<String>>,
    /// Release all active allocations matching a resource_id
    pub resource_id: Option<String>,
    /// Scope resource_id filter to a specific supernet
    pub supernet_id: Option<String>,
}

/// Result for a single released allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReleaseItemResult {
    pub allocation_id: String,
    pub cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Overall batch release response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReleaseResult {
    pub total_requested: usize,
    pub total_released: usize,
    pub results: Vec<BatchReleaseItemResult>,
}

// ---------------------------------------------------------------------------
// Allocation summary models
// ---------------------------------------------------------------------------

/// Grouped allocation summary across supernets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationSummary {
    pub supernets: Vec<SupernetAllocationSummary>,
    pub total_allocations: usize,
    pub total_active: usize,
}

/// Per-supernet allocation summary with groupings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupernetAllocationSummary {
    pub supernet_id: String,
    pub supernet_cidr: String,
    pub supernet_name: Option<String>,
    pub utilization_percent: f64,
    pub active_count: usize,
    pub by_resource: Vec<ResourceGroup>,
}

/// Allocations grouped by resource_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGroup {
    pub resource_id: String,
    pub name: Option<String>,
    pub environment: Option<String>,
    pub count: usize,
    pub cidrs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Dump / Load (export/import)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamDump {
    pub version: u32,
    pub exported_at: String,
    pub supernets: Vec<Supernet>,
    pub allocations: Vec<Allocation>,
}

// ---------------------------------------------------------------------------
// Idempotency keys
// ---------------------------------------------------------------------------

/// A cached response keyed by client-supplied `Idempotency-Key` plus a scope
/// (endpoint + resource ID) so retries on the same logical operation return
/// the same result without re-executing.
#[derive(Debug, Clone, PartialEq, Eq)]
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
