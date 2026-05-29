use serde::{Deserialize, Serialize};

use crate::auth::Role;

// ---------------------------------------------------------------------------
// CidrBlock
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CidrBlock {
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
pub struct CreateCidrBlock {
    /// CIDR notation (e.g., 10.0.0.0/8 or 2001:db8::/32)
    pub cidr: String,
    /// Optional name for the CIDR block
    pub name: Option<String>,
    /// Optional description
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CidrBlockList {
    pub cidr_blocks: Vec<CidrBlock>,
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
    pub cidr_block_id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAllocation {
    pub cidr_block_id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAllocateRequest {
    pub cidr_block_id: String,
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
    pub cidr_block_id: Option<String>,
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
    /// Authentication method that produced this mutation: `"oidc"`,
    /// `"pat"`, or `"bearer"`. Defaults to `"oidc"` for back-compat
    /// with rows written before the column existed.
    #[serde(default = "default_audit_auth_method")]
    pub auth_method: String,
    /// Personal access token id when `auth_method == "pat"`; otherwise `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pat_id: Option<String>,
}

fn default_audit_auth_method() -> String {
    "oidc".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditFilter {
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub action: Option<String>,
    /// Filter by the authenticated caller's email.
    pub caller_email: Option<String>,
    /// Filter by the personal access token id that performed the action.
    pub pat_id: Option<String>,
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
    pub cidr_block_id: String,
    pub cidr_block_cidr: String,
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
    pub cidr_block_id: String,
    pub cidr_block_cidr: String,
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

/// Minimal cidr_block view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactCidrBlock {
    pub id: String,
    pub cidr: String,
    pub name: Option<String>,
    pub total_hosts: u128,
}

impl From<&CidrBlock> for CompactCidrBlock {
    fn from(s: &CidrBlock) -> Self {
        Self {
            id: s.id.clone(),
            cidr: s.cidr.clone(),
            name: s.name.clone(),
            total_hosts: s.total_hosts,
        }
    }
}

impl From<CidrBlock> for CompactCidrBlock {
    fn from(s: CidrBlock) -> Self {
        Self::from(&s)
    }
}

// ---------------------------------------------------------------------------
// Batch operation models
// ---------------------------------------------------------------------------

/// A single item in a batch allocate request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAllocateItem {
    pub cidr_block_id: String,
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
    /// Scope resource_id filter to a specific cidr_block
    pub cidr_block_id: Option<String>,
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

/// Grouped allocation summary across CIDR blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationSummary {
    pub cidr_blocks: Vec<CidrBlockAllocationSummary>,
    pub total_allocations: usize,
    pub total_active: usize,
}

/// Per-cidr_block allocation summary with groupings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrBlockAllocationSummary {
    pub cidr_block_id: String,
    pub cidr_block_cidr: String,
    pub cidr_block_name: Option<String>,
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
    pub cidr_blocks: Vec<CidrBlock>,
    pub allocations: Vec<Allocation>,
}

// ---------------------------------------------------------------------------
// Personal Access Tokens
// ---------------------------------------------------------------------------

/// A long-lived personal access token bound to an OIDC identity. The
/// `token_hash` field is `#[serde(skip)]` to guarantee the on-wire hash never
/// leaks through any serialized API path; only the in-memory store/verifier
/// touch it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalAccessToken {
    pub id: String,
    pub tenant_id: String,
    pub owner_sub: String,
    pub owner_email: String,
    pub name: String,
    /// First 12 chars of the plaintext token (`ncdr_pat_xxxx`); shown in lists.
    pub prefix: String,
    /// `sha256(secret || pepper)` — 32 bytes. Never serialized.
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    /// Role granted by this PAT. Clamped at auth time to `min(owner_role, pat_role)`
    /// so a PAT can narrow privileges (e.g. an admin mints a reader-only CI
    /// token) but never widen them.
    pub role: Role,
    pub created_at: String,
    /// RFC3339; never NULL — minted with a default if the user didn't pick one.
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

/// Fields required to insert a new PAT row. Caller computes `prefix` and
/// `token_hash` via `crate::pat`; store layer trusts and parameterizes them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePersonalAccessToken {
    pub tenant_id: String,
    pub owner_sub: String,
    pub owner_email: String,
    pub name: String,
    pub prefix: String,
    pub token_hash: Vec<u8>,
    /// Role to stamp on the row. The lifecycle defaults this to the
    /// minting principal's resolved role; verify-time clamps re-apply
    /// `min(current_owner_role, stored_role)` on every use so a later
    /// demotion of the owner narrows existing PATs automatically.
    pub role: Role,
    pub expires_at: String,
}

/// Public-safe view of a PAT — no plaintext, no hash. Used by `GET /me/tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct PersonalAccessTokenSummary {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub role: Role,
    pub created_at: String,
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl From<PersonalAccessToken> for PersonalAccessTokenSummary {
    fn from(t: PersonalAccessToken) -> Self {
        Self {
            id: t.id,
            name: t.name,
            prefix: t.prefix,
            role: t.role,
            created_at: t.created_at,
            expires_at: t.expires_at,
            last_used_at: t.last_used_at,
            revoked_at: t.revoked_at,
        }
    }
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

// ---------------------------------------------------------------------------
// Hostname pointers
// ---------------------------------------------------------------------------

/// A tenant-scoped mapping of an IP address to a hostname. Many-to-many: an IP
/// may carry several names and a name may move between IPs over time. The
/// `(tenant_id, ip_address, hostname)` triple is unique.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct HostnamePointer {
    pub id: String,
    pub tenant_id: String,
    pub ip_address: String,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// When this IP↔hostname association was first recorded (RFC3339).
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CreateHostnamePointer {
    /// IP address (IPv4 or IPv6); normalized to canonical form on write.
    pub ip_address: String,
    /// Fully-qualified hostname (RFC 1123); lowercased on write.
    pub hostname: String,
    /// Optional allocation to associate this pointer with.
    #[serde(default)]
    pub allocation_id: Option<String>,
    /// Optional free-form notes.
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::IntoParams))]
pub struct HostnamePointerFilter {
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub allocation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct HostnamePointerList {
    pub pointers: Vec<HostnamePointer>,
    pub count: usize,
}

/// The kind of change recorded in [`HostnamePointerHistoryEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Create,
    Update,
    Delete,
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
        }
    }
}

impl std::str::FromStr for ChangeKind {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            other => Err(format!("invalid change kind: {}", other)),
        }
    }
}

/// One append-only entry in a hostname pointer's change history. `previous_value`
/// and `new_value` are JSON snapshots of the [`HostnamePointer`] (null for the
/// missing side of a create/delete).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct HostnamePointerHistoryEntry {
    pub id: String,
    pub tenant_id: String,
    pub pointer_id: String,
    pub ip_address: String,
    pub hostname: String,
    pub change_kind: ChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
    /// Actor that made the change: OIDC sub/email, or `"cli"`.
    pub actor: String,
    pub changed_at: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::IntoParams))]
pub struct HostnameHistoryFilter {
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct HostnamePointerHistoryList {
    pub entries: Vec<HostnamePointerHistoryEntry>,
    pub count: usize,
}

// ---------------------------------------------------------------------------
// Role assignments (global RBAC membership; email → role)
// ---------------------------------------------------------------------------

/// A global role grant for an email address. Not tenant-scoped: an email maps
/// to one role across the whole system (data isolation is handled separately
/// via tenant scoping). Source of truth for role resolution once seeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct RoleAssignment {
    pub email: String,
    pub role: Role,
    pub created_at: String,
    pub updated_at: String,
    /// Email of the admin who made the grant, or `"bootstrap"` for env-seeded rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct RoleAssignmentList {
    pub users: Vec<RoleAssignment>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct GrantRoleRequest {
    pub email: String,
    pub role: Role,
}
