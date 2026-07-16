use std::sync::Arc;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
#[cfg(feature = "swagger")]
use utoipa::{IntoParams, ToSchema};

use crate::authorization::{RequireAdmin, RequireAllocator, RequirePlatformAdmin, RequireReader};
use crate::error::NetcidrError;
use crate::error_presenter::{LogLevel, present};
use crate::ipam::idempotency;
use crate::ipam::models::*;
use crate::ipam::operations::{IdempotentOutcome, IpamOps};

// ---------------------------------------------------------------------------
// Error mapping — thin adapter over `error_presenter::present`. All
// classification, scrubbing, and log-policy lives there.
// ---------------------------------------------------------------------------

pub(crate) fn error_to_status_value(err: NetcidrError) -> (StatusCode, serde_json::Value) {
    let p = present(&err);
    if p.log_level == LogLevel::Error {
        tracing::error!(error = %err, "ipam request failed");
    }
    let status = StatusCode::from_u16(p.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, serde_json::json!({ "error": p.client_msg }))
}

fn ipam_error_response(err: NetcidrError) -> Response {
    let (status, body) = error_to_status_value(err);
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Idempotent-outcome → HTTP response. Replayed outcomes carry the same
// success status as fresh, plus an `Idempotent-Replay: true` header so the
// caller can tell whether their request was actually executed.
// ---------------------------------------------------------------------------

fn outcome_response<T: serde::Serialize>(
    outcome: IdempotentOutcome<T>,
    status_on_success: StatusCode,
) -> Response {
    let is_replay = outcome.is_replayed();
    let value = outcome.into_inner();
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
    let mut builder = Response::builder()
        .status(status_on_success)
        .header("Content-Type", "application/json");
    if is_replay {
        builder = builder.header("Idempotent-Replay", "true");
    }
    builder
        .body(body.into())
        .expect("static headers always valid")
}

/// Look up an `Idempotency-Key` only when the body is small enough to be
/// safely cached. Oversized requests skip idempotency entirely (the
/// caller's retry will re-execute), matching the pre-refactor behaviour.
fn idempotency_key(headers: &HeaderMap, body_len: usize) -> Option<String> {
    if body_len > idempotency::MAX_BODY_BYTES {
        return None;
    }
    idempotency::key_from_headers(headers)
}

// ---------------------------------------------------------------------------
// Error response schema (for OpenAPI)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
pub struct IpamErrorResponse {
    /// Error message
    error: String,
}

// ---------------------------------------------------------------------------
// Request/query types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
pub struct AllocateSpecificRequest {
    /// CIDR to allocate (e.g., 10.0.1.0/24)
    pub cidr: String,
    /// Allocation status (active, reserved)
    pub status: Option<AllocationStatus>,
    /// External resource identifier
    pub resource_id: Option<String>,
    /// Resource type (e.g., vpc, subnet, host)
    pub resource_type: Option<String>,
    /// Human-readable name
    pub name: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Environment (e.g., production, staging)
    pub environment: Option<String>,
    /// Owner
    pub owner: Option<String>,
    /// Parent allocation ID for hierarchical allocations
    pub parent_allocation_id: Option<String>,
    /// Key-value tags
    pub tags: Option<Vec<Tag>>,
    /// TTL in seconds (reservation expires after this duration)
    pub ttl_seconds: Option<u64>,
}

impl AllocateSpecificRequest {
    /// Combine the body with the path-supplied cidr_block_id. The id can
    /// only come from the path so the body can't override it.
    pub fn into_create_allocation(self, cidr_block_id: String) -> CreateAllocation {
        CreateAllocation {
            cidr_block_id,
            cidr: self.cidr,
            status: self.status,
            resource_id: self.resource_id,
            resource_type: self.resource_type,
            name: self.name,
            description: self.description,
            environment: self.environment,
            owner: self.owner,
            parent_allocation_id: self.parent_allocation_id,
            tags: self.tags,
            ttl_seconds: self.ttl_seconds,
        }
    }
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
pub struct AutoAllocateBody {
    /// Desired prefix length for the allocation
    pub prefix_length: u8,
    /// Number of blocks to allocate (default: 1)
    pub count: Option<u32>,
    /// Allocation status (active, reserved)
    pub status: Option<AllocationStatus>,
    /// External resource identifier
    pub resource_id: Option<String>,
    /// Resource type
    pub resource_type: Option<String>,
    /// Human-readable name
    pub name: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Environment
    pub environment: Option<String>,
    /// Owner
    pub owner: Option<String>,
    /// Parent allocation ID
    pub parent_allocation_id: Option<String>,
    /// Key-value tags
    pub tags: Option<Vec<Tag>>,
    /// TTL in seconds (reservation expires after this duration)
    pub ttl_seconds: Option<u64>,
}

impl AutoAllocateBody {
    /// Combine the body with the path-supplied cidr_block_id. The id can
    /// only come from the path so the body can't override it.
    pub fn into_auto_allocate_request(self, cidr_block_id: String) -> AutoAllocateRequest {
        AutoAllocateRequest {
            cidr_block_id,
            prefix_length: self.prefix_length,
            count: self.count,
            status: self.status,
            resource_id: self.resource_id,
            resource_type: self.resource_type,
            name: self.name,
            description: self.description,
            environment: self.environment,
            owner: self.owner,
            parent_allocation_id: self.parent_allocation_id,
            tags: self.tags,
            ttl_seconds: self.ttl_seconds,
        }
    }
}

/// Default number of rows a list endpoint returns when no `limit` is given.
const DEFAULT_PAGE_LIMIT: u32 = 100;
/// Hard ceiling on `limit` for any list endpoint, to bound response size and
/// memory regardless of what a caller requests.
const MAX_PAGE_LIMIT: u32 = 1000;

/// Resolve a caller-supplied `limit` into an enforced page size: default when
/// absent, clamped to `[1, MAX_PAGE_LIMIT]`.
fn page_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT)
}

/// Pagination query params shared by the list endpoints.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct CidrBlockListQuery {
    /// Max rows to return (default 100, max 1000)
    pub limit: Option<u32>,
    /// Rows to skip before returning results (default 0)
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct AllocationFilterQuery {
    /// Filter by status (active, reserved, released)
    pub status: Option<String>,
    /// Filter by resource ID
    pub resource_id: Option<String>,
    /// Filter by resource type
    pub resource_type: Option<String>,
    /// Filter by environment
    pub environment: Option<String>,
    /// Filter by owner
    pub owner: Option<String>,
    /// Max rows to return (default 100, max 1000)
    pub limit: Option<u32>,
    /// Rows to skip before returning results (default 0)
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct FreeBlocksQuery {
    /// Filter free blocks by minimum prefix length
    pub prefix: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct AuditQuery {
    /// Filter by entity type (cidr_block, allocation)
    pub entity_type: Option<String>,
    /// Filter by entity ID
    pub entity_id: Option<String>,
    /// Filter by action (e.g., create_cidr_block, allocate)
    pub action: Option<String>,
    /// Filter by the authenticated caller's email
    pub caller_email: Option<String>,
    /// Filter by the personal access token id that performed the action
    pub pat_id: Option<String>,
    /// Maximum number of entries to return (default 100, max 1000)
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct HostnameListQuery {
    /// Filter by IP address
    pub ip: Option<String>,
    /// Filter by hostname
    pub hostname: Option<String>,
    /// Filter by associated allocation ID
    pub allocation_id: Option<String>,
    /// Max rows to return (default 100, max 1000)
    pub limit: Option<u32>,
    /// Rows to skip before returning results (default 0)
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct HostnameHistoryQuery {
    /// Filter history by IP address
    pub ip: Option<String>,
    /// Filter history by hostname
    pub hostname: Option<String>,
    /// Max rows to return (default 100, max 1000)
    pub limit: Option<u32>,
    /// Rows to skip before returning results (default 0)
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct HostnameDeleteQuery {
    /// IP address of the pointer to delete
    pub ip: String,
    /// Hostname of the pointer to delete
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct DeleteUserQuery {
    /// Email whose role assignment should be revoked
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct SummaryQuery {
    /// Optional CIDR block ID to scope the summary
    pub cidr_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
pub struct TagsBody {
    /// Tags to set on the allocation
    pub tags: Vec<Tag>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn create_ipam_router() -> Router {
    Router::new()
        .route(
            "/cidr-blocks",
            post(ipam_create_cidr_block).get(ipam_list_cidr_blocks),
        )
        .route(
            "/cidr-blocks/{id}",
            get(ipam_get_cidr_block).delete(ipam_delete_cidr_block),
        )
        .route("/cidr-blocks/{id}/allocate", post(ipam_auto_allocate))
        .route(
            "/cidr-blocks/{id}/allocate-specific",
            post(ipam_allocate_specific),
        )
        .route(
            "/cidr-blocks/{id}/allocations",
            get(ipam_list_cidr_block_allocations),
        )
        .route("/cidr-blocks/{id}/free", get(ipam_free_blocks))
        .route("/cidr-blocks/{id}/utilization", get(ipam_utilization))
        .route(
            "/allocations/{id}",
            get(ipam_get_allocation).patch(ipam_update_allocation),
        )
        .route("/allocations/{id}/release", post(ipam_release_allocation))
        .route("/allocations/{id}/tags", put(ipam_set_tags))
        .route("/find-ip/{address}", get(ipam_find_ip))
        .route("/find-resource/{resource_id}", get(ipam_find_resource))
        .route(
            "/hostnames",
            post(ipam_set_hostname)
                .get(ipam_list_hostnames)
                .delete(ipam_delete_hostname),
        )
        .route("/hostnames/history", get(ipam_hostname_history))
        .route("/audit", get(ipam_query_audit))
        .route("/batch/allocate", post(ipam_batch_allocate))
        .route("/batch/release", post(ipam_batch_release))
        .route("/batch/summary", get(ipam_batch_summary))
}

/// Admin router (users directory, ADR-0006). Mounted at the root so paths
/// are `/admin/users`; all handlers are `RequirePlatformAdmin`-gated — a
/// tenant-space `Admin` gets 403. User records are global, so the injected
/// tenant is used only for the audit row.
pub fn create_admin_router() -> Router {
    Router::new().route(
        "/admin/users",
        get(admin_list_users)
            .post(admin_upsert_user)
            .delete(admin_delete_user),
    )
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/admin/users",
    responses(
        (status = 200, description = "User directory (email, role, status)", body = UserList),
        (status = 403, description = "Caller is not a platform admin"),
    ),
    security(("bearerAuth" = [])),
    tag = "auth"
))]
async fn admin_list_users(
    Extension(ops): Extension<Arc<IpamOps>>,
    _tenant: crate::tenant::Tenant,
    _: RequirePlatformAdmin,
) -> impl IntoResponse {
    match ops.list_users().await {
        Ok(users) => {
            let list = UserList {
                count: users.len(),
                users,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/admin/users",
    request_body = UpsertUserRequest,
    responses(
        (status = 200, description = "User created or updated", body = UserRecord),
        (status = 400, description = "Invalid email", body = IpamErrorResponse),
        (status = 403, description = "Caller is not a platform admin"),
        (status = 409, description = "Refused: would remove the last active platform admin", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "auth"
))]
async fn admin_upsert_user(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequirePlatformAdmin,
    Json(body): Json<UpsertUserRequest>,
) -> impl IntoResponse {
    match ops
        .upsert_user(tenant.as_str(), &body.email, body.role, body.status)
        .await
    {
        Ok(user) => Json(user).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    delete,
    path = "/admin/users",
    params(DeleteUserQuery),
    responses(
        (status = 204, description = "User removed (tenant data untouched)"),
        (status = 403, description = "Caller is not a platform admin"),
        (status = 404, description = "No user for email", body = IpamErrorResponse),
        (status = 409, description = "Refused: last active platform admin", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "auth"
))]
async fn admin_delete_user(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequirePlatformAdmin,
    Query(query): Query<DeleteUserQuery>,
) -> impl IntoResponse {
    match ops.delete_user(tenant.as_str(), &query.email).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ipam_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/ipam/cidr-blocks",
    request_body = CreateCidrBlock,
    responses(
        (status = 201, description = "CIDR block created", body = CidrBlock),
        (status = 400, description = "Invalid CIDR", body = IpamErrorResponse),
        (status = 409, description = "Overlapping cidr_block", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_create_cidr_block(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAdmin,
    Json(body): Json<CreateCidrBlock>,
) -> impl IntoResponse {
    match ops.create_cidr_block(tenant.as_str(), &body).await {
        Ok(cidr_block) => (StatusCode::CREATED, Json(cidr_block)).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/cidr-blocks",
    params(CidrBlockListQuery),
    responses(
        (status = 200, description = "List of cidr_blocks", body = CidrBlockList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_list_cidr_blocks(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Query(query): Query<CidrBlockListQuery>,
) -> impl IntoResponse {
    match ops
        .list_cidr_blocks_page(tenant.as_str(), Some(page_limit(query.limit)), query.offset)
        .await
    {
        Ok(cidr_blocks) => {
            let list = CidrBlockList {
                count: cidr_blocks.len(),
                cidr_blocks,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/cidr-blocks/{id}",
    params(
        ("id" = String, Path, description = "CIDR block ID")
    ),
    responses(
        (status = 200, description = "CIDR block details", body = CidrBlock),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_get_cidr_block(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.get_cidr_block(tenant.as_str(), &id).await {
        Ok(cidr_block) => Json(cidr_block).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    delete,
    path = "/ipam/cidr-blocks/{id}",
    params(
        ("id" = String, Path, description = "CIDR block ID")
    ),
    responses(
        (status = 204, description = "CIDR block deleted"),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
        (status = 409, description = "CIDR block has active allocations", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_delete_cidr_block(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAdmin,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.delete_cidr_block(tenant.as_str(), &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/ipam/cidr-blocks/{id}/allocate-specific",
    params(
        ("id" = String, Path, description = "CIDR block ID")
    ),
    request_body = AllocateSpecificRequest,
    responses(
        (status = 201, description = "Allocation created", body = Allocation),
        (status = 400, description = "Invalid CIDR", body = IpamErrorResponse),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
        (status = 409, description = "Overlapping allocation", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_allocate_specific(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Path(cidr_block_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let key = idempotency_key(&headers, body.len());
    let parsed: AllocateSpecificRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return ipam_error_response(NetcidrError::InvalidInput(e.to_string())),
    };
    let input = parsed.into_create_allocation(cidr_block_id);

    match key {
        Some(k) => match ops
            .allocate_specific_idempotent(tenant.as_str(), &input, &k)
            .await
        {
            Ok(outcome) => outcome_response(outcome, StatusCode::CREATED),
            Err(e) => ipam_error_response(e),
        },
        None => match ops.allocate_specific(tenant.as_str(), &input).await {
            Ok(allocation) => (StatusCode::CREATED, Json(allocation)).into_response(),
            Err(e) => ipam_error_response(e),
        },
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/ipam/cidr-blocks/{id}/allocate",
    params(
        ("id" = String, Path, description = "CIDR block ID")
    ),
    request_body = AutoAllocateBody,
    responses(
        (status = 201, description = "Allocations created", body = AllocationList),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
        (status = 422, description = "No free space available", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_auto_allocate(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Path(cidr_block_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let key = idempotency_key(&headers, body.len());
    let parsed: AutoAllocateBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return ipam_error_response(NetcidrError::InvalidInput(e.to_string())),
    };
    let request = parsed.into_auto_allocate_request(cidr_block_id);

    match key {
        Some(k) => match ops
            .allocate_auto_idempotent(tenant.as_str(), &request, &k)
            .await
        {
            Ok(outcome) => {
                let wrapped = outcome.map(|allocations| AllocationList {
                    count: allocations.len(),
                    allocations,
                });
                outcome_response(wrapped, StatusCode::CREATED)
            }
            Err(e) => ipam_error_response(e),
        },
        None => match ops.allocate_auto(tenant.as_str(), &request).await {
            Ok(allocations) => {
                let list = AllocationList {
                    count: allocations.len(),
                    allocations,
                };
                (StatusCode::CREATED, Json(list)).into_response()
            }
            Err(e) => ipam_error_response(e),
        },
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/cidr-blocks/{id}/allocations",
    params(
        ("id" = String, Path, description = "CIDR block ID"),
        AllocationFilterQuery,
    ),
    responses(
        (status = 200, description = "List of allocations", body = AllocationList),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_list_cidr_block_allocations(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(cidr_block_id): Path<String>,
    Query(query): Query<AllocationFilterQuery>,
) -> impl IntoResponse {
    let status = query.status.and_then(|s| s.parse().ok());
    let filter = AllocationFilter {
        cidr_block_id: Some(cidr_block_id),
        status,
        resource_id: query.resource_id,
        resource_type: query.resource_type,
        environment: query.environment,
        owner: query.owner,
        limit: Some(page_limit(query.limit)),
        offset: query.offset,
    };
    match ops.list_allocations(tenant.as_str(), &filter).await {
        Ok(allocations) => {
            let list = AllocationList {
                count: allocations.len(),
                allocations,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/cidr-blocks/{id}/free",
    params(
        ("id" = String, Path, description = "CIDR block ID"),
        FreeBlocksQuery,
    ),
    responses(
        (status = 200, description = "Free blocks report", body = FreeBlocksReport),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_free_blocks(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(cidr_block_id): Path<String>,
    Query(query): Query<FreeBlocksQuery>,
) -> impl IntoResponse {
    match ops
        .free_blocks(tenant.as_str(), &cidr_block_id, query.prefix)
        .await
    {
        Ok(report) => Json(report).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/cidr-blocks/{id}/utilization",
    params(
        ("id" = String, Path, description = "CIDR block ID")
    ),
    responses(
        (status = 200, description = "Utilization report", body = UtilizationReport),
        (status = 404, description = "CIDR block not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_utilization(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(cidr_block_id): Path<String>,
) -> impl IntoResponse {
    match ops.utilization(tenant.as_str(), &cidr_block_id).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/allocations/{id}",
    params(
        ("id" = String, Path, description = "Allocation ID")
    ),
    responses(
        (status = 200, description = "Allocation details", body = Allocation),
        (status = 404, description = "Allocation not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_get_allocation(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.get_allocation(tenant.as_str(), &id).await {
        Ok(allocation) => Json(allocation).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    patch,
    path = "/ipam/allocations/{id}",
    params(
        ("id" = String, Path, description = "Allocation ID")
    ),
    request_body = UpdateAllocation,
    responses(
        (status = 200, description = "Allocation updated", body = Allocation),
        (status = 404, description = "Allocation not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_update_allocation(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Path(id): Path<String>,
    Json(body): Json<UpdateAllocation>,
) -> impl IntoResponse {
    match ops.update_allocation(tenant.as_str(), &id, &body).await {
        Ok(allocation) => Json(allocation).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/ipam/allocations/{id}/release",
    params(
        ("id" = String, Path, description = "Allocation ID")
    ),
    responses(
        (status = 200, description = "Allocation released", body = Allocation),
        (status = 404, description = "Allocation not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_release_allocation(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.release_allocation(tenant.as_str(), &id).await {
        Ok(allocation) => Json(allocation).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/find-ip/{address}",
    params(
        ("address" = String, Path, description = "IP address to look up")
    ),
    responses(
        (status = 200, description = "Matching allocations", body = AllocationList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_find_ip(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(address): Path<String>,
) -> impl IntoResponse {
    match ops.find_by_ip(tenant.as_str(), &address).await {
        Ok(allocations) => {
            let list = AllocationList {
                count: allocations.len(),
                allocations,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/find-resource/{resource_id}",
    params(
        ("resource_id" = String, Path, description = "Resource ID to look up")
    ),
    responses(
        (status = 200, description = "Matching allocations", body = AllocationList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_find_resource(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Path(resource_id): Path<String>,
) -> impl IntoResponse {
    match ops.find_by_resource(tenant.as_str(), &resource_id).await {
        Ok(allocations) => {
            let list = AllocationList {
                count: allocations.len(),
                allocations,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/ipam/hostnames",
    request_body = CreateHostnamePointer,
    responses(
        (status = 200, description = "Hostname pointer created or updated", body = HostnamePointer),
        (status = 400, description = "Invalid IP or hostname", body = IpamErrorResponse),
        (status = 404, description = "Linked allocation not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_set_hostname(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Json(body): Json<CreateHostnamePointer>,
) -> impl IntoResponse {
    match ops.set_hostname_pointer(tenant.as_str(), &body).await {
        Ok(pointer) => Json(pointer).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/hostnames",
    params(HostnameListQuery),
    responses(
        (status = 200, description = "Hostname pointers", body = HostnamePointerList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_list_hostnames(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Query(query): Query<HostnameListQuery>,
) -> impl IntoResponse {
    let filter = HostnamePointerFilter {
        ip_address: query.ip,
        hostname: query.hostname,
        allocation_id: query.allocation_id,
        limit: Some(page_limit(query.limit)),
        offset: query.offset,
    };
    match ops.list_hostname_pointers(tenant.as_str(), &filter).await {
        Ok(pointers) => {
            let list = HostnamePointerList {
                count: pointers.len(),
                pointers,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/hostnames/history",
    params(HostnameHistoryQuery),
    responses(
        (status = 200, description = "Hostname pointer change history", body = HostnamePointerHistoryList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_hostname_history(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Query(query): Query<HostnameHistoryQuery>,
) -> impl IntoResponse {
    let filter = HostnameHistoryFilter {
        ip_address: query.ip,
        hostname: query.hostname,
        limit: Some(page_limit(query.limit)),
        offset: query.offset,
    };
    match ops.list_hostname_history(tenant.as_str(), &filter).await {
        Ok(entries) => {
            let list = HostnamePointerHistoryList {
                count: entries.len(),
                entries,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    delete,
    path = "/ipam/hostnames",
    params(HostnameDeleteQuery),
    responses(
        (status = 204, description = "Hostname pointer deleted"),
        (status = 404, description = "Hostname pointer not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_delete_hostname(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Query(query): Query<HostnameDeleteQuery>,
) -> impl IntoResponse {
    match ops
        .delete_hostname_pointer(tenant.as_str(), &query.ip, &query.hostname)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/audit",
    params(AuditQuery),
    responses(
        (status = 200, description = "Audit log entries", body = AuditList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_query_audit(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAdmin,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let filter = AuditFilter {
        entity_type: query.entity_type,
        entity_id: query.entity_id,
        action: query.action,
        caller_email: query.caller_email,
        pat_id: query.pat_id,
        // Default + clamp so omitting `limit` can't dump the whole audit log.
        limit: Some(page_limit(query.limit)),
    };
    match ops.query_audit(tenant.as_str(), &filter).await {
        Ok(entries) => {
            let list = AuditList {
                count: entries.len(),
                entries,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    put,
    path = "/ipam/allocations/{id}/tags",
    params(
        ("id" = String, Path, description = "Allocation ID")
    ),
    request_body = TagsBody,
    responses(
        (status = 200, description = "Tags updated, returns allocation", body = Allocation),
        (status = 404, description = "Allocation not found", body = IpamErrorResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_set_tags(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Path(id): Path<String>,
    Json(body): Json<TagsBody>,
) -> impl IntoResponse {
    if let Err(e) = ops.set_tags(tenant.as_str(), &id, &body.tags).await {
        return ipam_error_response(e);
    }
    match ops.get_allocation(tenant.as_str(), &id).await {
        Ok(allocation) => Json(allocation).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Batch handlers
// ---------------------------------------------------------------------------

async fn ipam_batch_allocate(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let key = idempotency_key(&headers, body.len());
    let items: Vec<BatchAllocateItem> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return ipam_error_response(NetcidrError::InvalidInput(e.to_string())),
    };

    match key {
        Some(k) => match ops
            .batch_allocate_idempotent(tenant.as_str(), &items, &k)
            .await
        {
            Ok(outcome) => outcome_response(outcome, StatusCode::OK),
            Err(e) => ipam_error_response(e),
        },
        None => match ops.batch_allocate(tenant.as_str(), &items).await {
            Ok(result) => (StatusCode::OK, Json(result)).into_response(),
            Err(e) => ipam_error_response(e),
        },
    }
}

async fn ipam_batch_release(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireAllocator,
    Json(body): Json<BatchReleaseRequest>,
) -> impl IntoResponse {
    match ops.batch_release(tenant.as_str(), &body).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

async fn ipam_batch_summary(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
    _: RequireReader,
    Query(query): Query<SummaryQuery>,
) -> impl IntoResponse {
    match ops
        .allocation_summary(tenant.as_str(), query.cidr_block_id.as_deref())
        .await
    {
        Ok(summary) => Json(summary).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limit_defaults_and_clamps() {
        assert_eq!(page_limit(None), DEFAULT_PAGE_LIMIT);
        assert_eq!(page_limit(Some(50)), 50);
        // Clamped up from 0 to the minimum of 1.
        assert_eq!(page_limit(Some(0)), 1);
        // Clamped down to the hard ceiling.
        assert_eq!(page_limit(Some(u32::MAX)), MAX_PAGE_LIMIT);
        assert_eq!(page_limit(Some(MAX_PAGE_LIMIT + 1)), MAX_PAGE_LIMIT);
    }
}
