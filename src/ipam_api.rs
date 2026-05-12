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

use crate::error::NetcidrError;
use crate::error_presenter::{LogLevel, present};
use crate::ipam::idempotency;
use crate::ipam::models::*;
use crate::ipam::operations::IpamOps;

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
// Idempotency wrapper for allocation handlers
// ---------------------------------------------------------------------------

/// Wrap a JSON-in/JSON-out POST allocation handler with `Idempotency-Key`
/// semantics. Behavior:
/// * Same key + same body → replay cached response (sets `Idempotent-Replay: true`).
/// * Same key + different body → 409 Conflict.
/// * No key → behave normally (no cache write).
///
/// Successful 2xx responses are cached. Error responses are not cached so a
/// retry with the same key can still succeed once the underlying issue clears.
async fn idempotent_post<T, F, Fut>(
    ops: Arc<IpamOps>,
    tenant_id: String,
    headers: HeaderMap,
    body: Bytes,
    scope: String,
    handler: F,
) -> Response
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(Arc<IpamOps>, String, T) -> Fut,
    Fut: std::future::Future<
            Output = std::result::Result<(StatusCode, serde_json::Value), NetcidrError>,
        >,
{
    let outcome = if body.len() <= idempotency::MAX_BODY_BYTES {
        match idempotency::check(ops.store(), &tenant_id, &headers, &scope, &body).await {
            Ok(o) => o,
            Err(e) => return ipam_error_response(e),
        }
    } else {
        idempotency::Outcome::NoKey
    };

    if let idempotency::Outcome::Replay {
        status,
        body: cached,
    } = &outcome
    {
        return Response::builder()
            .status(StatusCode::from_u16(*status).unwrap_or(StatusCode::OK))
            .header("Content-Type", "application/json")
            .header("Idempotent-Replay", "true")
            .body(cached.clone().into())
            .expect("static headers always valid");
    }

    if matches!(outcome, idempotency::Outcome::Conflict) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Idempotency-Key reused with a different request body",
            })),
        )
            .into_response();
    }

    let parsed: T = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return ipam_error_response(NetcidrError::InvalidInput(e.to_string())),
    };

    let (status, value) = match handler(ops.clone(), tenant_id.clone(), parsed).await {
        Ok(pair) => pair,
        Err(e) => error_to_status_value(e),
    };

    if status.is_success()
        && let idempotency::Outcome::Proceed { key, request_hash } = outcome
    {
        let cached_body = value.to_string();
        if let Err(e) = idempotency::record(
            ops.store(),
            &tenant_id,
            &key,
            &scope,
            &request_hash,
            status.as_u16(),
            &cached_body,
        )
        .await
        {
            tracing::warn!(error = %e, "failed to record idempotency key");
        }
    }

    (status, Json(value)).into_response()
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
    /// Maximum number of entries to return
    pub limit: Option<u32>,
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
        .route("/audit", get(ipam_query_audit))
        .route("/batch/allocate", post(ipam_batch_allocate))
        .route("/batch/release", post(ipam_batch_release))
        .route("/batch/summary", get(ipam_batch_summary))
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
    responses(
        (status = 200, description = "List of cidr_blocks", body = CidrBlockList),
    ),
    security(("bearerAuth" = [])),
    tag = "ipam"
))]
async fn ipam_list_cidr_blocks(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
) -> impl IntoResponse {
    match ops.list_cidr_blocks(tenant.as_str()).await {
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
    Path(cidr_block_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let scope = format!("allocate-specific:{cidr_block_id}");
    idempotent_post::<AllocateSpecificRequest, _, _>(
        ops,
        tenant.0,
        headers,
        body,
        scope,
        move |ops, tenant_id, parsed: AllocateSpecificRequest| {
            let cidr_block_id = cidr_block_id.clone();
            async move {
                let input = CreateAllocation {
                    cidr_block_id,
                    cidr: parsed.cidr,
                    status: parsed.status,
                    resource_id: parsed.resource_id,
                    resource_type: parsed.resource_type,
                    name: parsed.name,
                    description: parsed.description,
                    environment: parsed.environment,
                    owner: parsed.owner,
                    parent_allocation_id: parsed.parent_allocation_id,
                    tags: parsed.tags,
                    ttl_seconds: parsed.ttl_seconds,
                };
                let allocation = ops.allocate_specific(&tenant_id, &input).await?;
                Ok((
                    StatusCode::CREATED,
                    serde_json::to_value(&allocation).unwrap_or(serde_json::Value::Null),
                ))
            }
        },
    )
    .await
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
    Path(cidr_block_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let scope = format!("auto-allocate:{cidr_block_id}");
    idempotent_post::<AutoAllocateBody, _, _>(
        ops,
        tenant.0,
        headers,
        body,
        scope,
        move |ops, tenant_id, parsed: AutoAllocateBody| {
            let cidr_block_id = cidr_block_id.clone();
            async move {
                let request = AutoAllocateRequest {
                    cidr_block_id,
                    prefix_length: parsed.prefix_length,
                    count: parsed.count,
                    status: parsed.status,
                    resource_id: parsed.resource_id,
                    resource_type: parsed.resource_type,
                    name: parsed.name,
                    description: parsed.description,
                    environment: parsed.environment,
                    owner: parsed.owner,
                    parent_allocation_id: parsed.parent_allocation_id,
                    tags: parsed.tags,
                    ttl_seconds: parsed.ttl_seconds,
                };
                let allocations = ops.allocate_auto(&tenant_id, &request).await?;
                let list = AllocationList {
                    count: allocations.len(),
                    allocations,
                };
                Ok((
                    StatusCode::CREATED,
                    serde_json::to_value(&list).unwrap_or(serde_json::Value::Null),
                ))
            }
        },
    )
    .await
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
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let filter = AuditFilter {
        entity_type: query.entity_type,
        entity_id: query.entity_id,
        action: query.action,
        limit: query.limit,
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let scope = "batch-allocate".to_string();
    idempotent_post::<Vec<BatchAllocateItem>, _, _>(
        ops,
        tenant.0,
        headers,
        body,
        scope,
        |ops, tenant_id, items: Vec<BatchAllocateItem>| async move {
            let result = ops.batch_allocate(&tenant_id, &items).await?;
            Ok((
                StatusCode::OK,
                serde_json::to_value(&result).unwrap_or(serde_json::Value::Null),
            ))
        },
    )
    .await
}

async fn ipam_batch_release(
    Extension(ops): Extension<Arc<IpamOps>>,
    tenant: crate::tenant::Tenant,
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
