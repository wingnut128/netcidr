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
use crate::ipam::idempotency;
use crate::ipam::models::*;
use crate::ipam::operations::IpamOps;

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

pub(crate) fn error_to_status_value(err: NetcidrError) -> (StatusCode, serde_json::Value) {
    let (status, client_msg) = error_to_parts(&err);
    (status, serde_json::json!({ "error": client_msg }))
}

fn ipam_error_response(err: NetcidrError) -> Response {
    let (status, client_msg) = error_to_parts(&err);
    let body = serde_json::json!({ "error": client_msg });
    (status, Json(body)).into_response()
}

fn error_to_parts(err: &NetcidrError) -> (StatusCode, String) {
    match err {
        NetcidrError::InvalidCidr(_)
        | NetcidrError::InvalidPrefixLength { .. }
        | NetcidrError::InvalidInput(_)
        | NetcidrError::InvalidSubnetSplit { .. }
        | NetcidrError::InvalidIpv4Address(_)
        | NetcidrError::InvalidIpv6Address(_) => (StatusCode::BAD_REQUEST, err.to_string()),

        NetcidrError::SupernetNotFound(_) | NetcidrError::AllocationNotFound(_) => {
            (StatusCode::NOT_FOUND, err.to_string())
        }

        NetcidrError::AllocationConflict { .. } | NetcidrError::SupernetHasActiveAllocations(_) => {
            (StatusCode::CONFLICT, err.to_string())
        }

        NetcidrError::NoFreeSpace { .. } => (StatusCode::UNPROCESSABLE_ENTITY, err.to_string()),

        // DatabaseError: classify by content for status code, but never expose
        // raw DB messages (table names, file paths, constraint names) to clients.
        NetcidrError::DatabaseError(msg)
            if msg.contains("not found") || msg.contains("No supernet") =>
        {
            tracing::error!(error = %err, "database error");
            (StatusCode::NOT_FOUND, "not found".to_string())
        }

        NetcidrError::DatabaseError(msg) if msg.contains("overlap") || msg.contains("conflict") => {
            tracing::error!(error = %err, "database error");
            (StatusCode::CONFLICT, "allocation conflict".to_string())
        }

        NetcidrError::DatabaseError(_) => {
            tracing::error!(error = %err, "database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".to_string(),
            )
        }

        _ => {
            tracing::error!(error = %err, "unexpected error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".to_string(),
            )
        }
    }
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
    headers: HeaderMap,
    body: Bytes,
    scope: String,
    handler: F,
) -> Response
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(Arc<IpamOps>, T) -> Fut,
    Fut: std::future::Future<
            Output = std::result::Result<(StatusCode, serde_json::Value), NetcidrError>,
        >,
{
    let outcome = if body.len() <= idempotency::MAX_BODY_BYTES {
        match idempotency::check(ops.store(), &headers, &scope, &body).await {
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

    let (status, value) = match handler(ops.clone(), parsed).await {
        Ok(pair) => pair,
        Err(e) => error_to_status_value(e),
    };

    if status.is_success()
        && let idempotency::Outcome::Proceed { key, request_hash } = outcome
    {
        let cached_body = value.to_string();
        if let Err(e) = idempotency::record(
            ops.store(),
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
    /// Filter by entity type (supernet, allocation)
    pub entity_type: Option<String>,
    /// Filter by entity ID
    pub entity_id: Option<String>,
    /// Filter by action (e.g., create_supernet, allocate)
    pub action: Option<String>,
    /// Maximum number of entries to return
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "swagger", derive(IntoParams))]
pub struct SummaryQuery {
    /// Optional supernet ID to scope the summary
    pub supernet_id: Option<String>,
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
            "/supernets",
            post(ipam_create_supernet).get(ipam_list_supernets),
        )
        .route(
            "/supernets/{id}",
            get(ipam_get_supernet).delete(ipam_delete_supernet),
        )
        .route("/supernets/{id}/allocate", post(ipam_auto_allocate))
        .route(
            "/supernets/{id}/allocate-specific",
            post(ipam_allocate_specific),
        )
        .route(
            "/supernets/{id}/allocations",
            get(ipam_list_supernet_allocations),
        )
        .route("/supernets/{id}/free", get(ipam_free_blocks))
        .route("/supernets/{id}/utilization", get(ipam_utilization))
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
    path = "/ipam/supernets",
    request_body = CreateSupernet,
    responses(
        (status = 201, description = "Supernet created", body = Supernet),
        (status = 400, description = "Invalid CIDR", body = IpamErrorResponse),
        (status = 409, description = "Overlapping supernet", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_create_supernet(
    Extension(ops): Extension<Arc<IpamOps>>,
    Json(body): Json<CreateSupernet>,
) -> impl IntoResponse {
    match ops.create_supernet(&body).await {
        Ok(supernet) => (StatusCode::CREATED, Json(supernet)).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/supernets",
    responses(
        (status = 200, description = "List of supernets", body = SupernetList),
    ),
    tag = "ipam"
))]
async fn ipam_list_supernets(Extension(ops): Extension<Arc<IpamOps>>) -> impl IntoResponse {
    match ops.list_supernets().await {
        Ok(supernets) => {
            let list = SupernetList {
                count: supernets.len(),
                supernets,
            };
            Json(list).into_response()
        }
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/supernets/{id}",
    params(
        ("id" = String, Path, description = "Supernet ID")
    ),
    responses(
        (status = 200, description = "Supernet details", body = Supernet),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_get_supernet(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.get_supernet(&id).await {
        Ok(supernet) => Json(supernet).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    delete,
    path = "/ipam/supernets/{id}",
    params(
        ("id" = String, Path, description = "Supernet ID")
    ),
    responses(
        (status = 204, description = "Supernet deleted"),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
        (status = 409, description = "Supernet has active allocations", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_delete_supernet(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.delete_supernet(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/ipam/supernets/{id}/allocate-specific",
    params(
        ("id" = String, Path, description = "Supernet ID")
    ),
    request_body = AllocateSpecificRequest,
    responses(
        (status = 201, description = "Allocation created", body = Allocation),
        (status = 400, description = "Invalid CIDR", body = IpamErrorResponse),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
        (status = 409, description = "Overlapping allocation", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_allocate_specific(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(supernet_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let scope = format!("allocate-specific:{supernet_id}");
    idempotent_post::<AllocateSpecificRequest, _, _>(
        ops,
        headers,
        body,
        scope,
        move |ops, parsed: AllocateSpecificRequest| {
            let supernet_id = supernet_id.clone();
            async move {
                let input = CreateAllocation {
                    supernet_id,
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
                let allocation = ops.allocate_specific(&input).await?;
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
    path = "/ipam/supernets/{id}/allocate",
    params(
        ("id" = String, Path, description = "Supernet ID")
    ),
    request_body = AutoAllocateBody,
    responses(
        (status = 201, description = "Allocations created", body = AllocationList),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
        (status = 422, description = "No free space available", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_auto_allocate(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(supernet_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let scope = format!("auto-allocate:{supernet_id}");
    idempotent_post::<AutoAllocateBody, _, _>(
        ops,
        headers,
        body,
        scope,
        move |ops, parsed: AutoAllocateBody| {
            let supernet_id = supernet_id.clone();
            async move {
                let request = AutoAllocateRequest {
                    supernet_id,
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
                let allocations = ops.allocate_auto(&request).await?;
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
    path = "/ipam/supernets/{id}/allocations",
    params(
        ("id" = String, Path, description = "Supernet ID"),
        AllocationFilterQuery,
    ),
    responses(
        (status = 200, description = "List of allocations", body = AllocationList),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_list_supernet_allocations(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(supernet_id): Path<String>,
    Query(query): Query<AllocationFilterQuery>,
) -> impl IntoResponse {
    let status = query.status.and_then(|s| s.parse().ok());
    let filter = AllocationFilter {
        supernet_id: Some(supernet_id),
        status,
        resource_id: query.resource_id,
        resource_type: query.resource_type,
        environment: query.environment,
        owner: query.owner,
    };
    match ops.list_allocations(&filter).await {
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
    path = "/ipam/supernets/{id}/free",
    params(
        ("id" = String, Path, description = "Supernet ID"),
        FreeBlocksQuery,
    ),
    responses(
        (status = 200, description = "Free blocks report", body = FreeBlocksReport),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_free_blocks(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(supernet_id): Path<String>,
    Query(query): Query<FreeBlocksQuery>,
) -> impl IntoResponse {
    match ops.free_blocks(&supernet_id, query.prefix).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/ipam/supernets/{id}/utilization",
    params(
        ("id" = String, Path, description = "Supernet ID")
    ),
    responses(
        (status = 200, description = "Utilization report", body = UtilizationReport),
        (status = 404, description = "Supernet not found", body = IpamErrorResponse),
    ),
    tag = "ipam"
))]
async fn ipam_utilization(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(supernet_id): Path<String>,
) -> impl IntoResponse {
    match ops.utilization(&supernet_id).await {
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
    tag = "ipam"
))]
async fn ipam_get_allocation(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.get_allocation(&id).await {
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
    tag = "ipam"
))]
async fn ipam_update_allocation(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(id): Path<String>,
    Json(body): Json<UpdateAllocation>,
) -> impl IntoResponse {
    match ops.update_allocation(&id, &body).await {
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
    tag = "ipam"
))]
async fn ipam_release_allocation(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ops.release_allocation(&id).await {
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
    tag = "ipam"
))]
async fn ipam_find_ip(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    match ops.find_by_ip(&address).await {
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
    tag = "ipam"
))]
async fn ipam_find_resource(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(resource_id): Path<String>,
) -> impl IntoResponse {
    match ops.find_by_resource(&resource_id).await {
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
    tag = "ipam"
))]
async fn ipam_query_audit(
    Extension(ops): Extension<Arc<IpamOps>>,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let filter = AuditFilter {
        entity_type: query.entity_type,
        entity_id: query.entity_id,
        action: query.action,
        limit: query.limit,
    };
    match ops.query_audit(&filter).await {
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
    tag = "ipam"
))]
async fn ipam_set_tags(
    Extension(ops): Extension<Arc<IpamOps>>,
    Path(id): Path<String>,
    Json(body): Json<TagsBody>,
) -> impl IntoResponse {
    if let Err(e) = ops.set_tags(&id, &body.tags).await {
        return ipam_error_response(e);
    }
    match ops.get_allocation(&id).await {
        Ok(allocation) => Json(allocation).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Batch handlers
// ---------------------------------------------------------------------------

async fn ipam_batch_allocate(
    Extension(ops): Extension<Arc<IpamOps>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let scope = "batch-allocate".to_string();
    idempotent_post::<Vec<BatchAllocateItem>, _, _>(
        ops,
        headers,
        body,
        scope,
        |ops, items: Vec<BatchAllocateItem>| async move {
            let result = ops.batch_allocate(&items).await?;
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
    Json(body): Json<BatchReleaseRequest>,
) -> impl IntoResponse {
    match ops.batch_release(&body).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => ipam_error_response(e),
    }
}

async fn ipam_batch_summary(
    Extension(ops): Extension<Arc<IpamOps>>,
    Query(query): Query<SummaryQuery>,
) -> impl IntoResponse {
    match ops.allocation_summary(query.supernet_id.as_deref()).await {
        Ok(summary) => Json(summary).into_response(),
        Err(e) => ipam_error_response(e),
    }
}
