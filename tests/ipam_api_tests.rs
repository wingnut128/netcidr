use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use http_body_util::BodyExt;
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use tower::ServiceExt;

mod common;
use common::{TENANT_HEADER, TEST_TENANT, with_test_tenant};

async fn ipam_app() -> axum::Router {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let ops = Arc::new(IpamOps::new(Arc::new(store)));
    let router = create_router(RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ipam_ops: Some(ops),
    });
    with_test_tenant(router)
}

async fn req(
    app: axum::Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(TENANT_HEADER, TEST_TENANT);
    let req = if let Some(b) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp: Response = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let json = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
    };
    (status, json)
}

// ── CidrBlock CRUD ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_cidr_block_lifecycle() {
    let app = ipam_app().await;

    // Create
    let (status, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8","name":"test-net"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = json["id"].as_str().unwrap().to_string();
    assert_eq!(json["cidr"], "10.0.0.0/8");
    assert_eq!(json["name"], "test-net");

    // List
    let (status, json) = req(app.clone(), "GET", "/ipam/cidr-blocks", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["count"], 1);

    // Get
    let (status, json) = req(app.clone(), "GET", &format!("/ipam/cidr-blocks/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["cidr"], "10.0.0.0/8");

    // Delete
    let (status, _) = req(
        app.clone(),
        "DELETE",
        &format!("/ipam/cidr-blocks/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify gone
    let (status, _) = req(app, "GET", &format!("/ipam/cidr-blocks/{id}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Allocation workflow ───────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_allocate_specific() {
    let app = ipam_app().await;

    // Create cidr_block
    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    // Allocate specific
    let (status, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24","name":"web-tier"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["cidr"], "10.0.1.0/24");
    assert_eq!(json["name"], "web-tier");
    assert_eq!(json["status"], "active");
    let alloc_id = json["id"].as_str().unwrap().to_string();

    // Get allocation
    let (status, json) = req(
        app.clone(),
        "GET",
        &format!("/ipam/allocations/{alloc_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["cidr"], "10.0.1.0/24");
}

#[tokio::test]
async fn test_ipam_auto_allocate() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"192.168.0.0/16"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (status, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate"),
        Some(r#"{"prefix_length":24,"count":3}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["count"], 3);
}

// ── Overlap rejected ──────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_overlap_rejected() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    // First allocation succeeds
    let (status, _) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.0.0/24"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Overlapping allocation fails
    let (status, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.0.0/16"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("overlap"));
}

// ── Release ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_release_allocation() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (_, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24"}"#),
    )
    .await;
    let alloc_id = json["id"].as_str().unwrap().to_string();

    let (status, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/allocations/{alloc_id}/release"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "released");
}

// ── Update allocation ─────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_update_allocation() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (_, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24"}"#),
    )
    .await;
    let alloc_id = json["id"].as_str().unwrap().to_string();

    let (status, json) = req(
        app.clone(),
        "PATCH",
        &format!("/ipam/allocations/{alloc_id}"),
        Some(r#"{"owner":"ops-team","environment":"production"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["owner"], "ops-team");
    assert_eq!(json["environment"], "production");
}

// ── Utilization and free blocks ───────────────────────────────────────

#[tokio::test]
async fn test_ipam_utilization_and_free_blocks() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"192.168.0.0/24"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    // Allocate half
    req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"192.168.0.0/25"}"#),
    )
    .await;

    // Utilization
    let (status, json) = req(
        app.clone(),
        "GET",
        &format!("/ipam/cidr-blocks/{sn_id}/utilization"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["utilization_percent"].as_f64().unwrap() > 40.0);

    // Free blocks
    let (status, json) = req(
        app.clone(),
        "GET",
        &format!("/ipam/cidr-blocks/{sn_id}/free"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!json["blocks"].as_array().unwrap().is_empty());
}

// ── Find by IP ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_find_ip() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24"}"#),
    )
    .await;

    let (status, json) = req(app.clone(), "GET", "/ipam/find-ip/10.0.1.50", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["count"], 1);
    assert_eq!(json["allocations"][0]["cidr"], "10.0.1.0/24");
}

// ── Find by resource ──────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_find_resource() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24","resource_id":"vpc-123"}"#),
    )
    .await;

    let (status, json) = req(app.clone(), "GET", "/ipam/find-resource/vpc-123", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["count"], 1);
}

// ── Audit log ─────────────────────────────────────────────────────────

async fn ipam_app_with_bearer_auth() -> axum::Router {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let ops = Arc::new(IpamOps::new(Arc::new(store)));
    create_router(RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            auth_mode: AuthMode::Bearer,
            auth_token: Some("test-token".to_string()),
            ..Default::default()
        },
        ipam_ops: Some(ops),
    })
}

async fn req_with_bearer(
    app: axum::Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let req = if let Some(b) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp: Response = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let json = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
    };
    (status, json)
}

#[tokio::test]
async fn test_ipam_audit_records_caller_identity_and_request_id() {
    let app = ipam_app_with_bearer_auth().await;

    let (status, _) = req_with_bearer(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
        "test-token",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, json) =
        req_with_bearer(app, "GET", "/ipam/audit?limit=10", None, "test-token").await;
    assert_eq!(status, StatusCode::OK);
    let entry = &json["entries"][0];
    assert_eq!(entry["action"], "create_cidr_block");

    // Bearer mode: subject is the static "bearer-token" sentinel; email is null.
    assert_eq!(entry["caller_sub"], "bearer-token");
    assert!(
        entry["caller_email"].is_null(),
        "bearer auth has no email; got {:?}",
        entry["caller_email"]
    );

    // Request ID is generated by the auth middleware as a UUID v4.
    let req_id = entry["request_id"]
        .as_str()
        .expect("request_id should be set on authenticated mutations");
    assert_eq!(
        req_id.len(),
        36,
        "expected UUID-shaped request_id, got {req_id:?}"
    );
    assert_eq!(req_id.matches('-').count(), 4);
}

#[tokio::test]
async fn test_ipam_audit_log() {
    let app = ipam_app().await;

    // Create cidr_block (generates audit entry)
    req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;

    let (status, json) = req(app.clone(), "GET", "/ipam/audit?limit=10", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["count"].as_u64().unwrap() >= 1);
    assert_eq!(json["entries"][0]["action"], "create_cidr_block");
}

// ── Tags ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_tags() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (_, json) = req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24"}"#),
    )
    .await;
    let alloc_id = json["id"].as_str().unwrap().to_string();

    let (status, json) = req(
        app.clone(),
        "PUT",
        &format!("/ipam/allocations/{alloc_id}/tags"),
        Some(r#"{"tags":[{"key":"env","value":"prod"},{"key":"team","value":"platform"}]}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tags = json["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 2);
}

// ── IPAM disabled returns 404 ─────────────────────────────────────────

#[tokio::test]
async fn test_ipam_disabled_returns_404() {
    let app = create_router(RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ..Default::default()
    });
    let (status, _) = req(app, "GET", "/ipam/cidr-blocks", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Not found ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ipam_cidr_block_not_found() {
    let app = ipam_app().await;
    let (status, _) = req(app, "GET", "/ipam/cidr-blocks/nonexistent-id", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_ipam_allocation_not_found() {
    let app = ipam_app().await;
    let (status, _) = req(app, "GET", "/ipam/allocations/nonexistent-id", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Invalid input returns 400 ─────────────────────────────────────────

#[tokio::test]
async fn test_ipam_invalid_cidr() {
    let app = ipam_app().await;
    let (status, json) = req(
        app,
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"not-a-cidr"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!json["error"].as_str().unwrap().is_empty());
}

// ── List cidr_block allocations with filter ─────────────────────────────

#[tokio::test]
async fn test_ipam_list_allocations_with_filter() {
    let app = ipam_app().await;

    let (_, json) = req(
        app.clone(),
        "POST",
        "/ipam/cidr-blocks",
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    let sn_id = json["id"].as_str().unwrap().to_string();

    // Create two allocations
    req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.1.0/24","environment":"prod"}"#),
    )
    .await;
    req(
        app.clone(),
        "POST",
        &format!("/ipam/cidr-blocks/{sn_id}/allocate-specific"),
        Some(r#"{"cidr":"10.0.2.0/24","environment":"staging"}"#),
    )
    .await;

    // Filter by environment
    let (status, json) = req(
        app.clone(),
        "GET",
        &format!("/ipam/cidr-blocks/{sn_id}/allocations?environment=prod"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["count"], 1);
    assert_eq!(json["allocations"][0]["environment"], "prod");
}
