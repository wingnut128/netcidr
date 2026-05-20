//! End-to-end RBAC: every IPAM handler now requires an explicit role tier
//! via `RequireReader` / `RequireAllocator` / `RequireAdmin` (see
//! `src/authorization.rs` + ADR-0002). These tests exercise the seam
//! through the real router: a `Reader` principal hitting an `Allocator`
//! or `Admin` route gets 403 with a scrubbed body; a sufficient principal
//! gets the handler's normal response.
//!
//! Default-Admin policy: a request with no `X-Test-Role` header inherits
//! `Role::Admin`, which is the back-compat default that PR1 ships with.
//! That keeps every other integration test in this repo passing without
//! per-test changes.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::ServerConfig;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use tower::ServiceExt;

mod common;
use common::{ROLE_HEADER, TENANT_HEADER, with_test_tenant};

const TENANT: &str = "tester@example.com";

async fn app() -> axum::Router {
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
        pat_pepper: None,
    });
    with_test_tenant(router)
}

/// Send a request with a specific role and return (status, body string).
async fn send_as(
    app: &axum::Router,
    method: &str,
    uri: &str,
    role: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(TENANT_HEADER, TENANT);
    if let Some(r) = role {
        builder = builder.header(ROLE_HEADER, r);
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let req = builder
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8(bytes.to_vec()).unwrap_or_default(),
    )
}

#[tokio::test]
async fn reader_can_list_cidr_blocks() {
    let app = app().await;
    let (status, _body) = send_as(&app, "GET", "/ipam/cidr-blocks", Some("reader"), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn reader_denied_creating_cidr_block_with_403() {
    // POST /ipam/cidr-blocks is Admin-gated; a reader principal is denied.
    let app = app().await;
    let (status, body) = send_as(
        &app,
        "POST",
        "/ipam/cidr-blocks",
        Some("reader"),
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // 403 body must not echo the role names — the contract is a fixed
    // "Forbidden" string. Operator-side correlation goes through logs.
    assert!(body.contains("Forbidden"), "expected Forbidden, got {body}");
    assert!(
        !body.contains("Reader") && !body.contains("Admin"),
        "403 body leaked role detail: {body}"
    );
}

#[tokio::test]
async fn allocator_denied_creating_cidr_block_with_403() {
    let app = app().await;
    let (status, _body) = send_as(
        &app,
        "POST",
        "/ipam/cidr-blocks",
        Some("allocator"),
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reader_denied_allocating_with_403() {
    // POST /ipam/cidr-blocks/{id}/allocate is Allocator-gated.
    // Bootstrap the cidr_block as admin so the test focuses on the deny path.
    let app = app().await;
    let (create_status, body) = send_as(
        &app,
        "POST",
        "/ipam/cidr-blocks",
        Some("admin"),
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED, "bootstrap: {body}");
    let cidr_block_id: String = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _body) = send_as(
        &app,
        "POST",
        &format!("/ipam/cidr-blocks/{cidr_block_id}/allocate-specific"),
        Some("reader"),
        Some(r#"{"cidr":"10.0.0.0/16"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allocator_can_allocate() {
    let app = app().await;
    let (create_status, body) = send_as(
        &app,
        "POST",
        "/ipam/cidr-blocks",
        Some("admin"),
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED, "bootstrap: {body}");
    let cidr_block_id: String = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = send_as(
        &app,
        "POST",
        &format!("/ipam/cidr-blocks/{cidr_block_id}/allocate-specific"),
        Some("allocator"),
        Some(r#"{"cidr":"10.0.0.0/16"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "allocate failed: {body}");
}

#[tokio::test]
async fn admin_can_query_audit() {
    // GET /ipam/audit is Admin-only (sensitive read).
    let app = app().await;
    let (status, _body) = send_as(&app, "GET", "/ipam/audit", Some("admin"), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn allocator_denied_query_audit() {
    let app = app().await;
    let (status, _body) = send_as(&app, "GET", "/ipam/audit", Some("allocator"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reader_denied_query_audit() {
    let app = app().await;
    let (status, _body) = send_as(&app, "GET", "/ipam/audit", Some("reader"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_role_header_defaults_to_admin() {
    // PR1 back-compat: no X-Test-Role header → default Admin → all routes work.
    // This is what keeps every other integration test in this repo green.
    let app = app().await;
    let (status, _body) = send_as(
        &app,
        "POST",
        "/ipam/cidr-blocks",
        None,
        Some(r#"{"cidr":"10.0.0.0/8"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _body) = send_as(&app, "GET", "/ipam/audit", None, None).await;
    assert_eq!(status, StatusCode::OK);
}
