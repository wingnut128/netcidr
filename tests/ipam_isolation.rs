//! HTTP-level multi-tenant isolation matrix.
//!
//! Boots an in-memory netcidr API with a synthetic tenant-injection
//! middleware (see `tests/common/mod.rs`). The middleware reads
//! `X-Test-Tenant` and inserts a `Tenant` extension on each request, so
//! the production handler -> ops -> store path runs end-to-end without
//! standing up a real OIDC IdP.
//!
//! Two tenants `a@example.com` and `b@example.com` exercise the five
//! cross-tenant guarantees: supernets, allocations, audit log, idempotency
//! keys, and same-CIDR reuse.

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
use common::{TENANT_HEADER, with_test_tenant};

const TENANT_A: &str = "a@example.com";
const TENANT_B: &str = "b@example.com";

async fn isolation_app() -> axum::Router {
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

struct ReqResult {
    status: StatusCode,
    body: serde_json::Value,
    replay: bool,
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    tenant: &str,
    body: Option<&str>,
    idem_key: Option<&str>,
) -> ReqResult {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(TENANT_HEADER, tenant);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(k) = idem_key {
        builder = builder.header("Idempotency-Key", k);
    }
    let req = builder
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let replay = resp
        .headers()
        .get("Idempotent-Replay")
        .map(|v| v == "true")
        .unwrap_or(false);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let json = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
    };
    ReqResult {
        status,
        body: json,
        replay,
    }
}

async fn create_supernet(app: &axum::Router, tenant: &str, cidr: &str) -> String {
    let r = send(
        app,
        "POST",
        "/ipam/supernets",
        tenant,
        Some(&format!(r#"{{"cidr":"{cidr}"}}"#)),
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::CREATED,
        "create_supernet failed: {:?}",
        r.body
    );
    r.body["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn supernets_are_isolated_per_tenant() {
    let app = isolation_app().await;
    let s_a_id = create_supernet(&app, TENANT_A, "10.0.0.0/8").await;

    // B sees zero supernets.
    let r = send(&app, "GET", "/ipam/supernets", TENANT_B, None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body["count"], 0,
        "tenant B must not see tenant A's supernet"
    );

    // A sees its own one supernet.
    let r = send(&app, "GET", "/ipam/supernets", TENANT_A, None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["count"], 1);

    // B requesting A's supernet by ID gets 404, not 403.
    let r = send(
        &app,
        "GET",
        &format!("/ipam/supernets/{s_a_id}"),
        TENANT_B,
        None,
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "cross-tenant supernet read must 404 (no existence leak)"
    );
}

#[tokio::test]
async fn same_cidr_in_two_tenants_both_succeed() {
    let app = isolation_app().await;
    for tenant in [TENANT_A, TENANT_B] {
        let r = send(
            &app,
            "POST",
            "/ipam/supernets",
            tenant,
            Some(r#"{"cidr":"10.0.0.0/8"}"#),
            None,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::CREATED,
            "tenant {tenant} should accept its own 10.0.0.0/8: {:?}",
            r.body
        );
    }
}

#[tokio::test]
async fn allocations_are_isolated_per_tenant() {
    let app = isolation_app().await;
    let s_a_id = create_supernet(&app, TENANT_A, "10.0.0.0/8").await;

    let alloc = send(
        &app,
        "POST",
        &format!("/ipam/supernets/{s_a_id}/allocate-specific"),
        TENANT_A,
        Some(r#"{"cidr":"10.1.0.0/16"}"#),
        None,
    )
    .await;
    assert_eq!(alloc.status, StatusCode::CREATED);
    let alloc_id = alloc.body["id"].as_str().unwrap().to_string();

    // B requesting A's allocation by ID gets 404.
    let r = send(
        &app,
        "GET",
        &format!("/ipam/allocations/{alloc_id}"),
        TENANT_B,
        None,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // B trying to allocate inside A's supernet gets 404 (supernet hidden).
    let r = send(
        &app,
        "POST",
        &format!("/ipam/supernets/{s_a_id}/allocate-specific"),
        TENANT_B,
        Some(r#"{"cidr":"10.2.0.0/16"}"#),
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "cross-tenant allocation under A's supernet must 404"
    );
}

#[tokio::test]
async fn audit_log_is_isolated_per_tenant() {
    let app = isolation_app().await;
    let _s_a_id = create_supernet(&app, TENANT_A, "10.0.0.0/8").await;

    // B's audit log is empty.
    let r = send(&app, "GET", "/ipam/audit", TENANT_B, None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let entries = r.body["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 0, "tenant B must see no audit entries");

    // A's audit log has at least one entry.
    let r = send(&app, "GET", "/ipam/audit", TENANT_A, None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let entries = r.body["entries"].as_array().expect("entries array");
    assert!(
        !entries.is_empty(),
        "tenant A must see its own audit entries"
    );
}

#[tokio::test]
async fn idempotency_keys_are_isolated_per_tenant() {
    let app = isolation_app().await;
    let s_a_id = create_supernet(&app, TENANT_A, "10.0.0.0/8").await;
    let s_b_id = create_supernet(&app, TENANT_B, "10.0.0.0/8").await;

    let key = "shared-key-1";

    // A allocates with the key.
    let r_a = send(
        &app,
        "POST",
        &format!("/ipam/supernets/{s_a_id}/allocate-specific"),
        TENANT_A,
        Some(r#"{"cidr":"10.1.0.0/16"}"#),
        Some(key),
    )
    .await;
    assert_eq!(r_a.status, StatusCode::CREATED);
    assert!(!r_a.replay);

    // B uses the same key against its own supernet — must execute fresh.
    let r_b = send(
        &app,
        "POST",
        &format!("/ipam/supernets/{s_b_id}/allocate-specific"),
        TENANT_B,
        Some(r#"{"cidr":"10.2.0.0/16"}"#),
        Some(key),
    )
    .await;
    assert_eq!(r_b.status, StatusCode::CREATED);
    assert!(
        !r_b.replay,
        "tenant B's idempotency key must be in its own namespace, not replay A's"
    );

    // Their allocation IDs must differ — proves no cross-tenant key collision.
    assert_ne!(
        r_a.body["id"].as_str().unwrap(),
        r_b.body["id"].as_str().unwrap()
    );
}
