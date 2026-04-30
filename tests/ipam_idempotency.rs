//! Integration tests for the `Idempotency-Key` header on IPAM allocation
//! endpoints.

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

async fn ipam_app() -> axum::Router {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let ops = Arc::new(IpamOps::new(Arc::new(store)));
    create_router(RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ipam_ops: Some(ops),
    })
}

struct ReqResult {
    status: StatusCode,
    body: serde_json::Value,
    replay: bool,
}

async fn post_with_key(app: &axum::Router, uri: &str, body: &str, key: Option<&str>) -> ReqResult {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(k) = key {
        builder = builder.header("Idempotency-Key", k);
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let replay = resp
        .headers()
        .get("Idempotent-Replay")
        .map(|v| v == "true")
        .unwrap_or(false);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let body = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
    };
    ReqResult {
        status,
        body,
        replay,
    }
}

async fn create_supernet(app: &axum::Router, cidr: &str) -> String {
    let r = post_with_key(
        app,
        "/ipam/supernets",
        &format!(r#"{{"cidr":"{cidr}"}}"#),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    r.body["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn allocate_specific_replays_on_same_key_and_body() {
    let app = ipam_app().await;
    let sn = create_supernet(&app, "10.0.0.0/16").await;

    let body = r#"{"cidr":"10.0.1.0/24","name":"web"}"#;
    let first = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate-specific"),
        body,
        Some("retry-key-1"),
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert!(!first.replay);
    let first_id = first.body["id"].as_str().unwrap().to_string();

    // Same key + same body → cached replay; no new allocation row.
    let second = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate-specific"),
        body,
        Some("retry-key-1"),
    )
    .await;
    assert_eq!(second.status, StatusCode::CREATED);
    assert!(second.replay, "expected cached replay");
    assert_eq!(second.body["id"].as_str().unwrap(), first_id);
}

#[tokio::test]
async fn allocate_specific_conflicts_on_same_key_different_body() {
    let app = ipam_app().await;
    let sn = create_supernet(&app, "10.0.0.0/16").await;

    let first = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate-specific"),
        r#"{"cidr":"10.0.1.0/24"}"#,
        Some("dup-key"),
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);

    let second = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate-specific"),
        r#"{"cidr":"10.0.2.0/24"}"#,
        Some("dup-key"),
    )
    .await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert!(
        second.body["error"]
            .as_str()
            .unwrap()
            .contains("Idempotency-Key")
    );
}

#[tokio::test]
async fn auto_allocate_replays_on_same_key() {
    let app = ipam_app().await;
    let sn = create_supernet(&app, "10.10.0.0/16").await;

    let body = r#"{"prefix_length":24,"count":1}"#;
    let first = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate"),
        body,
        Some("auto-1"),
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let first_count = first.body["count"].as_u64().unwrap();
    assert_eq!(first_count, 1);

    let second = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate"),
        body,
        Some("auto-1"),
    )
    .await;
    assert_eq!(second.status, StatusCode::CREATED);
    assert!(second.replay);
    // Replayed body must equal the first one byte-for-byte.
    assert_eq!(second.body, first.body);

    // Verify the supernet still has only one allocation.
    let list_req = Request::builder()
        .method("GET")
        .uri(format!("/ipam/supernets/{sn}/allocations"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(list_req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["count"], 1);
}

#[tokio::test]
async fn batch_allocate_replays_on_same_key() {
    let app = ipam_app().await;
    let sn = create_supernet(&app, "10.20.0.0/16").await;

    let body = format!(r#"[{{"supernet_id":"{sn}","prefix_length":24,"count":1,"name":"a"}}]"#,);
    let first = post_with_key(&app, "/ipam/batch/allocate", &body, Some("batch-1")).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["total_allocated"], 1);

    let second = post_with_key(&app, "/ipam/batch/allocate", &body, Some("batch-1")).await;
    assert_eq!(second.status, StatusCode::OK);
    assert!(second.replay);
    assert_eq!(second.body, first.body);
}

#[tokio::test]
async fn no_key_means_no_caching() {
    let app = ipam_app().await;
    let sn = create_supernet(&app, "10.30.0.0/16").await;

    let body = r#"{"cidr":"10.30.1.0/24"}"#;
    let first = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate-specific"),
        body,
        None,
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert!(!first.replay);

    // Second identical request without a key → conflict from the regular
    // overlap detection (NOT a cached replay).
    let second = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn}/allocate-specific"),
        body,
        None,
    )
    .await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert!(!second.replay);
}

#[tokio::test]
async fn key_scope_is_per_endpoint_and_supernet() {
    let app = ipam_app().await;
    let sn1 = create_supernet(&app, "10.40.0.0/16").await;
    let sn2 = create_supernet(&app, "10.41.0.0/16").await;

    // Same key, different supernet path → fresh execution, not a conflict.
    let r1 = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn1}/allocate-specific"),
        r#"{"cidr":"10.40.1.0/24"}"#,
        Some("shared-key"),
    )
    .await;
    assert_eq!(r1.status, StatusCode::CREATED);

    let r2 = post_with_key(
        &app,
        &format!("/ipam/supernets/{sn2}/allocate-specific"),
        r#"{"cidr":"10.41.1.0/24"}"#,
        Some("shared-key"),
    )
    .await;
    assert_eq!(r2.status, StatusCode::CREATED);
    assert!(!r2.replay);
}
