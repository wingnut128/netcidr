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

async fn bearer_ipam_test_config() -> RouterConfig {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let ops = Arc::new(IpamOps::new(Arc::new(store)));
    RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            auth_mode: AuthMode::Bearer,
            auth_token: Some("test-token".to_string()),
            ..ServerConfig::default()
        },
        ipam_ops: Some(ops),
    }
}

/// Default config with rate limiting disabled (oneshot tests lack ConnectInfo).
fn test_config() -> RouterConfig {
    RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            ..ServerConfig::default()
        },
        ..RouterConfig::default()
    }
}

fn bearer_test_config() -> RouterConfig {
    RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            auth_mode: AuthMode::Bearer,
            auth_token: Some("test-token".to_string()),
            ..ServerConfig::default()
        },
        ..RouterConfig::default()
    }
}

async fn get(uri: &str) -> (StatusCode, String) {
    let app = create_router(test_config());
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn get_with_headers(uri: &str) -> (StatusCode, String, axum::http::HeaderMap) {
    let app = create_router(test_config());
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap(), headers)
}

async fn get_with_config_and_auth(
    uri: &str,
    config: RouterConfig,
    token: Option<&str>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let app = create_router(config);
    let mut req = Request::builder().uri(uri);
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let resp: Response = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap(), headers)
}

async fn post_json(uri: &str, json_body: &str) -> (StatusCode, String) {
    let app = create_router(test_config());
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json_body.to_string()))
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn post_json_with_config(
    uri: &str,
    json_body: &str,
    config: RouterConfig,
) -> (StatusCode, String) {
    let app = create_router(config);
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json_body.to_string()))
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

// ── Health & Version ────────────────────────────────────────────────

#[tokio::test]
async fn test_health() {
    let (status, body) = get("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body, "OK");
}

#[tokio::test]
async fn test_version() {
    let (status, body) = get("/version").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["name"], "netcidr");
    assert!(json["version"].is_string());
}

// ── Authentication ─────────────────────────────────────────────────

#[tokio::test]
async fn test_bearer_auth_leaves_public_paths_open() {
    let (status, body, _) = get_with_config_and_auth("/health", bearer_test_config(), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OK");

    let (status, body, _) = get_with_config_and_auth("/version", bearer_test_config(), None).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["name"], "netcidr");
}

#[tokio::test]
async fn test_bearer_auth_blocks_ipam_without_token() {
    let (status, body, headers) =
        get_with_config_and_auth("/ipam/supernets", bearer_ipam_test_config().await, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "Unauthorized");
    assert_eq!(headers.get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
}

#[tokio::test]
async fn test_bearer_auth_blocks_ipam_with_invalid_token() {
    let (status, body, _) = get_with_config_and_auth(
        "/ipam/supernets",
        bearer_ipam_test_config().await,
        Some("wrong-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "Unauthorized");
}

#[tokio::test]
async fn test_bearer_auth_allows_ipam_with_valid_token() {
    let (status, _body, _) = get_with_config_and_auth(
        "/ipam/supernets",
        bearer_ipam_test_config().await,
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_non_ipam_routes_are_public_even_when_auth_configured() {
    // Auth is scoped to /ipam/* — calculator/health/version remain public.
    let (status, _body, _) =
        get_with_config_and_auth("/features", bearer_ipam_test_config().await, None).await;
    assert_eq!(status, StatusCode::OK);
}

// ── IPv4 ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_v4_valid() {
    let (status, body) = get("/v4?cidr=192.168.1.0/24").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["network_address"], "192.168.1.0");
    assert_eq!(json["broadcast_address"], "192.168.1.255");
    assert_eq!(json["prefix_length"], 24);
}

#[tokio::test]
async fn test_v4_invalid() {
    let (status, body) = get("/v4?cidr=invalid").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].is_string());
}

// ── IPv6 ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_v6_valid() {
    let (status, body) = get("/v6?cidr=2001:db8::/32").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["network_address"], "2001:db8::");
    assert_eq!(json["prefix_length"], 32);
}

#[tokio::test]
async fn test_v6_invalid() {
    let (status, body) = get("/v6?cidr=invalid").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].is_string());
}

// ── IPv4 Split ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_v4_split() {
    let (status, body) = get("/v4/split?cidr=192.168.0.0/24&prefix=27&count=5").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["subnets"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_v4_split_max() {
    let (status, body) = get("/v4/split?cidr=192.168.0.0/24&prefix=26&max=true").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // /24 split into /26 = 2^(26-24) = 4 subnets
    assert_eq!(json["subnets"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn test_v4_split_missing_params() {
    let (status, body) = get("/v4/split?cidr=192.168.0.0/24&prefix=27").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("count"));
}

// ── IPv6 Split ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_v6_split() {
    let (status, body) = get("/v6/split?cidr=2001:db8::/32&prefix=48&count=3").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["subnets"].as_array().unwrap().len(), 3);
}

// ── IPv4 Contains ───────────────────────────────────────────────────

#[tokio::test]
async fn test_v4_contains_true() {
    let (status, body) = get("/v4/contains?cidr=192.168.1.0/24&address=192.168.1.100").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["contained"], true);
}

#[tokio::test]
async fn test_v4_contains_false() {
    let (status, body) = get("/v4/contains?cidr=192.168.1.0/24&address=10.0.0.1").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["contained"], false);
}

#[tokio::test]
async fn test_v4_contains_invalid() {
    let (status, body) = get("/v4/contains?cidr=192.168.1.0/24&address=bad").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].is_string());
}

// ── IPv6 Contains ───────────────────────────────────────────────────

#[tokio::test]
async fn test_v6_contains() {
    let (status, body) = get("/v6/contains?cidr=2001:db8::/32&address=2001:db8::1").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["contained"], true);
}

// ── Pretty Output ───────────────────────────────────────────────────

// ── Split Count Only ────────────────────────────────────────────────

#[tokio::test]
async fn test_v4_split_count_only() {
    let (status, body) = get("/v4/split?cidr=192.168.0.0/22&prefix=27&count_only=true").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["available_subnets"], "32");
    assert_eq!(json["new_prefix"], 27);
}

#[tokio::test]
async fn test_v4_split_count_only_hyphenated() {
    let (status, body) = get("/v4/split?cidr=192.168.0.0/22&prefix=27&count-only=true").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["available_subnets"], "32");
    assert_eq!(json["new_prefix"], 27);
}

#[tokio::test]
async fn test_v6_split_count_only() {
    let (status, body) = get("/v6/split?cidr=2001:db8::/64&prefix=96&count_only=true").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["available_subnets"], "4294967296");
    assert_eq!(json["new_prefix"], 96);
}

#[tokio::test]
async fn test_v6_split_limit_exceeded() {
    let (status, body) = get("/v6/split?cidr=2001:db8::/32&prefix=64&max=true").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("limit"));
}

// ── Pretty Output ───────────────────────────────────────────────────

#[tokio::test]
async fn test_pretty_output() {
    let (status, body) = get("/v4?cidr=192.168.1.0/24&pretty=true").await;
    assert_eq!(status, 200);
    // Pretty-printed JSON contains newlines and indentation
    assert!(body.contains('\n'));
    assert!(body.contains("  "));
}

// ── Batch ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_batch_v4() {
    let (status, body) = post_json("/batch", r#"{"cidrs":["192.168.1.0/24","10.0.0.0/8"]}"#).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["count"], 2);
    assert_eq!(json["results"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_batch_mixed() {
    let (status, body) =
        post_json("/batch", r#"{"cidrs":["192.168.1.0/24","2001:db8::/32"]}"#).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["count"], 2);
    assert_eq!(json["results"][0]["subnet"]["version"], "v4");
    assert_eq!(json["results"][1]["subnet"]["version"], "v6");
}

#[tokio::test]
async fn test_batch_with_invalid() {
    let (status, body) = post_json(
        "/batch",
        r#"{"cidrs":["192.168.1.0/24","invalid","10.0.0.0/8"]}"#,
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["count"], 3);
    assert!(json["results"][0]["subnet"].is_object());
    assert!(json["results"][1]["error"].is_string());
    assert!(json["results"][2]["subnet"].is_object());
}

#[tokio::test]
async fn test_batch_empty() {
    let (status, body) = post_json("/batch", r#"{"cidrs":[]}"#).await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].is_string());
}

#[tokio::test]
async fn test_batch_pretty() {
    let (status, body) = post_json("/batch", r#"{"cidrs":["192.168.1.0/24"],"pretty":true}"#).await;
    assert_eq!(status, 200);
    // Pretty-printed JSON contains newlines and indentation
    assert!(body.contains('\n'));
    assert!(body.contains("  "));
}

// ── CSV Format ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_v4_csv_format() {
    let (status, body) = get("/v4?cidr=192.168.1.0/24&format=csv").await;
    assert_eq!(status, 200);
    let lines: Vec<&str> = body.lines().collect();
    assert!(lines[0].contains("network_address"));
    assert!(lines[1].contains("192.168.1.0"));
}

#[tokio::test]
async fn test_v6_csv_format() {
    let (status, body) = get("/v6?cidr=2001:db8::/32&format=csv").await;
    assert_eq!(status, 200);
    let lines: Vec<&str> = body.lines().collect();
    assert!(lines[0].contains("network_address"));
    assert!(lines[1].contains("2001:db8::"));
}

#[tokio::test]
async fn test_v4_split_csv_format() {
    let (status, body) = get("/v4/split?cidr=192.168.0.0/24&prefix=26&max=true&format=csv").await;
    assert_eq!(status, 200);
    let data_lines: Vec<&str> = body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    // header + 4 subnets
    assert_eq!(data_lines.len(), 5);
}

// ── YAML Format ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_v4_yaml_format() {
    let (status, body) = get("/v4?cidr=192.168.1.0/24&format=yaml").await;
    assert_eq!(status, 200);
    assert!(body.contains("network_address:"));
    assert!(body.contains("192.168.1.0"));
}

#[tokio::test]
async fn test_v6_yaml_format() {
    let (status, body) = get("/v6?cidr=2001:db8::/32&format=yaml").await;
    assert_eq!(status, 200);
    assert!(body.contains("network_address:"));
    assert!(body.contains("prefix_length:"));
}

// ── Error responses stay JSON regardless of format ──────────────────

#[tokio::test]
async fn test_error_stays_json_with_csv_format() {
    let (status, body) = get("/v4?cidr=invalid&format=csv").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].is_string());
}

#[tokio::test]
async fn test_error_stays_json_with_yaml_format() {
    let (status, body) = get("/v4?cidr=invalid&format=yaml").await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].is_string());
}

// ── Security Tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_security_headers_present() {
    let (status, _body, headers) = get_with_headers("/health").await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn test_batch_size_exceeded() {
    let config = RouterConfig {
        server: ServerConfig {
            max_batch_size: 2,
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    // 3 CIDRs with max_batch_size=2 should fail
    let (status, body) = post_json_with_config(
        "/batch",
        r#"{"cidrs":["192.168.1.0/24","10.0.0.0/8","172.16.0.0/12"]}"#,
        config,
    )
    .await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("exceeds maximum"));
}

#[tokio::test]
async fn test_swagger_disabled_by_default() {
    let app = create_router(test_config());
    let req = Request::builder()
        .uri("/swagger-ui")
        .body(Body::empty())
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    // Swagger should not be available (404) when enable_swagger is false
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_input_too_long_rejected() {
    let long_cidr = "a".repeat(300);
    let uri = format!("/v4?cidr={}", long_cidr);
    let (status, body) = get(&uri).await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("exceeds maximum length")
    );
}

#[tokio::test]
async fn test_body_size_limit() {
    let config = RouterConfig {
        server: ServerConfig {
            max_body_size: 64,
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    let app = create_router(config);
    // Send a body larger than 64 bytes
    let large_body = format!(
        r#"{{"cidrs":[{}]}}"#,
        (0..20)
            .map(|i| format!(r#""10.0.{}.0/24""#, i))
            .collect::<Vec<_>>()
            .join(",")
    );
    let req = Request::builder()
        .method("POST")
        .uri("/batch")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(large_body))
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ── Version Endpoint Matches Cargo.toml ─────────────────────────────

#[tokio::test]
async fn test_version_matches_cargo_toml() {
    let (status, body) = get("/version").await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["name"], "netcidr");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

// ── CORS Headers ────────────────────────────────────────────────────

#[tokio::test]
async fn test_cors_preflight_options_request() {
    let app = create_router(test_config());
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/batch")
        .header("origin", "https://example.com")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    // CORS is configured with an empty origin allowlist, so the preflight
    // should not include an access-control-allow-origin header for arbitrary origins.
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "No origins should be allowed when the allowlist is empty"
    );
}

#[tokio::test]
async fn test_cors_get_request_no_origin_header() {
    let (_status, _body, headers) = get_with_headers("/health").await;
    // Without an Origin header in the request, no CORS headers should appear
    assert!(headers.get("access-control-allow-origin").is_none());
}

// ── Invalid Content-Type ────────────────────────────────────────────

#[tokio::test]
async fn test_post_with_wrong_content_type() {
    let app = create_router(test_config());
    let req = Request::builder()
        .method("POST")
        .uri("/batch")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"cidrs":["192.168.1.0/24"]}"#))
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    // Axum rejects non-JSON content type for Json<T> extractors with 415
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_post_with_no_content_type() {
    let app = create_router(test_config());
    let req = Request::builder()
        .method("POST")
        .uri("/batch")
        .body(Body::from(r#"{"cidrs":["192.168.1.0/24"]}"#))
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    // Missing Content-Type header should also be rejected
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ── Malformed JSON ──────────────────────────────────────────────────

#[tokio::test]
async fn test_malformed_json_batch() {
    let (status, body) = post_json("/batch", r#"{"cidrs": [invalid json"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Axum returns a JSON parse error description
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_wrong_json_shape_batch() {
    // Valid JSON but wrong shape (missing required "cidrs" field)
    let (status, body) = post_json("/batch", r#"{"wrong_field": true}"#).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_empty_body_batch() {
    let (status, _body) = post_json("/batch", "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── Timeout Configuration ───────────────────────────────────────────

#[tokio::test]
async fn test_timeout_config_applied() {
    // Verify the server config timeout value is respected in the router.
    // We can't easily trigger a real timeout in a unit test, but we verify
    // that a custom timeout config doesn't break router creation and normal
    // requests still succeed.
    let config = RouterConfig {
        server: ServerConfig {
            timeout_seconds: 1,
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let app = create_router(config);
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Body Size Limit on Different Endpoints ──────────────────────────

#[tokio::test]
async fn test_body_size_limit_default_allows_normal_batch() {
    // Default max_body_size is 1 MB; a normal batch request should be well within that
    let cidrs: Vec<String> = (0..100)
        .map(|i| format!(r#""10.0.{}.0/24""#, i % 256))
        .collect();
    let body = format!(r#"{{"cidrs":[{}]}}"#, cidrs.join(","));
    let (status, _body) = post_json("/batch", &body).await;
    assert_eq!(status, StatusCode::OK);
}

// ── 404 for Unknown Routes ──────────────────────────────────────────

#[tokio::test]
async fn test_unknown_route_returns_404() {
    let (status, _body) = get("/nonexistent").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_post_to_get_only_endpoint() {
    let app = create_router(test_config());
    let req = Request::builder()
        .method("POST")
        .uri("/v4?cidr=192.168.1.0/24")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp: Response = app.oneshot(req).await.unwrap();
    // POST to a GET-only route should return 405 Method Not Allowed
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── Rate Limiting ───────────────────────────────────────────────────

#[tokio::test]
async fn test_rate_limit_returns_429() {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // Tight limit: burst of 1, replenish every 10 seconds
    let config = RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 1,
            rate_limit_burst: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let app = create_router(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let client = reqwest::Client::new();
    let url = format!("http://{}/health", addr);

    // First request should succeed
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Burst is 1, so the second request should be rate limited
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn test_rate_limit_disabled_when_zero() {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    let config = RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let app = create_router(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let client = reqwest::Client::new();
    let url = format!("http://{}/health", addr);

    // All requests should succeed with rate limiting disabled
    for _ in 0..10 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }
}

#[tokio::test]
async fn test_rate_limit_allows_burst() {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // Allow burst of 3, slow replenish
    let config = RouterConfig {
        server: ServerConfig {
            rate_limit_per_second: 1,
            rate_limit_burst: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let app = create_router(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let client = reqwest::Client::new();
    let url = format!("http://{}/health", addr);

    // First 3 requests within the burst should succeed
    for _ in 0..3 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    // 4th request should be rate limited
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 429);
}
