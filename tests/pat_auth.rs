//! HTTP-level tests for Personal Access Token authentication.
//!
//! Boots an in-memory netcidr API with `auth_mode = bearer` (so the
//! existing static-bearer branch is also exercised) plus a PAT pepper
//! and an IPAM store. PATs are minted directly via the store layer —
//! Phase 4 will add the `/me/tokens` endpoints; the middleware tests
//! only need the verifier to work end-to-end.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::ipam::models::CreatePersonalAccessToken;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use netcidr::pat::{self, PatPepper};
use tower::ServiceExt;

const OWNER_EMAIL: &str = "owner@example.com";
const OWNER_SUB: &str = "117290938723847238472";

struct Harness {
    router: axum::Router,
    store: Arc<dyn IpamStore>,
    pepper: Arc<PatPepper>,
}

async fn build_harness(allowed_emails: Vec<String>) -> Harness {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let ops = Arc::new(IpamOps::new(Arc::clone(&store)));
    let pepper = Arc::new(PatPepper::from_bytes(&[0xA5u8; 32]).unwrap());

    // Bearer-mode keeps the existing static-bearer branch reachable for the
    // OIDC-vs-PAT dispatch sanity test below; PAT verification works under
    // any non-None auth mode as long as the pepper is set.
    let mut server = ServerConfig {
        rate_limit_per_second: 0,
        auth_mode: AuthMode::Bearer,
        auth_token: Some("static-bearer-token".to_string()),
        ipam_enabled: true,
        ..Default::default()
    };
    server.oidc_allowed_emails = allowed_emails;

    let router = create_router(RouterConfig {
        server,
        ipam_ops: Some(ops),
        pat_pepper: Some(Arc::clone(&pepper)),
    });

    Harness {
        router,
        store,
        pepper,
    }
}

/// Mint a token by calling into `pat::mint` and persisting via the store
/// directly. Returns `(plaintext_token, pat_id)`.
async fn mint_pat(
    store: &Arc<dyn IpamStore>,
    pepper: &PatPepper,
    expires_at: &str,
    owner_email: &str,
) -> (String, String) {
    let minted = pat::mint(pepper);
    let row = store
        .pat_create(&CreatePersonalAccessToken {
            tenant_id: owner_email.to_string(),
            owner_sub: OWNER_SUB.to_string(),
            owner_email: owner_email.to_string(),
            name: "test token".to_string(),
            prefix: minted.prefix.clone(),
            token_hash: minted.hash.to_vec(),
            role: netcidr::auth::Role::Admin,
            expires_at: expires_at.to_string(),
        })
        .await
        .unwrap();
    (minted.plaintext, row.id)
}

async fn req(router: &axum::Router, uri: &str, bearer: &str) -> (StatusCode, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn future_rfc3339() -> String {
    (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339()
}

fn past_rfc3339() -> String {
    (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()
}

#[tokio::test]
async fn valid_pat_authenticates_and_reaches_handler() {
    let h = build_harness(Vec::new()).await;
    let (token, _id) = mint_pat(&h.store, &h.pepper, &future_rfc3339(), OWNER_EMAIL).await;

    // Listing the (initially empty) CIDR blocks for OWNER_EMAIL is enough
    // to prove the request reached the handler with the right tenant.
    let (status, body) = req(&h.router, "/ipam/cidr-blocks", &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // Tenant-scoped response: an empty CIDR blocks list for a fresh tenant.
    assert!(
        body.contains("\"cidr_blocks\""),
        "expected CIDR blocks envelope, got {body}"
    );
}

#[tokio::test]
async fn expired_pat_is_unauthorized() {
    let h = build_harness(Vec::new()).await;
    let (token, _id) = mint_pat(&h.store, &h.pepper, &past_rfc3339(), OWNER_EMAIL).await;
    let (status, _) = req(&h.router, "/ipam/cidr-blocks", &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_pat_is_unauthorized() {
    let h = build_harness(Vec::new()).await;
    let (token, id) = mint_pat(&h.store, &h.pepper, &future_rfc3339(), OWNER_EMAIL).await;

    let now = chrono::Utc::now().to_rfc3339();
    h.store
        .pat_revoke(OWNER_EMAIL, OWNER_SUB, &id, &now)
        .await
        .unwrap();

    let (status, _) = req(&h.router, "/ipam/cidr-blocks", &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn shape_invalid_pat_is_unauthorized() {
    // `Bearer ncdr_pat_short` is the canonical "right prefix, wrong shape"
    // case. The verifier short-circuits via `pat::hash_for_lookup` before
    // any DB query happens. We can't easily count DB calls here without
    // wrapping the store in a counting decorator; assert at minimum that
    // the request 401s, and rely on `pat::hash_for_lookup`'s unit tests
    // to prove the no-DB-query property.
    let h = build_harness(Vec::new()).await;
    let (status, _) = req(&h.router, "/ipam/cidr-blocks", "ncdr_pat_short").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn static_bearer_token_still_works_alongside_pats() {
    let h = build_harness(Vec::new()).await;
    let (status, _) = req(&h.router, "/ipam/cidr-blocks", "static-bearer-token").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pat_owner_outside_allowlist_is_unauthorized() {
    // Allowlist explicitly excludes the PAT owner — middleware must reject
    // even though the hash matches and the row is unrevoked / unexpired.
    let h = build_harness(vec!["someone-else@example.com".to_string()]).await;
    let (token, _id) = mint_pat(&h.store, &h.pepper, &future_rfc3339(), OWNER_EMAIL).await;
    let (status, _) = req(&h.router, "/ipam/cidr-blocks", &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_authorization_header_is_unauthorized() {
    let h = build_harness(Vec::new()).await;
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ipam/cidr-blocks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
