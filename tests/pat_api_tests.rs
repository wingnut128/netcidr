//! Phase 4 — `/me/tokens` REST endpoint tests.
//!
//! Stands up an in-memory netcidr API in OIDC mode, with a stubbed JWKS
//! (via `auth::test_support`) so integration tests can mint signed ID
//! tokens locally. Exercises the OIDC-only mint guard, list/revoke
//! lifecycle, cross-tenant isolation, validation, and the
//! "plaintext-once" contract.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use netcidr::api::{RouterConfig, create_router};
use netcidr::auth::test_support;
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::ipam::models::CreatePersonalAccessToken;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use netcidr::pat::{self, PatPepper};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use tower::ServiceExt;

const TEST_KID: &str = "pat-api-test-key";
const AUDIENCE: &str = "test-audience";
const ISSUER: &str = "https://accounts.google.com";

const USER_A_EMAIL: &str = "alice@example.com";
const USER_A_SUB: &str = "1110000000000000001";
const USER_B_EMAIL: &str = "bob@example.com";
const USER_B_SUB: &str = "1110000000000000002";

#[derive(Serialize)]
struct TestClaims {
    sub: String,
    aud: String,
    email: String,
    email_verified: bool,
    iss: String,
    exp: usize,
    iat: usize,
}

/// Process-wide RSA keypair shared across all tests in this binary.
/// Generating a fresh 2048-bit key per test is slow; one keypair plus
/// one JWKS install is enough because the cache is keyed by `kid`.
fn keypair() -> &'static (RsaPrivateKey, RsaPublicKey) {
    static KEYS: OnceLock<(RsaPrivateKey, RsaPublicKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let public = RsaPublicKey::from(&private);
        (private, public)
    })
}

async fn install_test_jwks() {
    let (_, public) = keypair();
    test_support::install_jwks(
        TEST_KID,
        &public.n().to_bytes_be(),
        &public.e().to_bytes_be(),
    )
    .await;
}

fn now_seconds() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

fn sign_id_token(sub: &str, email: &str) -> String {
    let (private, _) = keypair();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: sub.to_string(),
        aud: AUDIENCE.to_string(),
        email: email.to_string(),
        email_verified: true,
        iss: ISSUER.to_string(),
        exp: now_seconds() + 3600,
        iat: now_seconds(),
    };
    let pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode private key");
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("decoding key"),
    )
    .expect("sign jwt")
}

struct Harness {
    router: axum::Router,
    store: Arc<dyn IpamStore>,
    pepper: Arc<PatPepper>,
    /// Held so JWKS state stays installed for the lifetime of the test.
    _jwks_guard: tokio::sync::OwnedMutexGuard<()>,
}

async fn build_harness(allowed_emails: Vec<String>) -> Harness {
    // JWKS state is process-global; take an owned guard so JWKS-touching
    // tests run sequentially and the install survives for this test.
    let owned = jwks_lock_arc().lock_owned().await;
    install_test_jwks().await;

    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let ops = Arc::new(IpamOps::new(Arc::clone(&store)));
    let pepper = Arc::new(PatPepper::from_bytes(&[0xC3u8; 32]).unwrap());

    let mut server = ServerConfig {
        rate_limit_per_second: 0,
        auth_mode: AuthMode::Oidc,
        oidc_audience: Some(AUDIENCE.to_string()),
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
        _jwks_guard: owned,
    }
}

/// Wrap the static lock in an Arc once so we can take owned guards
/// (tokio's `lock_owned` requires `Arc<Mutex<_>>`).
fn jwks_lock_arc() -> Arc<Mutex<()>> {
    static ARC: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
    Arc::clone(ARC.get_or_init(|| Arc::new(Mutex::new(()))))
}

async fn req(
    router: &axum::Router,
    method: &str,
    uri: &str,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let body = if let Some(b) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&b).unwrap())
    } else {
        Body::empty()
    };
    let resp = router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn mint_pat_in_store(
    store: &Arc<dyn IpamStore>,
    pepper: &PatPepper,
    owner_email: &str,
    owner_sub: &str,
) -> (String, String) {
    let minted = pat::mint(pepper);
    let expires = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let row = store
        .pat_create(&CreatePersonalAccessToken {
            tenant_id: owner_email.to_string(),
            owner_sub: owner_sub.to_string(),
            owner_email: owner_email.to_string(),
            name: "seed".to_string(),
            prefix: minted.prefix.clone(),
            token_hash: minted.hash.to_vec(),
            expires_at: expires,
        })
        .await
        .unwrap();
    (minted.plaintext, row.id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_mint_list_revoke_relist_lifecycle() {
    let h = build_harness(vec![USER_A_EMAIL.to_string()]).await;
    let token = sign_id_token(USER_A_SUB, USER_A_EMAIL);

    // 1. Mint a PAT via OIDC.
    let (status, body) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &token,
        Some(json!({ "name": "laptop", "expires_in_days": 30 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let plaintext = parsed["token"].as_str().unwrap().to_string();
    let pat_id = parsed["id"].as_str().unwrap().to_string();
    assert!(
        plaintext.starts_with("ncdr_pat_"),
        "minted token should start with ncdr_pat_: {plaintext}"
    );
    assert_eq!(parsed["name"].as_str(), Some("laptop"));
    assert_eq!(parsed["prefix"].as_str().unwrap().len(), 12);

    // 2. List shows exactly one row, no plaintext.
    let (status, list_body) = req(&h.router, "GET", "/me/tokens", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_str(&list_body).unwrap();
    assert_eq!(list["count"], 1);
    assert_eq!(list["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(list["tokens"][0]["id"], pat_id);
    assert!(list["tokens"][0].get("token").is_none());
    assert!(list["tokens"][0].get("token_hash").is_none());
    // Plaintext-once contract: the GET body MUST NOT contain the
    // plaintext token returned by the create response.
    assert!(
        !list_body.contains(&plaintext),
        "GET /me/tokens leaked the plaintext minted token"
    );

    // 3. Revoke succeeds.
    let (status, _) = req(
        &h.router,
        "DELETE",
        &format!("/me/tokens/{pat_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 4. List still shows the row but with revoked_at set (soft delete).
    let (status, list_body) = req(&h.router, "GET", "/me/tokens", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_str(&list_body).unwrap();
    assert_eq!(list["count"], 1, "soft-delete should keep the row visible");
    assert!(
        list["tokens"][0]["revoked_at"].is_string(),
        "revoked_at should be set after DELETE: {list_body}"
    );
}

#[tokio::test]
async fn pat_authed_caller_cannot_mint_another_pat() {
    let h = build_harness(vec![USER_A_EMAIL.to_string()]).await;
    // Seed a PAT directly in the store, then use it as the caller.
    let (pat_plaintext, _id) =
        mint_pat_in_store(&h.store, &h.pepper, USER_A_EMAIL, USER_A_SUB).await;

    let (status, body) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &pat_plaintext,
        Some(json!({ "name": "child", "expires_in_days": 30 })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "PAT-authed caller must not mint PATs; body: {body}"
    );
}

#[tokio::test]
async fn static_bearer_caller_cannot_mint_pat() {
    // Bearer-mode harness: the AuthConfig has a static bearer token,
    // and PAT minting must reject it because there's no OIDC identity.
    let lock = jwks_lock_arc();
    let _guard = lock.lock_owned().await;
    install_test_jwks().await;

    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let ops = Arc::new(IpamOps::new(Arc::clone(&store)));
    let pepper = Arc::new(PatPepper::from_bytes(&[0x77u8; 32]).unwrap());

    let server = ServerConfig {
        rate_limit_per_second: 0,
        auth_mode: AuthMode::Bearer,
        auth_token: Some("static-bearer".to_string()),
        ipam_enabled: true,
        ..Default::default()
    };
    let router = create_router(RouterConfig {
        server,
        ipam_ops: Some(ops),
        pat_pepper: Some(pepper),
    });

    let (status, body) = req(
        &router,
        "POST",
        "/me/tokens",
        "static-bearer",
        Some(json!({ "name": "no", "expires_in_days": 30 })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "static bearer must not mint PATs; body: {body}"
    );
}

#[tokio::test]
async fn cross_tenant_revoke_returns_404_and_target_token_survives() {
    let h = build_harness(vec![USER_A_EMAIL.to_string(), USER_B_EMAIL.to_string()]).await;

    // User A mints via the API.
    let token_a = sign_id_token(USER_A_SUB, USER_A_EMAIL);
    let (status, body) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &token_a,
        Some(json!({ "name": "a-laptop" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let a_id = parsed["id"].as_str().unwrap().to_string();

    // User B authenticates and tries to revoke A's token.
    let token_b = sign_id_token(USER_B_SUB, USER_B_EMAIL);
    let (status, _) = req(
        &h.router,
        "DELETE",
        &format!("/me/tokens/{a_id}"),
        &token_b,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant revoke must be 404, never 403"
    );

    // A's token survives — listing as A still shows it active.
    let (status, list_body) = req(&h.router, "GET", "/me/tokens", &token_a, None).await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_str(&list_body).unwrap();
    assert_eq!(list["count"], 1);
    assert!(
        list["tokens"][0]["revoked_at"].is_null(),
        "A's token should still be active: {list_body}"
    );
}

#[tokio::test]
async fn invalid_expires_in_days_rejected() {
    let h = build_harness(vec![USER_A_EMAIL.to_string()]).await;
    let token = sign_id_token(USER_A_SUB, USER_A_EMAIL);

    for bad in [0u32, 366, 400, 10_000] {
        let (status, body) = req(
            &h.router,
            "POST",
            "/me/tokens",
            &token,
            Some(json!({ "name": "x", "expires_in_days": bad })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expires_in_days={bad} should 400; body: {body}"
        );
    }
}

#[tokio::test]
async fn invalid_name_rejected() {
    let h = build_harness(vec![USER_A_EMAIL.to_string()]).await;
    let token = sign_id_token(USER_A_SUB, USER_A_EMAIL);

    // Empty name.
    let (status, _) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &token,
        Some(json!({ "name": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Whitespace-only name (trim makes it empty).
    let (status, _) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &token,
        Some(json!({ "name": "   " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Control character.
    let (status, _) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &token,
        Some(json!({ "name": "bad\u{0001}name" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_isolation_between_owners() {
    let h = build_harness(vec![USER_A_EMAIL.to_string(), USER_B_EMAIL.to_string()]).await;

    let token_a = sign_id_token(USER_A_SUB, USER_A_EMAIL);
    let token_b = sign_id_token(USER_B_SUB, USER_B_EMAIL);

    // A mints two.
    for n in ["a-1", "a-2"] {
        let (status, _) = req(
            &h.router,
            "POST",
            "/me/tokens",
            &token_a,
            Some(json!({ "name": n })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // B mints one.
    let (status, _) = req(
        &h.router,
        "POST",
        "/me/tokens",
        &token_b,
        Some(json!({ "name": "b-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // A sees 2, B sees 1.
    let (_, body_a) = req(&h.router, "GET", "/me/tokens", &token_a, None).await;
    let list_a: serde_json::Value = serde_json::from_str(&body_a).unwrap();
    assert_eq!(list_a["count"], 2, "A should see 2 tokens: {body_a}");

    let (_, body_b) = req(&h.router, "GET", "/me/tokens", &token_b, None).await;
    let list_b: serde_json::Value = serde_json::from_str(&body_b).unwrap();
    assert_eq!(list_b["count"], 1, "B should see 1 token: {body_b}");
}
