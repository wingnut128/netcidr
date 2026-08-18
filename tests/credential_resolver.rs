//! Precedence and refresh behavior of the shared credential resolver.
//!
//! None of these tests read or mutate `NETCIDR_API_TOKEN` (or any other
//! process env var). `resolve_from` takes the env-token value as an
//! explicit parameter instead of reading the environment itself, so these
//! tests are deterministic regardless of what the calling shell exports —
//! see `env_token_wins_over_the_cache` / `no_env_token_falls_through_to_the_cache`.

use netcidr::credentials::{Account, CredentialStore, is_expired, resolve_from};
use netcidr::error::NetcidrError;
use tempfile::TempDir;

fn account(expires_at: &str) -> Account {
    Account {
        email: "user@example.com".to_string(),
        refresh_token: "1//0g-refresh".to_string(),
        id_token: "eyJ-cached".to_string(),
        expires_at: expires_at.to_string(),
        client_id: "desktop-client".to_string(),
    }
}

fn far_future() -> String {
    (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn already_past() -> String {
    (chrono::Utc::now() - chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A `client_secret` provider that panics if invoked — used to prove a
/// given call path never reaches the refresh branch (and therefore never
/// needs the secret), rather than merely happening not to use its value.
async fn unreachable_secret() -> netcidr::error::Result<String> {
    panic!("client_secret provider must not be called on this path")
}

async fn stub_secret() -> netcidr::error::Result<String> {
    Ok("GOCSPX-test".to_string())
}

#[test]
fn expiry_respects_the_skew_window() {
    assert!(!is_expired(&far_future(), 60));
    assert!(is_expired(&already_past(), 60));
    // Inside the skew window counts as expired: refresh before it bites.
    let in_thirty_seconds = (chrono::Utc::now() + chrono::Duration::seconds(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(is_expired(&in_thirty_seconds, 60));
    // An unparseable timestamp is treated as expired, never as valid.
    assert!(is_expired("not-a-timestamp", 60));
}

#[tokio::test]
async fn explicit_token_wins_over_the_cache() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let mut store = CredentialStore::default();
    store.insert("https://server", account(&far_future()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        Some("explicit-pat"),
        None,
        unreachable_secret,
    )
    .await
    .unwrap();

    assert_eq!(token, "explicit-pat");
}

#[tokio::test]
async fn env_token_wins_over_the_cache() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let mut store = CredentialStore::default();
    store.insert("https://server", account(&far_future()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        Some("env-token"),
        unreachable_secret,
    )
    .await
    .unwrap();

    assert_eq!(token, "env-token");
}

#[tokio::test]
async fn explicit_token_wins_over_env_token() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        Some("explicit-pat"),
        Some("env-token"),
        unreachable_secret,
    )
    .await
    .unwrap();

    assert_eq!(token, "explicit-pat");
}

#[tokio::test]
async fn cached_token_is_used_when_still_valid() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let mut store = CredentialStore::default();
    store.insert("https://server", account(&far_future()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        None,
        unreachable_secret,
    )
    .await
    .unwrap();

    assert_eq!(token, "eyJ-cached");
}

#[tokio::test]
async fn no_env_token_falls_through_to_the_cache() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let mut store = CredentialStore::default();
    store.insert("https://server", account(&far_future()));
    store.save_to(&path).unwrap();

    // env_token is explicitly None here — proving the outcome depends on
    // the parameter, not on whatever the test process's real environment
    // happens to contain.
    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        None,
        unreachable_secret,
    )
    .await
    .unwrap();

    assert_eq!(token, "eyJ-cached");
}

#[tokio::test]
async fn no_credential_produces_an_actionable_error() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let err = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        None,
        unreachable_secret,
    )
    .await
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("not authenticated"), "got: {message}");
    assert!(message.contains("netcidr login"), "got: {message}");
}

#[tokio::test]
async fn no_cached_account_is_not_authenticated_not_auth() {
    // Finding 3's variant boundary: an empty store (never logged in) must
    // produce `NotAuthenticated`, not the generic `Auth`, so a caller like
    // `mcp-serve --remote` can treat it as a silent, legitimate state
    // instead of a real credential failure worth a warning.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let err = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        None,
        unreachable_secret,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, NetcidrError::NotAuthenticated(_)),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn a_failed_refresh_is_auth_not_not_authenticated() {
    // The other half of Finding 3's variant boundary: a cached account
    // exists but its refresh token is dead. This is a real problem (not
    // "never logged in"), so it must come back as `Auth`, letting
    // `mcp-serve --remote` warn instead of staying silent.
    use axum::{Json, Router, routing::post};
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn stub() -> (axum::http::StatusCode, Json<serde_json::Value>) {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/token", post(stub)))
            .await
            .unwrap();
    });
    let token_endpoint = format!("http://{addr}/token");

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");
    let mut store = CredentialStore::default();
    store.insert("https://server", account(&already_past()));
    store.save_to(&path).unwrap();

    let err = resolve_from(
        &path,
        &token_endpoint,
        "https://server",
        None,
        None,
        stub_secret,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, NetcidrError::Auth(_)), "got: {err:?}");

    // The dead entry is dropped, not left behind to fail forever.
    let reloaded = CredentialStore::load_from(&path).unwrap();
    assert!(reloaded.get("https://server").is_none());
}

#[tokio::test]
async fn a_stale_credential_is_refreshed_and_written_back() {
    use axum::{Json, Router, routing::post};
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn stub() -> Json<serde_json::Value> {
        Json(json!({ "id_token": "eyJ-refreshed", "expires_in": 3599 }))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/token", post(stub)))
            .await
            .unwrap();
    });
    let token_endpoint = format!("http://{addr}/token");

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");
    let mut store = CredentialStore::default();
    store.insert("https://server", account(&already_past()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        &token_endpoint,
        "https://server",
        None,
        None,
        stub_secret,
    )
    .await
    .unwrap();
    assert_eq!(token, "eyJ-refreshed");

    // The refreshed token is persisted, so the next call does no network I/O.
    let reloaded = CredentialStore::load_from(&path).unwrap();
    let stored = reloaded.get("https://server").unwrap();
    assert_eq!(stored.id_token, "eyJ-refreshed");
    assert_eq!(
        stored.refresh_token, "1//0g-refresh",
        "refresh token preserved"
    );
    assert!(!is_expired(&stored.expires_at, 60));
}
