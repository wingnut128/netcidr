//! Precedence and refresh behavior of the shared credential resolver.

use netcidr::credentials::{Account, CredentialStore, is_expired, resolve_from};
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
        "GOCSPX-test",
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
        "GOCSPX-test",
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
        "GOCSPX-test",
    )
    .await
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("not authenticated"), "got: {message}");
    assert!(message.contains("netcidr login"), "got: {message}");
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
        "GOCSPX-test",
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
