//! Token-endpoint tests against a local axum stub. No test in this file
//! contacts Google.

use axum::{Json, Router, extract::Form, routing::post};
use netcidr::oauth::{exchange_code, refresh_id_token};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
    client_id: String,
    client_secret: String,
}

/// Reject bad input with a 400 carrying a distinctive code rather than
/// panicking. A panic inside an axum handler drops the connection, which
/// reaches the test as an opaque "token request failed" and hides the real
/// cause; a 400 flows through the normal error path and names the problem.
async fn stub_token(
    Form(form): Form<TokenForm>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    fn bad(code: &str) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": code })),
        )
    }
    let ok = |body: serde_json::Value| (axum::http::StatusCode::OK, Json(body));

    if form.client_id != "desktop-client" {
        return bad("stub_bad_client_id");
    }
    if form.client_secret != "GOCSPX-test" {
        return bad("stub_bad_client_secret");
    }

    match form.grant_type.as_str() {
        "authorization_code" => {
            if form.code != "the-code" {
                return bad("stub_bad_code");
            }
            if form.code_verifier != "the-verifier" {
                return bad("stub_bad_verifier");
            }
            ok(json!({
                "id_token": "eyJ-fresh",
                "refresh_token": "1//0g-refresh",
                "expires_in": 3599
            }))
        }
        "refresh_token" => {
            if form.refresh_token != "1//0g-refresh" {
                return bad("stub_bad_refresh_token");
            }
            ok(json!({ "id_token": "eyJ-refreshed", "expires_in": 3599 }))
        }
        _ => bad("stub_unexpected_grant_type"),
    }
}

async fn stub_invalid_grant() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_grant", "error_description": "Token has been revoked." })),
    )
}

async fn spawn(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}/token")
}

#[tokio::test]
async fn exchange_returns_tokens() {
    let url = spawn(Router::new().route("/token", post(stub_token))).await;

    let response = exchange_code(
        &url,
        "desktop-client",
        "GOCSPX-test",
        "the-code",
        "the-verifier",
        "http://127.0.0.1:51847/callback",
    )
    .await
    .unwrap();

    assert_eq!(response.id_token, "eyJ-fresh");
    assert_eq!(response.refresh_token.as_deref(), Some("1//0g-refresh"));
    assert_eq!(response.expires_in, 3599);
}

#[tokio::test]
async fn refresh_returns_a_new_id_token() {
    let url = spawn(Router::new().route("/token", post(stub_token))).await;

    let response = refresh_id_token(&url, "desktop-client", "GOCSPX-test", "1//0g-refresh")
        .await
        .unwrap();

    assert_eq!(response.id_token, "eyJ-refreshed");
    // A refresh response carries no new refresh token; the caller keeps
    // the one it already has.
    assert!(response.refresh_token.is_none());
}

#[tokio::test]
async fn invalid_grant_is_reported_as_an_expired_session() {
    let url = spawn(Router::new().route("/token", post(stub_invalid_grant))).await;

    let err = refresh_id_token(&url, "desktop-client", "GOCSPX-test", "stale")
        .await
        .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("session expired"), "got: {message}");
    assert!(message.contains("netcidr login"), "got: {message}");
}

#[tokio::test]
async fn wrong_credentials_surface_the_stubs_error_code() {
    let url = spawn(Router::new().route("/token", post(stub_token))).await;

    let err = exchange_code(
        &url,
        "wrong-client",
        "GOCSPX-test",
        "the-code",
        "the-verifier",
        "http://127.0.0.1:51847/callback",
    )
    .await
    .unwrap_err();

    // Proves the stub's rejection path produces a legible failure rather
    // than a dropped connection.
    assert!(err.to_string().contains("stub_bad_client_id"), "got: {err}");
}

#[tokio::test]
async fn exchange_without_a_refresh_token_is_an_error() {
    async fn no_refresh() -> Json<serde_json::Value> {
        Json(json!({ "id_token": "eyJ-fresh", "expires_in": 3599 }))
    }
    let url = spawn(Router::new().route("/token", post(no_refresh))).await;

    let err = exchange_code(
        &url,
        "desktop-client",
        "GOCSPX-test",
        "the-code",
        "the-verifier",
        "http://127.0.0.1:51847/callback",
    )
    .await
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("no refresh token"), "got: {message}");
    assert!(message.contains("Desktop app"), "got: {message}");
}
