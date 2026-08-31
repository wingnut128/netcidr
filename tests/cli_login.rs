//! CLI-level behavior of `netcidr login` that does not require a real
//! Google flow: the two ways a server can be unusable for login.

use std::process::Command;

fn netcidr() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netcidr"));
    cmd.env_remove("NETCIDR_API_TOKEN");
    cmd.env_remove("NETCIDR_API_URL");
    cmd
}

#[test]
fn login_rejects_a_malformed_api_url() {
    let output = netcidr()
        .args(["login", "--api-url", "not-a-url"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("http://") && stderr.contains("https://"),
        "got: {stderr}"
    );
}

#[test]
fn login_requires_an_api_url() {
    let output = netcidr().arg("login").output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("NETCIDR_API_URL"), "got: {stderr}");
}

#[tokio::test]
async fn login_reports_a_server_with_no_cli_client() {
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn features() -> Json<serde_json::Value> {
        Json(json!({ "ipam": true, "swagger": false }))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/features", get(features)))
            .await
            .unwrap();
    });

    let output = tokio::task::spawn_blocking(move || {
        netcidr()
            .args([
                "login",
                "--api-url",
                &format!("http://{addr}"),
                "--no-browser",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NETCIDR_OIDC_CLI_CLIENT_ID"),
        "got: {stderr}"
    );
}
