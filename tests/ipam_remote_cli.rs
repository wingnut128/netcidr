//! `netcidr ipam` against a remote server: the real binary talking to an
//! in-process `netcidr serve` router (bearer-token mode).

use std::process::{Command, Output};
use std::sync::Arc;

use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;

/// Start a bearer-mode server; returns its base URL and the token it accepts.
async fn start_server() -> (String, String) {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let server = ServerConfig {
        rate_limit_per_second: 0,
        auth_mode: AuthMode::Bearer,
        auth_token: Some("remote-cli-test-token".to_string()),
        ..Default::default()
    };
    // NETCIDR_API_TOKEN in the environment would win over the field.
    let token = server.auth_token().unwrap();
    let app = create_router(RouterConfig {
        server,
        ipam_ops: Some(Arc::new(IpamOps::new(Arc::new(store)))),
        pat_pepper: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), token)
}

/// The binary with every netcidr variable cleared and HOME pointed at an
/// empty dir, so no cached login or default DB can leak in.
fn netcidr(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netcidr"));
    for var in ["NETCIDR_API_URL", "NETCIDR_API_TOKEN", "NETCIDR_DB"] {
        cmd.env_remove(var);
    }
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"));
    cmd
}

async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn stdout_json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test]
async fn api_url_flag_runs_ipam_against_the_server() {
    let (url, token) = start_server().await;
    let home = tempfile::tempdir().unwrap();

    let mut create = netcidr(home.path());
    create.args([
        "ipam",
        "--api-url",
        &url,
        "--api-token",
        &token,
        "cidr-block",
        "create",
        "10.0.0.0/16",
    ]);
    let created = run(create).await;
    let block = stdout_json(&created);
    let stderr = String::from_utf8_lossy(&created.stderr);
    assert!(
        stderr.contains(&format!("ipam: remote {url}")),
        "stderr: {stderr}"
    );

    let mut alloc = netcidr(home.path());
    alloc.args([
        "ipam",
        "--api-url",
        &url,
        "--api-token",
        &token,
        "allocate",
        block["id"].as_str().unwrap(),
        "10.0.1.0/24",
        "--name",
        "web",
    ]);
    stdout_json(&run(alloc).await);

    let mut list = netcidr(home.path());
    list.args([
        "ipam",
        "--api-url",
        &url,
        "--api-token",
        &token,
        "allocation",
        "list",
    ]);
    let list = stdout_json(&run(list).await);
    assert_eq!(list["count"], 1);
    assert_eq!(list["allocations"][0]["name"], "web");
}

#[tokio::test]
async fn env_vars_select_remote_and_db_flag_overrides() {
    let (url, token) = start_server().await;
    let home = tempfile::tempdir().unwrap();

    let mut create = netcidr(home.path());
    create
        .env("NETCIDR_API_URL", &url)
        .env("NETCIDR_API_TOKEN", &token)
        .args(["ipam", "cidr-block", "create", "10.9.0.0/16"]);
    stdout_json(&run(create).await);

    let mut remote = netcidr(home.path());
    remote
        .env("NETCIDR_API_URL", &url)
        .env("NETCIDR_API_TOKEN", &token)
        .args(["ipam", "cidr-block", "list"]);
    assert_eq!(stdout_json(&run(remote).await)["count"], 1);

    // --db wins over NETCIDR_API_URL: a fresh local DB is empty.
    let db = home.path().join("local.db");
    let mut local = netcidr(home.path());
    local
        .env("NETCIDR_API_URL", &url)
        .env("NETCIDR_API_TOKEN", &token)
        .args(["ipam", "--db", db.to_str().unwrap(), "cidr-block", "list"]);
    let out = run(local).await;
    assert_eq!(stdout_json(&out)["count"], 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ipam: local"), "stderr: {stderr}");
}

#[tokio::test]
async fn remote_without_credentials_says_how_to_log_in() {
    let (url, _) = start_server().await;
    let home = tempfile::tempdir().unwrap();
    let mut cmd = netcidr(home.path());
    cmd.args(["ipam", "--api-url", &url, "cidr-block", "list"]);
    let out = run(cmd).await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("netcidr login"), "stderr: {stderr}");
    assert!(stderr.contains("NETCIDR_API_TOKEN"), "stderr: {stderr}");
}

#[tokio::test]
async fn dump_and_load_refuse_remote_mode() {
    let (url, token) = start_server().await;
    let home = tempfile::tempdir().unwrap();
    for args in [vec!["dump"], vec!["load", "/dev/null"]] {
        let mut cmd = netcidr(home.path());
        cmd.args(["ipam", "--api-url", &url, "--api-token", &token])
            .args(&args);
        let out = run(cmd).await;
        assert!(!out.status.success(), "{args:?} should fail remotely");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--db"), "{args:?} stderr: {stderr}");
    }
}

#[test]
fn db_and_api_url_flags_conflict() {
    let home = tempfile::tempdir().unwrap();
    let out = netcidr(home.path())
        .args([
            "ipam",
            "--db",
            "x.db",
            "--api-url",
            "http://localhost:1",
            "cidr-block",
            "list",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot be used with"));
}

#[test]
fn help_explains_backend_selection() {
    let home = tempfile::tempdir().unwrap();
    let out = netcidr(home.path())
        .args(["ipam", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "--api-url",
        "NETCIDR_API_URL",
        "NETCIDR_API_TOKEN",
        "NETCIDR_DB",
        "netcidr login",
    ] {
        assert!(help.contains(needle), "help missing {needle}:\n{help}");
    }
}
