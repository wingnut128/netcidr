//! Phase 5 — `netcidr token …` CLI integration test.
//!
//! Spins up an in-process netcidr API in OIDC mode (with stubbed JWKS via
//! `auth::test_support`) bound to a real TCP port, then runs the CLI
//! binary as a subprocess against that URL. Exercises the
//! create → use → list → revoke → can't-use lifecycle end-to-end.
//!
//! Single test on purpose: HTTP-level validation/edge cases are already
//! covered exhaustively by `pat_api_tests.rs`. This test's job is to
//! prove the CLI ↔ server wire-up actually works.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use netcidr::api::{RouterConfig, create_router};
use netcidr::auth::test_support;
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use netcidr::pat::PatPepper;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

const TEST_KID: &str = "cli-token-test-key";
const AUDIENCE: &str = "test-audience";
const ISSUER: &str = "https://accounts.google.com";

const USER_EMAIL: &str = "alice@example.com";
const USER_SUB: &str = "1110000000000000111";

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

fn keypair() -> &'static (RsaPrivateKey, RsaPublicKey) {
    static KEYS: OnceLock<(RsaPrivateKey, RsaPublicKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let public = RsaPublicKey::from(&private);
        (private, public)
    })
}

fn jwks_lock_arc() -> Arc<Mutex<()>> {
    static ARC: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
    Arc::clone(ARC.get_or_init(|| Arc::new(Mutex::new(()))))
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

#[tokio::test(flavor = "multi_thread")]
async fn cli_create_use_list_revoke_lifecycle() {
    // ----- Stand up the server on a real ephemeral port. -----
    let _jwks_guard = jwks_lock_arc().lock_owned().await;
    let (_, public) = keypair();
    test_support::install_jwks(
        TEST_KID,
        &public.n().to_bytes_be(),
        &public.e().to_bytes_be(),
    )
    .await;

    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let ops = Arc::new(IpamOps::new(Arc::clone(&store)));
    let pepper = Arc::new(PatPepper::from_bytes(&[0xA7u8; 32]).unwrap());

    let server = ServerConfig {
        rate_limit_per_second: 0,
        auth_mode: AuthMode::Oidc,
        oidc_audience: Some(AUDIENCE.to_string()),
        oidc_allowed_emails: vec![USER_EMAIL.to_string()],
        ipam_enabled: true,
        ..Default::default()
    };

    let router = create_router(RouterConfig {
        server,
        ipam_ops: Some(ops),
        pat_pepper: Some(Arc::clone(&pepper)),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let api_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // ----- CREATE via CLI (OIDC bearer). -----
    let id_token = sign_id_token(USER_SUB, USER_EMAIL);
    let bin = env!("CARGO_BIN_EXE_netcidr");

    let create_out = Command::new(bin)
        .args(["--format", "json", "token", "create", "--name", "cli-test"])
        .env("NETCIDR_API_URL", &api_url)
        .env("NETCIDR_API_TOKEN", &id_token)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn netcidr token create");

    assert!(
        create_out.status.success(),
        "token create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create_out.stdout),
        String::from_utf8_lossy(&create_out.stderr)
    );

    let created: Value =
        serde_json::from_slice(&create_out.stdout).expect("token create stdout should be JSON");
    let pat_id = created["id"].as_str().expect("id").to_string();
    let pat_plaintext = created["token"].as_str().expect("token").to_string();
    assert!(
        pat_plaintext.starts_with("ncdr_pat_"),
        "minted token has expected prefix: {pat_plaintext}"
    );

    // ----- USE the new PAT against /ipam/supernets to prove it works. -----
    let http = reqwest::Client::new();
    let probe_resp = http
        .get(format!("{api_url}/ipam/supernets"))
        .bearer_auth(&pat_plaintext)
        .send()
        .await
        .unwrap();
    assert_eq!(
        probe_resp.status().as_u16(),
        200,
        "fresh PAT should authenticate against /ipam/*"
    );

    // ----- LIST via CLI; the new token must show up. -----
    let list_out = Command::new(bin)
        .args(["--format", "json", "token", "list"])
        .env("NETCIDR_API_URL", &api_url)
        .env("NETCIDR_API_TOKEN", &id_token)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn netcidr token list");
    assert!(list_out.status.success(), "token list failed");
    let listed: Value = serde_json::from_slice(&list_out.stdout).expect("list JSON");
    let ids: Vec<&str> = listed["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&pat_id.as_str()),
        "list should include {pat_id}; got {ids:?}"
    );

    // ----- REVOKE via CLI. -----
    let revoke_out = Command::new(bin)
        .args(["--format", "json", "token", "revoke", &pat_id])
        .env("NETCIDR_API_URL", &api_url)
        .env("NETCIDR_API_TOKEN", &id_token)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn netcidr token revoke");
    assert!(
        revoke_out.status.success(),
        "token revoke failed: stderr={}",
        String::from_utf8_lossy(&revoke_out.stderr)
    );

    // ----- The revoked PAT must no longer authenticate. -----
    let probe2 = http
        .get(format!("{api_url}/ipam/supernets"))
        .bearer_auth(&pat_plaintext)
        .send()
        .await
        .unwrap();
    assert_eq!(
        probe2.status().as_u16(),
        401,
        "revoked PAT must be rejected"
    );

    test_support::clear_jwks().await;
}
