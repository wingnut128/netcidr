//! AWS Lambda entrypoint for the netcidr API.
//!
//! Runs the same Axum router that `netcidr serve` uses, just driven by the
//! Lambda runtime instead of bound to a TCP listener. The router is
//! constructed from environment variables (no config file on disk inside
//! the function package).
//!
//! ## S3-backed SQLite (recommended for small deployments)
//!
//! Set `NETCIDR_S3_BUCKET` to opt into the SQLite-on-S3 backend instead of
//! Postgres. On every cold start the database is pulled from S3 to
//! `/tmp/netcidr.db`; after each mutating request it is pushed back.
//!
//! Required env vars for S3 mode:
//! - `NETCIDR_S3_BUCKET` — S3 bucket name
//! - `NETCIDR_S3_KEY`    — object key (default: `netcidr/netcidr.db`)
//! - `NETCIDR_DB`        — local path (default: `/tmp/netcidr.db`)
//!
//! The Lambda execution role needs `s3:GetObject` + `s3:PutObject` on the
//! bucket. Set `reserved_concurrency = 1` on the function to prevent
//! concurrent containers from diverging state.
//!
//! ## Postgres backend
//!
//! Leave `NETCIDR_S3_BUCKET` unset and provide `NETCIDR_DATABASE_URL`.
//!
//! Build with:
//!   `cargo lambda build --release --arm64 --bin lambda --features lambda,ipam-postgres`
//!   (Postgres backend)
//!
//!   `cargo lambda build --release --arm64 --bin lambda --features lambda`
//!   (S3/SQLite backend)

use std::sync::Arc;

use lambda_http::{Error, run};
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::s3_sync::{S3Syncer, is_write_method};

fn env_or<S: Into<String>>(key: &str, fallback: S) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.into())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .json()
        .with_ansi(false)
        .with_target(true)
        .without_time() // Lambda already adds timestamps to log lines.
        .init();

    // -----------------------------------------------------------------------
    // S3/SQLite sync — activated when NETCIDR_S3_BUCKET is set.
    // Pull the DB to /tmp on cold start; push back after every write.
    // -----------------------------------------------------------------------
    let s3_syncer: Option<Arc<S3Syncer>> = if let Ok(bucket) = std::env::var("NETCIDR_S3_BUCKET") {
        let key = env_or("NETCIDR_S3_KEY", "netcidr/netcidr.db");
        let db_path = env_or("NETCIDR_DB", "/tmp/netcidr.db");
        let syncer = S3Syncer::new(bucket, key, db_path).await;
        syncer.pull().await?;
        Some(Arc::new(syncer))
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // Server config — backend is forced to sqlite when S3 sync is active.
    // -----------------------------------------------------------------------
    let (ipam_backend, ipam_db) = if let Some(ref syncer) = s3_syncer {
        ("sqlite".to_string(), Some(syncer.db_path.clone()))
    } else {
        (
            env_or("NETCIDR_IPAM_BACKEND", "postgres"),
            None, // Postgres URL is read via NETCIDR_DATABASE_URL below
        )
    };

    let server = ServerConfig {
        auth_mode: match env_or("NETCIDR_AUTH_MODE", "oidc").as_str() {
            "bearer" => AuthMode::Bearer,
            "oidc" => AuthMode::Oidc,
            _ => AuthMode::None,
        },
        ipam_enabled: env_or("NETCIDR_IPAM_ENABLED", "true") == "true",
        ipam_backend,
        ipam_db,
        ipam_db_url: std::env::var("NETCIDR_DATABASE_URL").ok(),
        enable_swagger: env_or("NETCIDR_ENABLE_SWAGGER", "true") == "true",
        // Disable the per-IP rate limiter under Lambda. tower_governor needs
        // ConnectInfo<SocketAddr> from a real TCP peer, which lambda_http
        // doesn't provide — every request would 500 with "Unable To Extract
        // Key!". AWS Lambda's own concurrency limits cover throttling.
        rate_limit_per_second: 0,
        ..ServerConfig::default()
    };

    let ipam_ops = if server.ipam_enabled {
        let mut ipam_config = netcidr::ipam::config::IpamConfig::default();
        if let Ok(b) = server
            .ipam_backend
            .parse::<netcidr::ipam::config::Backend>()
        {
            ipam_config.backend = b;
        }
        let store = netcidr::ipam::create_store(
            &ipam_config,
            server.ipam_db.as_deref(),
            server.ipam_db_url.as_deref(),
        )
        .await?;
        Some(Arc::new(netcidr::ipam::operations::IpamOps::new(store)))
    } else {
        None
    };

    // Keep Lambda startup aligned with `netcidr serve`: OIDC deployments
    // that can mint PATs must also configure the pepper used to hash and
    // verify them. Without this, the dashboard can ship token UI while the
    // Lambda router never mounts /me/tokens.
    let pat_pepper = if matches!(server.auth_mode, AuthMode::Oidc) {
        Some(Arc::new(netcidr::pat::PatPepper::from_env()?))
    } else {
        None
    };

    let mut router = create_router(RouterConfig {
        server,
        ipam_ops,
        pat_pepper,
    });

    // -----------------------------------------------------------------------
    // After every mutating request, push the SQLite DB back to S3.
    // -----------------------------------------------------------------------
    if let Some(syncer) = s3_syncer {
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let syncer = Arc::clone(&syncer);
                async move {
                    let method = req.method().clone();
                    let response = next.run(req).await;
                    if is_write_method(&method) && let Err(e) = syncer.push().await {
                        tracing::error!(error = %e, "S3 push failed after write");
                    }
                    response
                }
            },
        ));
    }

    run(router).await
}
