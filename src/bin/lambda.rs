//! AWS Lambda entrypoint for the netcidr API.
//!
//! Runs the same Axum router that `netcidr serve` uses, just driven by the
//! Lambda runtime instead of bound to a TCP listener. The router is
//! constructed from environment variables (no config file on disk inside
//! the function package).
//!
//! Build with: `cargo lambda build --release --arm64 --bin lambda
//!              --features lambda,ipam-postgres`

use std::sync::Arc;

use lambda_http::{Error, run};
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};

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

    // Auth audience, allowed_emails, and bearer token are read directly from
    // env vars by ServerConfig::auth_config(), so they don't appear here.
    let server = ServerConfig {
        auth_mode: match env_or("NETCIDR_AUTH_MODE", "oidc").as_str() {
            "bearer" => AuthMode::Bearer,
            "oidc" => AuthMode::Oidc,
            _ => AuthMode::None,
        },
        ipam_enabled: env_or("NETCIDR_IPAM_ENABLED", "true") == "true",
        ipam_backend: env_or("NETCIDR_IPAM_BACKEND", "postgres"),
        ipam_db_url: std::env::var("NETCIDR_DATABASE_URL").ok(),
        enable_swagger: false,
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

    let router = create_router(RouterConfig { server, ipam_ops });

    run(router).await
}
