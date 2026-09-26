//! AWS Lambda entrypoint for the netcidr API.
//!
//! Runs the same Axum router that `netcidr serve` uses, just driven by the
//! Lambda runtime instead of bound to a TCP listener. The router is
//! constructed from environment variables (no config file on disk inside
//! the function package).
//!
//! ## Postgres backend
//!
//! Provide `NETCIDR_DATABASE_URL` with a Postgres connection string. The
//! backend defaults to `postgres`; override with `NETCIDR_IPAM_BACKEND`.
//!
//! Build with:
//!   `cargo lambda build --release --arm64 --bin lambda --features lambda,ipam-postgres`

use std::sync::Arc;

use lambda_http::{Error, run};
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};

fn env_or<S: Into<String>>(key: &str, fallback: S) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.into())
}

/// Parse a numeric environment variable, falling back to `fallback` when the
/// variable is unset or cannot be parsed.
fn env_parse<T: std::str::FromStr>(key: &str, fallback: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// An unknown authentication mode must never become an unauthenticated router.
fn parse_auth_mode(raw: &str) -> Result<AuthMode, String> {
    match raw {
        "oidc" => Ok(AuthMode::Oidc),
        "bearer" => Ok(AuthMode::Bearer),
        _ => Err(format!(
            "invalid NETCIDR_AUTH_MODE {raw:?}; expected 'oidc' or 'bearer'"
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,tower_http=warn".into());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_target(true)
        .without_time(); // Lambda already adds timestamps to log lines.

    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    // Opt-in OTLP span export. When built without `otel` or with
    // OTEL_EXPORTER_OTLP_ENDPOINT unset, no layer is attached (true no-op).
    // The guard is held for the force_flush middleware below.
    #[cfg(feature = "otel")]
    let otel_guard: Option<Arc<netcidr::telemetry::OtelGuard>> = {
        let (otel_layer, guard) = match netcidr::telemetry::otel_layer() {
            Some((layer, g)) => (Some(layer), Some(Arc::new(g))),
            None => (None, None),
        };
        registry.with(otel_layer).init();
        guard
    };
    #[cfg(not(feature = "otel"))]
    registry.init();

    let server = ServerConfig {
        auth_mode: parse_auth_mode(&env_or("NETCIDR_AUTH_MODE", "oidc"))?,
        ipam_enabled: env_or("NETCIDR_IPAM_ENABLED", "true") == "true",
        ipam_backend: env_or("NETCIDR_IPAM_BACKEND", "postgres"),
        ipam_db: None,
        ipam_db_url: std::env::var("NETCIDR_DATABASE_URL").ok(),
        enable_swagger: env_or("NETCIDR_ENABLE_SWAGGER", "true") == "true",
        // Per-IP rate limiting works under Lambda because the router uses
        // SmartIpKeyExtractor, which reads the client IP from the
        // X-Forwarded-For header that API Gateway sets (lambda_http provides
        // no ConnectInfo). Tunable without a redeploy via NETCIDR_RATE_LIMIT
        // (requests/sec, 0 disables) and NETCIDR_RATE_LIMIT_BURST.
        rate_limit_per_second: env_parse("NETCIDR_RATE_LIMIT", 20),
        rate_limit_burst: env_parse("NETCIDR_RATE_LIMIT_BURST", 50),
        ..ServerConfig::default()
    };

    // Lambda has no TCP bind address, but this runs the same auth and IPAM
    // startup checks as `serve` before any store or router is constructed.
    server.validate_deployment("127.0.0.1:0")?;

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

        // Bootstrap the users directory from the env lists — a one-shot
        // seed (marker-guarded); the DB is the source of truth thereafter.
        // Shared with `netcidr serve`.
        netcidr::ipam::bootstrap::seed_users(&store, &server).await;

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

    // `mut` is only needed when the otel layer is appended below.
    #[cfg_attr(not(feature = "otel"), allow(unused_mut))]
    let mut router = create_router(RouterConfig {
        server,
        ipam_ops,
        pat_pepper,
    });

    // Flush OTLP spans at the end of every invocation. The Lambda execution
    // environment can freeze between invocations, so a batch exporter must be
    // force-flushed per request to avoid losing in-flight spans. Added as the
    // outermost layer so it runs after the response is done.
    #[cfg(feature = "otel")]
    if let Some(guard) = otel_guard {
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let guard = Arc::clone(&guard);
                async move {
                    let response = next.run(req).await;
                    guard.force_flush();
                    response
                }
            },
        ));
    }

    run(router).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lambda_rejects_every_unauthenticated_mode_and_typos() {
        assert!(matches!(parse_auth_mode("oidc"), Ok(AuthMode::Oidc)));
        assert!(matches!(parse_auth_mode("bearer"), Ok(AuthMode::Bearer)));
        for value in ["", "none", "OIDC", "oidc ", "beerer", "disabled"] {
            assert!(parse_auth_mode(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn lambda_deployment_validation_rejects_missing_auth_configuration() {
        let config = ServerConfig {
            ipam_enabled: true,
            auth_mode: AuthMode::None,
            ..ServerConfig::default()
        };
        assert!(config.validate_deployment("127.0.0.1:0").is_err());
    }
}
