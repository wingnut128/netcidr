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
        auth_mode: match env_or("NETCIDR_AUTH_MODE", "oidc").as_str() {
            "bearer" => AuthMode::Bearer,
            "oidc" => AuthMode::Oidc,
            _ => AuthMode::None,
        },
        ipam_enabled: env_or("NETCIDR_IPAM_ENABLED", "true") == "true",
        ipam_backend: env_or("NETCIDR_IPAM_BACKEND", "postgres"),
        ipam_db: None,
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

        // Bootstrap role membership from the env lists on first start
        // (no-op once the table has rows). DB is source of truth thereafter.
        {
            use netcidr::auth::Role;
            let mut seeds: Vec<(String, Role)> = Vec::new();
            seeds.extend(server.admin_emails().into_iter().map(|e| (e, Role::Admin)));
            seeds.extend(
                server
                    .allocator_emails()
                    .into_iter()
                    .map(|e| (e, Role::Allocator)),
            );
            seeds.extend(
                server
                    .reader_emails()
                    .into_iter()
                    .map(|e| (e, Role::Reader)),
            );
            match store.seed_role_assignments_if_empty(&seeds).await {
                Ok(n) if n > 0 => {
                    tracing::info!("seeded {n} role assignment(s) from env lists")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "role assignment bootstrap seed failed"),
            }
        }

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
