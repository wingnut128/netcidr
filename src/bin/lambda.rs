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
//! ## Scheduled expiry sweep
//!
//! Lambda has no long-lived process for `netcidr serve`'s background sweep,
//! so an EventBridge schedule invokes the function instead. An invocation
//! whose payload is an EventBridge Scheduled Event (`"source":
//! "aws.events"`, `"detail-type": "Scheduled Event"`) runs one expiry sweep
//! across every tenant; every other payload is an HTTP request for the
//! router. API Gateway builds HTTP events itself, so a client cannot make a
//! request look scheduled; only an IAM principal allowed to invoke the
//! function directly can send arbitrary payloads.
//!
//! Build with:
//!   `cargo lambda build --release --arm64 --bin lambda --features lambda,ipam-postgres`

use std::sync::Arc;

use lambda_http::request::LambdaRequest;
use lambda_http::tower::{Service, ServiceExt};
use lambda_http::{Adapter, Error, LambdaEvent, lambda_runtime, service_fn};
use netcidr::api::{RouterConfig, create_router};
use netcidr::config::{AuthMode, ServerConfig};
use netcidr::ipam::operations::IpamOps;
use serde_json::Value;

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

/// Loopback stand-in passed to `validate_deployment`: Lambda has no TCP bind
/// address. Must be a bare IP (no port) — `is_loopback_bind_address` parses
/// it as an `IpAddr`, so `"127.0.0.1:0"` would fail every cold start.
const LAMBDA_VALIDATION_BIND_ADDRESS: &str = "127.0.0.1";

/// What a raw invocation asks the function to do.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// An EventBridge scheduled event: run the expiry sweep.
    Sweep,
    /// Anything else: an HTTP request for the router.
    Http,
}

fn classify(payload: &Value) -> Invocation {
    let field = |name: &str| payload.get(name).and_then(Value::as_str);
    if field("source") == Some("aws.events") && field("detail-type") == Some("Scheduled Event") {
        Invocation::Sweep
    } else {
        Invocation::Http
    }
}

/// Run one expiry sweep and report it as the invocation's result.
async fn run_sweep(ops: Option<&IpamOps>) -> Result<Value, Error> {
    let Some(ops) = ops else {
        tracing::warn!("scheduled sweep invoked but IPAM is disabled");
        return Ok(serde_json::json!({ "swept": false }));
    };
    let report = netcidr::ipam::sweeper::sweep_and_log(ops).await?;
    Ok(serde_json::to_value(report)?)
}

/// Handle one invocation: run the sweep for a scheduled event, otherwise
/// pass the HTTP event to `adapter` (the same `lambda_http` adapter that
/// `lambda_http::run` would use).
async fn dispatch<S>(
    mut adapter: S,
    ops: Option<Arc<IpamOps>>,
    event: LambdaEvent<Value>,
) -> Result<Value, Error>
where
    S: Service<LambdaEvent<LambdaRequest>>,
    S::Response: serde::Serialize,
    S::Error: Into<Error>,
{
    let LambdaEvent { payload, context } = event;
    match classify(&payload) {
        Invocation::Sweep => run_sweep(ops.as_deref()).await,
        Invocation::Http => {
            let request: LambdaRequest = serde_json::from_value(payload)?;
            let response = adapter
                .ready()
                .await
                .map_err(Into::into)?
                .call(LambdaEvent::new(request, context))
                .await
                .map_err(Into::into)?;
            Ok(serde_json::to_value(response)?)
        }
    }
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
    server.validate_deployment(LAMBDA_VALIDATION_BIND_ADDRESS)?;

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

    let sweep_ops = ipam_ops.clone();
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

    // `lambda_http::run(router)` would accept only HTTP events. Dispatch by
    // hand so scheduled events reach the sweep; HTTP events go through the
    // same adapter `run` uses.
    let adapter = Adapter::from(router);
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        dispatch(adapter.clone(), sweep_ops.clone(), event)
    }))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_eventbridge_scheduled_events_run_the_sweep() {
        let scheduled = serde_json::json!({
            "version": "0",
            "id": "53dc4d37-cffa-4f76-80c9-8b7d4a4d2eaa",
            "detail-type": "Scheduled Event",
            "source": "aws.events",
            "account": "123456789012",
            "time": "2026-10-01T12:00:00Z",
            "region": "us-east-1",
            "resources": ["arn:aws:events:us-east-1:123456789012:rule/netcidr-sweep"],
            "detail": {}
        });
        assert_eq!(classify(&scheduled), Invocation::Sweep);

        let api_gateway = serde_json::json!({
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/health",
            "headers": {"source": "aws.events", "detail-type": "Scheduled Event"},
            "requestContext": {"http": {"method": "GET", "path": "/health"}}
        });
        assert_eq!(classify(&api_gateway), Invocation::Http);
        // Other EventBridge events are not sweeps.
        let other = serde_json::json!({"source": "aws.events", "detail-type": "EC2 State Change"});
        assert_eq!(classify(&other), Invocation::Http);
    }

    fn api_gateway_get(path: &str) -> Value {
        serde_json::json!({
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": path,
            "rawQueryString": "",
            "headers": {"host": "example.com"},
            "requestContext": {
                "accountId": "123456789012",
                "apiId": "api",
                "domainName": "example.com",
                "domainPrefix": "example",
                "http": {
                    "method": "GET",
                    "path": path,
                    "protocol": "HTTP/1.1",
                    "sourceIp": "192.0.2.1",
                    "userAgent": "test"
                },
                "requestId": "req",
                "routeKey": "$default",
                "stage": "$default",
                "time": "01/Oct/2026:12:00:00 +0000",
                "timeEpoch": 1790000000000_u64
            },
            "isBase64Encoded": false
        })
    }

    #[tokio::test]
    async fn http_events_still_reach_the_router() {
        let router = axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
        let adapter = Adapter::from(router);
        let out = dispatch(
            adapter,
            None,
            LambdaEvent::new(api_gateway_get("/ping"), lambda_http::Context::default()),
        )
        .await
        .unwrap();
        assert_eq!(out["statusCode"], 200);
        assert_eq!(out["body"], "pong");
    }

    #[tokio::test]
    async fn a_scheduled_event_sweeps_every_tenant() {
        use netcidr::ipam::models::{CreateAllocation, CreateCidrBlock};
        use netcidr::ipam::store::IpamStore;
        let store = netcidr::ipam::sqlite::SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        let ops = Arc::new(IpamOps::new(Arc::new(store)));
        let block = ops
            .create_cidr_block(
                "t",
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();
        ops.allocate_specific(
            "t",
            &CreateAllocation {
                cidr_block_id: block.id,
                cidr: "10.0.1.0/24".to_string(),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
                ttl_seconds: Some(1),
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let scheduled = serde_json::json!({
            "detail-type": "Scheduled Event",
            "source": "aws.events",
            "detail": {}
        });
        let router = axum::Router::new();
        let out = dispatch(
            Adapter::from(router),
            Some(ops),
            LambdaEvent::new(scheduled, lambda_http::Context::default()),
        )
        .await
        .unwrap();
        assert_eq!(out["allocations_released"], 1);
    }

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
        let err = config
            .validate_deployment(LAMBDA_VALIDATION_BIND_ADDRESS)
            .expect_err("IPAM without auth must be rejected");
        // Guard against passing for the wrong reason (e.g. an unparseable
        // bind address rejecting every config).
        assert!(
            err.to_string().contains("auth_mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lambda_deployment_validation_accepts_oidc_with_ipam() {
        let config = ServerConfig {
            ipam_enabled: true,
            auth_mode: AuthMode::Oidc,
            oidc_audience: Some("client-id.apps.googleusercontent.com".to_string()),
            ..ServerConfig::default()
        };
        config
            .validate_deployment(LAMBDA_VALIDATION_BIND_ADDRESS)
            .expect("the production Lambda configuration must pass startup validation");
    }
}
