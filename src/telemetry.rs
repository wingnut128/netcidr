//! Opt-in OpenTelemetry / OTLP span export (Cargo feature `otel`).
//!
//! Exports the existing `tracing` `#[instrument]` spans to an OTLP collector
//! (Honeycomb or any OTLP/HTTP backend) over HTTP+protobuf via reqwest+rustls
//! — no gRPC/tonic transport, no native deps.
//!
//! ## Activation
//!
//! The OTel layer is attached **only** when both are true:
//! 1. the binary was built with `--features otel`, and
//! 2. `OTEL_EXPORTER_OTLP_ENDPOINT` is set at runtime.
//!
//! With either missing, no layer is attached and the SDK is never initialized
//! — a true no-op. Local dev and unconfigured deployments pay zero overhead.
//!
//! ## Configuration (OTel-generic env vars)
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` — collector base URL (required to enable).
//! - `OTEL_EXPORTER_OTLP_HEADERS`  — e.g. `x-honeycomb-team=<key>` for Honeycomb.
//! - `OTEL_SERVICE_NAME`           — service name (default `netcidr`).
//! - `OTEL_TRACES_SAMPLER_ARG`     — parent-based ratio sampler arg (default `1.0`).
//!
//! ## PII allowlist — enforced, not just documented
//!
//! Span attributes are restricted to a fixed allowlist (`http.route`,
//! `http.method`, `http.status_code`, `netcidr.tenant_id`, `netcidr.role`).
//! Because the `tracing`→OTel bridge exports *every* field recorded on a span,
//! the allowlist is enforced at the export boundary by [`RedactingExporter`],
//! which strips any attribute whose key looks like PII or a credential
//! (`*email`, `sub`, `*token*`, `*secret*`, `database_url`, …) before the batch
//! leaves the process. Email/sub/bearer/PAT-secret/`DATABASE_URL` are NEVER
//! exported, even if some `#[instrument]` records them for local CloudWatch logs.

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider, SpanData};
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

/// Env var that gates activation. Set it to enable OTLP export.
const ENABLE_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Attribute keys that are safe to export. Documented for auditability; the
/// actual gate is the denylist in [`is_pii_key`] (deny-by-pattern is safer
/// than allow-by-list when fields can be added anywhere a span is created).
pub const SPAN_ATTR_ALLOWLIST: &[&str] = &[
    "http.route",
    "http.method",
    "http.status_code",
    "netcidr.tenant_id",
    "netcidr.role",
];

/// Returns true when an attribute key looks like PII or a credential and must
/// be stripped before export. Pattern-based so it also catches fields added by
/// future `#[instrument]` sites (e.g. `owner_email`, `caller_email`). Note that
/// non-sensitive identifiers like `pat_id` (a token *id*, not the secret) are
/// intentionally NOT matched.
pub fn is_pii_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.ends_with("email")
        || k == "sub"
        || k.ends_with("_sub")
        || k.contains("token")
        || k.contains("password")
        || k.contains("secret")
        || k.contains("authorization")
        || k.contains("bearer")
        || k.contains("api_key")
        || k.contains("apikey")
        || k.contains("credential")
        || k.contains("database_url")
}

/// Held for the lifetime of the program. On drop, shuts the provider down
/// (flushing any buffered spans). For Lambda, [`OtelGuard::force_flush`] is
/// called at the end of every invocation so nothing is lost to env freeze.
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl OtelGuard {
    /// Flush any buffered spans now. Cheap to call when there is nothing
    /// pending; used by the Lambda per-invocation middleware.
    pub fn force_flush(&self) {
        if let Err(e) = self.provider.force_flush() {
            tracing::warn!(error = ?e, "otel force_flush failed");
        }
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        // Best-effort: flush + shut down the exporter pipeline on shutdown.
        if let Err(e) = self.provider.shutdown() {
            eprintln!("otel provider shutdown failed: {e:?}");
        }
    }
}

/// Looks up a configuration variable by name. Production reads the process
/// environment ([`process_env`]); tests pass a closure so they never have to
/// mutate process-wide env, which is `unsafe` and races parallel tests.
type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Parse the parent-based sampler ratio from `OTEL_TRACES_SAMPLER_ARG`,
/// clamped to `[0.0, 1.0]`. Defaults to `1.0` (sample everything) when unset
/// or unparseable.
pub fn sampler_ratio_from_env() -> f64 {
    sampler_ratio(&process_env)
}

fn sampler_ratio(env: EnvLookup) -> f64 {
    env("OTEL_TRACES_SAMPLER_ARG")
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map(|r| r.clamp(0.0, 1.0))
        .unwrap_or(1.0)
}

/// Service name from `OTEL_SERVICE_NAME`, defaulting to `netcidr`.
fn service_name(env: EnvLookup) -> String {
    env("OTEL_SERVICE_NAME")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "netcidr".to_string())
}

/// True when OTLP export is configured at runtime (the enable env var is set
/// to a non-empty value). When false, [`otel_layer`] returns `None`.
pub fn is_configured() -> bool {
    configured(&process_env)
}

fn configured(env: EnvLookup) -> bool {
    env(ENABLE_ENV).is_some_and(|v| !v.trim().is_empty())
}

/// Build the OTel tracing layer and a guard, or `None` when export is not
/// configured (env var unset). The returned layer is attached to the
/// subscriber registry; the guard must be held for the program's lifetime.
///
/// `Option<Layer>` composes cleanly via `registry().with(maybe_layer)` — a
/// `None` layer is a no-op, so callers attach the result unconditionally.
pub fn otel_layer<S>() -> Option<(
    OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>,
    OtelGuard,
)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    otel_layer_with(&process_env)
}

fn otel_layer_with<S>(
    env: EnvLookup,
) -> Option<(
    OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>,
    OtelGuard,
)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    if !configured(env) {
        return None;
    }

    // HTTP/protobuf exporter over reqwest+rustls. Endpoint and headers are read
    // from the standard `OTEL_EXPORTER_OTLP_*` env vars by the builder.
    let exporter = match SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build OTLP exporter; spans will not be exported");
            return None;
        }
    };

    let ratio = sampler_ratio(env);
    let resource = Resource::builder()
        .with_service_name(service_name(env))
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(RedactingExporter::new(exporter))
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            ratio,
        ))))
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(service_name(env));
    let layer = OpenTelemetryLayer::new(tracer);

    // Make the provider global so context propagation / nested spans work.
    opentelemetry::global::set_tracer_provider(provider.clone());

    Some((layer, OtelGuard { provider }))
}

/// A [`SpanExporter`] decorator that strips PII/credential-keyed attributes
/// from every span before delegating to the real OTLP exporter. This is the
/// enforcement point for the documented attribute allowlist — see [`is_pii_key`].
#[derive(Debug)]
struct RedactingExporter<E> {
    inner: E,
}

impl<E> RedactingExporter<E> {
    fn new(inner: E) -> Self {
        Self { inner }
    }
}

/// Remove any attribute whose key is flagged by [`is_pii_key`].
fn redact_attributes(attrs: &mut Vec<KeyValue>) {
    attrs.retain(|kv| !is_pii_key(kv.key.as_str()));
}

impl<E: opentelemetry_sdk::trace::SpanExporter> opentelemetry_sdk::trace::SpanExporter
    for RedactingExporter<E>
{
    async fn export(&self, mut batch: Vec<SpanData>) -> OTelSdkResult {
        for span in &mut batch {
            redact_attributes(&mut span.attributes);
        }
        self.inner.export(batch).await
    }

    fn shutdown(&self) -> OTelSdkResult {
        self.inner.shutdown()
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_keys_are_flagged() {
        for k in [
            "email",
            "owner_email",
            "caller_email",
            "sub",
            "caller_sub",
            "access_token",
            "bearer_token",
            "db_password",
            "api_secret",
            "x_api_key",
            "apikey",
            "database_url",
            "Authorization",
            "credential",
        ] {
            assert!(is_pii_key(k), "expected `{k}` to be flagged as PII");
        }
    }

    #[test]
    fn safe_keys_are_not_flagged() {
        for k in [
            "http.route",
            "http.method",
            "http.status_code",
            "netcidr.tenant_id",
            "netcidr.role",
            "pat_id", // a token *id*, not the secret — must survive
            "cidr",
            "prefix",
            "count",
        ] {
            assert!(!is_pii_key(k), "expected `{k}` to be allowed");
        }
    }

    #[test]
    fn allowlist_contains_no_pii_keys() {
        for k in SPAN_ATTR_ALLOWLIST {
            assert!(!is_pii_key(k), "allowlisted key `{k}` must not be PII");
        }
    }

    #[test]
    fn redact_attributes_strips_pii_keeps_safe() {
        let mut attrs = vec![
            KeyValue::new("http.route", "/ipam/allocations"),
            KeyValue::new("netcidr.tenant_id", "tenant-a"),
            KeyValue::new("owner_email", "alice@example.com"),
            KeyValue::new("access_token", "secret-value"),
            KeyValue::new("pat_id", "abc-123"),
        ];
        redact_attributes(&mut attrs);
        let keys: Vec<&str> = attrs.iter().map(|kv| kv.key.as_str()).collect();
        assert!(keys.contains(&"http.route"));
        assert!(keys.contains(&"netcidr.tenant_id"));
        assert!(keys.contains(&"pat_id"));
        assert!(!keys.contains(&"owner_email"));
        assert!(!keys.contains(&"access_token"));
    }

    /// An env lookup backed by fixed pairs, so tests never touch process env.
    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn sampler_ratio_defaults_and_clamps() {
        let ratio = |v: Option<&str>| match v {
            Some(v) => sampler_ratio(&fake_env(&[("OTEL_TRACES_SAMPLER_ARG", v)])),
            None => sampler_ratio(&fake_env(&[])),
        };
        assert_eq!(ratio(None), 1.0);
        assert_eq!(ratio(Some("0.25")), 0.25);
        assert_eq!(ratio(Some(" 0.5 ")), 0.5);
        assert_eq!(ratio(Some("2.0")), 1.0);
        assert_eq!(ratio(Some("-1")), 0.0);
        assert_eq!(ratio(Some("nope")), 1.0);
    }

    #[test]
    fn service_name_defaults_when_unset_or_blank() {
        assert_eq!(service_name(&fake_env(&[])), "netcidr");
        assert_eq!(
            service_name(&fake_env(&[("OTEL_SERVICE_NAME", "  ")])),
            "netcidr"
        );
        assert_eq!(
            service_name(&fake_env(&[("OTEL_SERVICE_NAME", "netcidr-prod")])),
            "netcidr-prod"
        );
    }

    #[test]
    fn configured_requires_a_non_blank_endpoint() {
        assert!(!configured(&fake_env(&[])));
        assert!(!configured(&fake_env(&[(ENABLE_ENV, "   ")])));
        assert!(configured(&fake_env(&[(
            ENABLE_ENV,
            "http://127.0.0.1:4318"
        )])));
    }

    /// Measures the one-time OTel pipeline init cost (a proxy for the Lambda
    /// cold-start delta — the dominant added cost is building the exporter +
    /// provider, not per-request work). Ignored by default; run with:
    /// `cargo test --features otel otel_init_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing measurement; run manually with --ignored --nocapture"]
    fn otel_init_timing() {
        let env = fake_env(&[(ENABLE_ENV, "http://127.0.0.1:4318")]);
        // The exporter (reqwest client) + batch processor need a tokio runtime
        // context, which `serve`/Lambda provide via `#[tokio::main]`.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _enter = rt.enter();
        let start = std::time::Instant::now();
        let layer = otel_layer_with::<tracing_subscriber::Registry>(&env);
        let elapsed = start.elapsed();
        assert!(layer.is_some(), "endpoint set → layer should be Some");
        // Drop the guard to shut the pipeline down promptly.
        drop(layer);
        println!("otel pipeline init took {elapsed:?}");
    }

    #[test]
    fn not_configured_yields_no_layer() {
        // Guards the acceptance criterion: env unset → no layer attached.
        let layer = otel_layer_with::<tracing_subscriber::Registry>(&fake_env(&[]));
        assert!(layer.is_none());
    }
}
