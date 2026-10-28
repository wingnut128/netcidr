//! HTTP server request spans for the API router.
//!
//! Replaces tower-http's default `TraceLayer` span, which is created at DEBUG
//! under the `tower_http` target and is therefore dropped by the usual
//! `info,tower_http=warn` filter, leaving every handler's `#[instrument]` span
//! as its own root trace. The span built here is INFO under netcidr's own
//! target and follows the OpenTelemetry HTTP server semantic conventions:
//!
//! - span name `{METHOD} {route}` via `otel.name`, using the matched route
//!   template (`/ipam/cidr-blocks/{id}`), never the raw path, so names stay
//!   low-cardinality; just `{METHOD}` when no route matched;
//! - `otel.kind = server`, `http.request.method`, `http.route`. The raw path
//!   and query string are not recorded: path parameters include free-form
//!   user text (`find-resource/{resource_id}`) and unmatched paths are
//!   whatever the client sent;
//! - `http.response.status_code`, and `otel.status_code = error` on 5xx
//!   (4xx is the client's fault and leaves the status unset, per semconv).
//!
//! With the `otel` feature, the span also continues an inbound W3C
//! `traceparent` (see [`crate::telemetry::set_remote_parent`]).

use std::time::Duration;

use axum::extract::MatchedPath;
use axum::http::{Request, Response};
use tracing::{Span, field};

/// Span name for a request: `{METHOD} {route}` when a route template matched,
/// else the bare method.
pub fn span_name(method: &str, route: Option<&str>) -> String {
    match route {
        Some(route) => format!("{method} {route}"),
        None => method.to_string(),
    }
}

/// `TraceLayer::make_span_with` callback.
pub fn make_span<B>(req: &Request<B>) -> Span {
    let method = req.method().as_str();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);

    let span = tracing::info_span!(
        "http.request",
        otel.name = %span_name(method, route),
        otel.kind = "server",
        otel.status_code = field::Empty,
        http.request.method = %method,
        http.route = route,
        http.response.status_code = field::Empty,
    );

    #[cfg(feature = "otel")]
    crate::telemetry::set_remote_parent(&span, req.headers());

    span
}

/// `TraceLayer::on_response` callback: records the status code and marks
/// server errors. Emits no event; the span itself is the record.
pub fn on_response<B>(res: &Response<B>, _latency: Duration, span: &Span) {
    let status = res.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Subscriber, field::Field, field::Visit};
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::{Layer, Registry};

    #[test]
    fn span_name_uses_route_template() {
        assert_eq!(
            span_name("GET", Some("/ipam/cidr-blocks/{id}")),
            "GET /ipam/cidr-blocks/{id}"
        );
    }

    #[test]
    fn span_name_without_route_is_method_only() {
        assert_eq!(span_name("POST", None), "POST");
    }

    /// Field values recorded on one span, keyed by field name.
    #[derive(Default)]
    struct Fields(HashMap<String, String>);

    impl Visit for Fields {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    /// Collects the fields of every `http.request` span when it closes.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<HashMap<String, String>>>>);

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Capture {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
            let mut fields = Fields::default();
            attrs.record(&mut fields);
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(fields);
            }
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
            if let Some(span) = ctx.span(id)
                && let Some(fields) = span.extensions_mut().get_mut::<Fields>()
            {
                values.record(fields);
            }
        }

        fn on_close(&self, id: Id, ctx: Context<'_, S>) {
            if let Some(span) = ctx.span(&id)
                && span.name() == "http.request"
                && let Some(fields) = span.extensions_mut().remove::<Fields>()
            {
                self.0.lock().unwrap().push(fields.0);
            }
        }
    }

    fn app() -> Router {
        let ipam = Router::new().route("/things/{id}", get(|| async { "ok" }));
        Router::new()
            .route(
                "/boom",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "no") }),
            )
            .route("/denied", get(|| async { StatusCode::FORBIDDEN }))
            .nest("/ipam", ipam)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(make_span)
                    .on_response(on_response),
            )
    }

    /// Sends one request through [`app`] and returns its captured span fields.
    async fn request_span(uri: &str) -> HashMap<String, String> {
        let capture = Capture::default();
        let subscriber = Registry::default().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        app().oneshot(req).await.unwrap();

        let mut spans = capture.0.lock().unwrap();
        assert_eq!(spans.len(), 1, "expected exactly one http.request span");
        spans.pop().unwrap()
    }

    #[tokio::test]
    async fn nested_route_span_uses_full_template_and_omits_raw_path() {
        let f = request_span("/ipam/things/42?secret=x").await;
        assert_eq!(f["otel.name"], "GET /ipam/things/{id}");
        assert_eq!(f["otel.kind"], "server");
        assert_eq!(f["http.request.method"], "GET");
        assert_eq!(f["http.route"], "/ipam/things/{id}");
        assert!(!f.contains_key("url.path"));
        assert!(
            f.values()
                .all(|v| !v.contains("42") && !v.contains("secret"))
        );
        assert_eq!(f["http.response.status_code"], "200");
        assert!(!f.contains_key("otel.status_code"));
    }

    #[tokio::test]
    async fn server_error_marks_span_status_error() {
        let f = request_span("/boom").await;
        assert_eq!(f["http.response.status_code"], "500");
        assert_eq!(f["otel.status_code"], "error");
    }

    #[tokio::test]
    async fn client_error_leaves_span_status_unset() {
        let f = request_span("/denied").await;
        assert_eq!(f["http.response.status_code"], "403");
        assert!(!f.contains_key("otel.status_code"));
    }

    #[tokio::test]
    async fn unmatched_request_is_named_by_method_only() {
        let f = request_span("/nope/123").await;
        assert_eq!(f["otel.name"], "GET");
        assert!(!f.contains_key("http.route"));
        assert_eq!(f["http.response.status_code"], "404");
    }
}
