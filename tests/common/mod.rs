//! Shared test helpers for HTTP-level IPAM tests.
//!
//! The HTTP integration tests in this repository run against `auth_mode: None`
//! routers built via `tower::ServiceExt::oneshot`. Production auth middleware
//! sets a `Tenant` extension on each request from the verified OIDC email
//! (or the bearer-token subject) — under `AuthMode::None` no extension is
//! ever set, so every IPAM handler would 401 on the `Tenant` extractor.
//!
//! This module exposes a synthetic middleware that reads an `X-Test-Tenant`
//! header and inserts a `Tenant` extension. Tests pass the header on every
//! request to drive a specific tenant identity end-to-end through handler →
//! ops → store, without bringing up real OIDC.

#![allow(dead_code)]

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, header},
    middleware::{self, Next},
    response::Response,
};
use netcidr::tenant::Tenant;

/// Header read by [`inject_test_tenant`] to populate the `Tenant` extension.
pub const TENANT_HEADER: &str = "X-Test-Tenant";

/// Default tenant for non-isolation tests.
pub const TEST_TENANT: &str = "test@example.com";

/// Test-only middleware: copies the `X-Test-Tenant` request header into a
/// `Tenant` extension so handlers that call `Tenant::from_request_parts`
/// see a tenant even though auth is disabled.
pub async fn inject_test_tenant(mut req: Request, next: Next) -> Response {
    let tenant = req
        .headers()
        .get(HeaderName::from_static("x-test-tenant"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| TEST_TENANT.to_string());
    req.extensions_mut().insert(Tenant(tenant));
    next.run(req).await
}

/// Wrap a router with `inject_test_tenant`.
pub fn with_test_tenant(router: axum::Router) -> axum::Router {
    router.layer(middleware::from_fn(inject_test_tenant))
}

/// Build a JSON request with a tenant header. `body` may be `None` for GET.
pub fn json_request(
    method: &str,
    uri: &str,
    tenant: &str,
    body: Option<&str>,
) -> axum::http::Request<Body> {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header(TENANT_HEADER, tenant);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
        .unwrap()
}
