//! Shared test helpers for HTTP-level IPAM tests.
//!
//! The HTTP integration tests in this repository run against `auth_mode: None`
//! routers built via `tower::ServiceExt::oneshot`. Production auth middleware
//! sets both a `Tenant` and an `AuthenticatedPrincipal` extension on each
//! request — under `AuthMode::None` no extension is ever set, so every IPAM
//! handler would 401 on the `Tenant` extractor or 500 on the role extractors.
//!
//! This module exposes a synthetic middleware that reads an `X-Test-Tenant`
//! header and inserts both a `Tenant` and a matching `AuthenticatedPrincipal`
//! (with a configurable role via `X-Test-Role`, defaulting to `Admin`). Tests
//! pass the header on every request to drive a specific tenant identity
//! end-to-end through middleware → handler → ops → store, without bringing
//! up real OIDC.

#![allow(dead_code)]

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, header},
    middleware::{self, Next},
    response::Response,
};
use netcidr::auth::{AuthMethod, AuthenticatedPrincipal, PrincipalKind, Role};
use netcidr::tenant::Tenant;

/// Header read by [`inject_test_tenant`] to populate the `Tenant` extension.
pub const TENANT_HEADER: &str = "X-Test-Tenant";

/// Header read by [`inject_test_tenant`] to override the role on the
/// injected [`AuthenticatedPrincipal`]. Accepts `reader` / `allocator` /
/// `admin` (case-insensitive). Missing or unrecognised values fall through
/// to [`Role::Admin`] — the production back-compat default that keeps every
/// existing integration test passing without changes.
pub const ROLE_HEADER: &str = "X-Test-Role";

/// Default tenant for non-isolation tests.
pub const TEST_TENANT: &str = "test@example.com";

fn parse_role(s: &str) -> Option<Role> {
    match s.trim().to_ascii_lowercase().as_str() {
        "reader" => Some(Role::Reader),
        "allocator" => Some(Role::Allocator),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}

/// Test-only middleware: reads `X-Test-Tenant` and `X-Test-Role`, inserts
/// a `Tenant` extension and a synthesised `AuthenticatedPrincipal` whose
/// email matches the tenant and whose role matches the header (defaulting
/// to `Admin`). The principal is required by the per-handler `Require*`
/// extractors added in PR1 of #102.
pub async fn inject_test_tenant(mut req: Request, next: Next) -> Response {
    let tenant = req
        .headers()
        .get(HeaderName::from_static("x-test-tenant"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| TEST_TENANT.to_string());
    let role = req
        .headers()
        .get(HeaderName::from_static("x-test-role"))
        .and_then(|h| h.to_str().ok())
        .and_then(parse_role)
        .unwrap_or(Role::Admin);

    req.extensions_mut().insert(Tenant(tenant.clone()));
    req.extensions_mut().insert(AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: format!("test-sub-{tenant}"),
        email: Some(tenant),
        audience: None,
        auth_method: AuthMethod::Oidc,
        pat_id: None,
        role,
    });
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
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap()
}
