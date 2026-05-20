//! Role-based authorization extractors for Axum handlers.
//!
//! These extractors run *after* [`crate::auth::require_auth`] has populated
//! the [`AuthenticatedPrincipal`] extension. Each one checks
//! `principal.role >= min_role` and either yields the wrapped principal or
//! short-circuits with a 403 response. Per ADR-0002 they are deliberately
//! per-handler rather than per-router-group so adding a new IPAM endpoint
//! that omits a role gate is a compile error rather than a silent default.
//!
//! ```ignore
//! async fn list_things(
//!     Extension(ops): Extension<Arc<IpamOps>>,
//!     _: RequireReader,   // anyone authenticated with reader+ may call
//!     tenant: Tenant,
//! ) -> impl IntoResponse { ... }
//! ```
//!
//! Handlers that need the caller's identity (for audit) can bind it:
//! `RequireAdmin(principal): RequireAdmin`.
//!
//! ## Response shape
//!
//! Forbidden responses go through [`crate::error_presenter::present`] so
//! they share the `{ "error": "Forbidden" }` body and 403 status with any
//! handler-internal `NetcidrError::Forbidden`. The required and actual
//! roles are **never** echoed to the client — they are logged at WARN with
//! the caller's email so an operator can correlate denials.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Json, Response};
use serde::Serialize;

use crate::auth::{AuthenticatedPrincipal, Role};
use crate::error::NetcidrError;
use crate::error_presenter::present;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Build a JSON error response that matches the shape used by the IPAM
/// and /me handlers (`{ "error": "<msg>" }`). Kept private to this module
/// so the only public surface is the three extractors.
fn json_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: msg.to_string(),
        }),
    )
        .into_response()
}

/// Resolve the principal from request extensions and confirm it meets the
/// `required` role threshold. Shared by the three concrete extractors so
/// the policy lives in exactly one place.
///
/// Returns the wrapped principal on success, or a ready-to-return
/// [`Response`] on failure. Missing-principal yields 500 (it implies
/// [`crate::auth::require_auth`] did not run upstream — a wiring bug, not
/// a caller error); insufficient role yields 403 via the error presenter.
fn check_role(parts: &Parts, required: Role) -> Result<AuthenticatedPrincipal, Response> {
    let Some(principal) = parts.extensions.get::<AuthenticatedPrincipal>().cloned() else {
        // The auth middleware should have stashed the principal. If it
        // didn't, the router was wired without `require_auth` and we
        // should surface that as an operator-side problem, not a caller
        // 401 (which would suggest the caller can fix it by retrying
        // with a token).
        tracing::error!(
            required = required.as_str(),
            "role extractor invoked without an AuthenticatedPrincipal in request extensions \
             — this means `require_auth` is not layered on this route (wiring bug)"
        );
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error",
        ));
    };

    if principal.role >= required {
        return Ok(principal);
    }

    tracing::warn!(
        required = required.as_str(),
        actual = principal.role.as_str(),
        email = principal.email.as_deref().unwrap_or("<none>"),
        subject = %principal.subject,
        "rbac denied request"
    );

    let err = NetcidrError::Forbidden {
        required,
        actual: principal.role,
    };
    let presented = present(&err);
    let status =
        StatusCode::from_u16(presented.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Err(json_error(status, &presented.client_msg))
}

macro_rules! require_role_extractor {
    ($name:ident, $role:expr, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(pub AuthenticatedPrincipal);

        impl<S> FromRequestParts<S> for $name
        where
            S: Send + Sync,
        {
            type Rejection = Response;

            async fn from_request_parts(
                parts: &mut Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                check_role(parts, $role).map(Self)
            }
        }
    };
}

require_role_extractor!(
    RequireReader,
    Role::Reader,
    "Allow any authenticated principal whose role is at least `Reader`. \
     This is the lowest tier — only useful as an explicit assertion that \
     a handler *is* role-gated (the missing-principal 500 still applies)."
);

require_role_extractor!(
    RequireAllocator,
    Role::Allocator,
    "Require role >= `Allocator`. Denies callers configured as \
     `Reader` with 403."
);

require_role_extractor!(
    RequireAdmin,
    Role::Admin,
    "Require role == `Admin`. Denies callers configured as `Reader` or \
     `Allocator` with 403."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, PrincipalKind};
    use axum::http::Request;
    use http_body_util::BodyExt;

    fn principal_with(role: Role) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            kind: PrincipalKind::Oidc,
            subject: "sub-1".to_string(),
            email: Some("user@example.com".to_string()),
            audience: None,
            auth_method: AuthMethod::Oidc,
            pat_id: None,
            role,
        }
    }

    async fn parts_with_principal(p: Option<AuthenticatedPrincipal>) -> Parts {
        let mut req = Request::builder().body(()).unwrap();
        if let Some(principal) = p {
            req.extensions_mut().insert(principal);
        }
        let (parts, _) = req.into_parts();
        parts
    }

    async fn body_text(resp: Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap_or_default())
    }

    #[tokio::test]
    async fn reader_extractor_accepts_reader_allocator_and_admin() {
        for role in [Role::Reader, Role::Allocator, Role::Admin] {
            let mut parts = parts_with_principal(Some(principal_with(role))).await;
            let extracted = RequireReader::from_request_parts(&mut parts, &()).await;
            assert!(
                extracted.is_ok(),
                "RequireReader should accept role {role:?}"
            );
            assert_eq!(extracted.unwrap().0.role, role);
        }
    }

    #[tokio::test]
    async fn allocator_extractor_rejects_reader_with_403_forbidden() {
        let mut parts = parts_with_principal(Some(principal_with(Role::Reader))).await;
        let result = RequireAllocator::from_request_parts(&mut parts, &()).await;
        let err = result.err().expect("reader should be denied by RequireAllocator");
        let (status, body) = body_text(err).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Body MUST be the fixed "Forbidden" string — required/actual
        // roles must NOT appear in the response.
        assert!(
            body.contains("Forbidden") && !body.contains("Reader") && !body.contains("Allocator"),
            "403 body leaked role detail: {body}"
        );
    }

    #[tokio::test]
    async fn allocator_extractor_accepts_allocator_and_admin() {
        for role in [Role::Allocator, Role::Admin] {
            let mut parts = parts_with_principal(Some(principal_with(role))).await;
            assert!(
                RequireAllocator::from_request_parts(&mut parts, &())
                    .await
                    .is_ok(),
                "RequireAllocator should accept role {role:?}"
            );
        }
    }

    #[tokio::test]
    async fn admin_extractor_rejects_reader_and_allocator() {
        for role in [Role::Reader, Role::Allocator] {
            let mut parts = parts_with_principal(Some(principal_with(role))).await;
            let result = RequireAdmin::from_request_parts(&mut parts, &()).await;
            let err = result
                .err()
                .unwrap_or_else(|| panic!("role {role:?} should be denied by RequireAdmin"));
            let (status, _body) = body_text(err).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn admin_extractor_accepts_admin() {
        let mut parts = parts_with_principal(Some(principal_with(Role::Admin))).await;
        assert!(
            RequireAdmin::from_request_parts(&mut parts, &())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn missing_principal_yields_500_not_401() {
        // No principal extension set — this means require_auth did not
        // run upstream. We want a 500 (operator wiring bug) rather than
        // a 401 (which would suggest the caller can retry with a token).
        let mut parts = parts_with_principal(None).await;
        for extractor_result in [
            RequireReader::from_request_parts(&mut parts, &()).await.err(),
            RequireAllocator::from_request_parts(&mut parts, &())
                .await
                .err(),
            RequireAdmin::from_request_parts(&mut parts, &()).await.err(),
        ] {
            let resp = extractor_result.expect("missing principal should fail");
            let (status, body) = body_text(resp).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(body.contains("internal server error"));
        }
    }
}
