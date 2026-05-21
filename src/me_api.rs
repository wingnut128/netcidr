//! `/me/tokens` REST endpoints — let an OIDC-authenticated caller mint,
//! list, and revoke their own personal access tokens.
//!
//! ## Auth model
//!
//! The router itself is mounted in `api.rs` behind the standard
//! `require_auth` middleware (so an unauthenticated request 401s before
//! ever reaching these handlers) plus an *OIDC-only* guard middleware
//! that rejects PAT-authed and bearer-authed requests with 403. This
//! closes the PAT-mints-PAT privilege-escalation path described in the
//! design spec; static-bearer holders are similarly denied because they
//! have no OIDC identity to attach the new token to.
//!
//! Choosing middleware (approach B) over per-handler checks (approach A):
//! the codebase already layers `require_auth` per-router, so an
//! `oidc_only` peer-layer keeps the policy in one place and impossible
//! to forget on a future handler.
//!
//! ## Plaintext exposure
//!
//! `CreateTokenResponse.token` is the **only** field anywhere in this
//! module that carries the minted plaintext. It's emitted exactly once,
//! in the 201 response to `POST /me/tokens`. `GET /me/tokens` returns
//! `PersonalAccessTokenSummary` (no `token_hash`, no plaintext).

use std::sync::Arc;

use axum::{
    Extension, Router,
    extract::Path,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

use crate::auth::{AuthMethod, AuthenticatedPrincipal};
use crate::error::NetcidrError;
use crate::error_presenter::{LogLevel, present};
use crate::ipam::models::PersonalAccessTokenSummary;
use crate::pat_lifecycle::{CreatePatRequest, MintForPrincipalError, PatLifecycle};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CreateTokenRequest {
    /// Human-readable label for the token (shown in the UI / list response).
    pub name: String,
    /// Number of days from now until the token expires. `None` defaults
    /// to the lifecycle default; values outside `1..=365` are 400.
    pub expires_in_days: Option<u32>,
}

impl From<CreateTokenRequest> for CreatePatRequest {
    fn from(r: CreateTokenRequest) -> Self {
        Self {
            name: r.name,
            expires_in_days: r.expires_in_days,
            role: None,
        }
    }
}

/// One-time response to a successful mint. The `token` field is the
/// plaintext secret — surfaced exactly once and never again.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CreateTokenResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    /// Plaintext `ncdr_pat_…` secret. Returned once on mint; never
    /// stored, never re-fetchable. Clients MUST persist this immediately.
    pub token: String,
    pub expires_at: String,
    pub created_at: String,
}

/// `GET /me/tokens` envelope. Mirrors the `CidrBlockList` shape used by
/// `/ipam/cidr-blocks` — `{ tokens: [...], count: N }`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct TokenListResponse {
    pub tokens: Vec<PersonalAccessTokenSummary>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
struct ErrorBody {
    error: String,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: msg.into() })).into_response()
}

/// Reject any request whose principal is not OIDC-authenticated. This
/// guard runs *after* `require_auth` (which inserts the principal into
/// request extensions); a missing principal here implies a wiring bug,
/// not a bad caller, so we 500 rather than 401 to make it obvious.
pub async fn require_oidc(request: axum::extract::Request, next: Next) -> Response {
    match request.extensions().get::<AuthenticatedPrincipal>() {
        Some(p) if p.auth_method == AuthMethod::Oidc => next.run(request).await,
        Some(_) => (
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "OIDC authentication required to manage personal access tokens".to_string(),
            }),
        )
            .into_response(),
        None => {
            // require_auth should have populated this; if not, the
            // /me router has been misconfigured upstream.
            warn!("/me router reached without an authenticated principal");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Build the `/me/tokens` router. Caller layers `require_auth` *outside*
/// this router; `require_oidc` is layered *inside* so principals are
/// already resolved by the time it runs.
///
/// Returned at the absolute path level (`/me/tokens`) rather than nested
/// under `/me` so we don't collide with the existing `GET /me` handler
/// in `api.rs` (which serves the unauthenticated identity probe and
/// must stay at exactly `/me`).
pub fn create_me_router() -> Router {
    Router::new()
        .route("/me/tokens", post(create_token).get(list_tokens))
        .route("/me/tokens/{id}", delete(revoke_token))
        .layer(middleware::from_fn(require_oidc))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/me/tokens",
    request_body = CreateTokenRequest,
    responses(
        (status = 201, description = "PAT minted. The plaintext `token` is returned exactly once.", body = CreateTokenResponse),
        (status = 400, description = "Invalid request body"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "OIDC authentication required (PAT and static-bearer auth are rejected here)"),
    ),
    security(("bearerAuth" = [])),
    tag = "auth"
))]
#[instrument(skip_all, fields(owner_email = %principal.email.as_deref().unwrap_or("<none>")))]
pub(crate) async fn create_token(
    Extension(lifecycle): Extension<Arc<PatLifecycle>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(body): Json<CreateTokenRequest>,
) -> Response {
    let minted = match lifecycle.mint_for_principal(&principal, body.into()).await {
        Ok(minted) => minted,
        Err(e) => return map_principal_error(e, "mint token"),
    };

    info!(pat_id = %minted.summary.id, "PAT minted");

    let resp = CreateTokenResponse {
        id: minted.summary.id,
        name: minted.summary.name,
        prefix: minted.summary.prefix,
        token: minted.plaintext,
        expires_at: minted.summary.expires_at,
        created_at: minted.summary.created_at,
    };
    (StatusCode::CREATED, Json(resp)).into_response()
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/me/tokens",
    responses(
        (status = 200, description = "All PATs (including revoked) owned by the caller", body = TokenListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "OIDC authentication required"),
    ),
    security(("bearerAuth" = [])),
    tag = "auth"
))]
#[instrument(skip_all, fields(owner_email = %principal.email.as_deref().unwrap_or("<none>")))]
pub(crate) async fn list_tokens(
    Extension(lifecycle): Extension<Arc<PatLifecycle>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Response {
    match lifecycle.list_for_principal(&principal).await {
        Ok(tokens) => {
            // Soft-delete contract: revoked rows stay visible to their
            // owner with `revoked_at` set. Don't filter them out here.
            let count = tokens.len();
            Json(TokenListResponse { tokens, count }).into_response()
        }
        Err(e) => map_principal_error(e, "list tokens"),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    delete,
    path = "/me/tokens/{id}",
    params(
        ("id" = String, Path, description = "PAT id (from the create/list response)"),
    ),
    responses(
        (status = 204, description = "Token revoked (idempotent — already-revoked tokens also return 204)"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "OIDC authentication required"),
        (status = 404, description = "Token id not found in the caller's bucket"),
    ),
    security(("bearerAuth" = [])),
    tag = "auth"
))]
#[instrument(skip_all, fields(pat_id = %id, owner_email = %principal.email.as_deref().unwrap_or("<none>")))]
pub(crate) async fn revoke_token(
    Extension(lifecycle): Extension<Arc<PatLifecycle>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(id): Path<String>,
) -> Response {
    // pat_revoke is idempotent on already-revoked rows by contract,
    // so a successful Ok(_) covers both first-revoke and re-revoke.
    // PatNotFound (including cross-tenant ids by spec) flows through
    // map_pat_error → presenter → 404 "token not found" without
    // echoing the id; never 403.
    match lifecycle.revoke_for_principal(&principal, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_principal_error(e, "revoke token"),
    }
}

/// Map a `MintForPrincipalError` to an HTTP response. NoVerifiedEmail
/// surfaces as 403 (the auth layer should have caught it, but the
/// lifecycle defends in depth). Lifecycle errors go through the shared
/// presenter and inherit its scrubbing.
fn map_principal_error(err: MintForPrincipalError, action: &str) -> Response {
    match err {
        MintForPrincipalError::NoVerifiedEmail => error_response(
            StatusCode::FORBIDDEN,
            format!("OIDC principal has no verified email; cannot {action}"),
        ),
        MintForPrincipalError::Lifecycle(e) => {
            warn!(error = %e, action = %action, "pat operation failed");
            map_pat_error(e)
        }
    }
}

/// Map storage-layer errors to HTTP via the shared error presenter.
/// Identical classification, scrubbing, and log policy as `ipam_api`.
fn map_pat_error(err: NetcidrError) -> Response {
    let p = present(&err);
    if p.log_level == LogLevel::Error {
        tracing::error!(error = %err, "error in /me/tokens");
    }
    let status = StatusCode::from_u16(p.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    error_response(status, p.client_msg)
}
