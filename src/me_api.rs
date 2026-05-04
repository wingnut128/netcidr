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
use crate::ipam::models::{CreatePersonalAccessToken, PersonalAccessTokenSummary};
use crate::ipam::operations::IpamOps;
use crate::pat::{self, PatPepper};
use crate::validation;

/// Default token lifetime in days when `expires_in_days` is omitted.
const DEFAULT_EXPIRES_IN_DAYS: u32 = 90;

/// Hard upper bound on `expires_in_days`.
const MAX_EXPIRES_IN_DAYS: u32 = 365;

/// Maximum length of the user-supplied `name` field, in bytes.
const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    /// Number of days from now until the token expires. `None` defaults
    /// to [`DEFAULT_EXPIRES_IN_DAYS`]; values outside `1..=365` are 400.
    pub expires_in_days: Option<u32>,
}

/// One-time response to a successful mint. The `token` field is the
/// plaintext secret — surfaced exactly once and never again.
#[derive(Debug, Serialize, Deserialize)]
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

/// `GET /me/tokens` envelope. Mirrors the `SupernetList` shape used by
/// `/ipam/supernets` — `{ tokens: [...], count: N }`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenListResponse {
    pub tokens: Vec<PersonalAccessTokenSummary>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
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

#[instrument(skip_all, fields(owner_email = %principal.email.as_deref().unwrap_or("<none>")))]
async fn create_token(
    Extension(ops): Extension<Arc<IpamOps>>,
    Extension(pepper): Extension<Arc<PatPepper>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(body): Json<CreateTokenRequest>,
) -> Response {
    // 1. Validate name. `validate_text_field` rejects control chars and
    //    overlong inputs; we additionally require non-empty.
    let name = body.name.trim();
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "name must not be empty");
    }
    if let Err(e) = validation::validate_text_field(name, MAX_NAME_LEN) {
        return error_response(StatusCode::BAD_REQUEST, e.to_string());
    }

    // 2. Validate expires_in_days.
    let days = match body.expires_in_days {
        None => DEFAULT_EXPIRES_IN_DAYS,
        Some(0) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "expires_in_days must be at least 1",
            );
        }
        Some(n) if n > MAX_EXPIRES_IN_DAYS => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("expires_in_days must not exceed {MAX_EXPIRES_IN_DAYS}"),
            );
        }
        Some(n) => n,
    };

    // 3. Pull required identity fields off the principal. OIDC requires
    //    a verified email; the require_auth layer already enforces this
    //    for OIDC mode, but defend in depth.
    let owner_email = match principal.email.clone() {
        Some(e) => e,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                "OIDC principal has no verified email; cannot mint tokens",
            );
        }
    };
    let owner_sub = principal.subject.clone();

    // 4. Mint, compute timestamps, persist.
    let minted = pat::mint(pepper.as_ref());
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::days(days as i64)).to_rfc3339();

    let input = CreatePersonalAccessToken {
        tenant_id: owner_email.clone(),
        owner_sub,
        owner_email,
        name: name.to_string(),
        prefix: minted.prefix.clone(),
        token_hash: minted.hash.to_vec(),
        expires_at,
    };

    let row = match ops.store().pat_create(&input).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "pat_create failed");
            return map_pat_error(e);
        }
    };

    info!(pat_id = %row.id, "PAT minted");

    let resp = CreateTokenResponse {
        id: row.id,
        name: row.name,
        prefix: row.prefix,
        token: minted.plaintext,
        expires_at: row.expires_at,
        created_at: row.created_at,
    };
    (StatusCode::CREATED, Json(resp)).into_response()
}

#[instrument(skip_all, fields(owner_email = %principal.email.as_deref().unwrap_or("<none>")))]
async fn list_tokens(
    Extension(ops): Extension<Arc<IpamOps>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Response {
    let owner_email = match principal.email.clone() {
        Some(e) => e,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                "OIDC principal has no verified email",
            );
        }
    };

    match ops
        .store()
        .pat_list_for_owner(&owner_email, &principal.subject)
        .await
    {
        Ok(rows) => {
            // Soft-delete contract: revoked rows stay visible to their
            // owner with `revoked_at` set. Don't filter them out here.
            let tokens: Vec<PersonalAccessTokenSummary> =
                rows.into_iter().map(Into::into).collect();
            let count = tokens.len();
            Json(TokenListResponse { tokens, count }).into_response()
        }
        Err(e) => {
            warn!(error = %e, "pat_list_for_owner failed");
            map_pat_error(e)
        }
    }
}

#[instrument(skip_all, fields(pat_id = %id, owner_email = %principal.email.as_deref().unwrap_or("<none>")))]
async fn revoke_token(
    Extension(ops): Extension<Arc<IpamOps>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(id): Path<String>,
) -> Response {
    let owner_email = match principal.email.clone() {
        Some(e) => e,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                "OIDC principal has no verified email",
            );
        }
    };

    if let Err(e) = validation::validate_identifier(&id) {
        return error_response(StatusCode::BAD_REQUEST, e.to_string());
    }

    let now = chrono::Utc::now().to_rfc3339();
    match ops
        .store()
        .pat_revoke(&owner_email, &principal.subject, &id, &now)
        .await
    {
        // pat_revoke is idempotent on already-revoked rows by contract,
        // so a successful Ok(_) covers both first-revoke and re-revoke.
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        // Per spec: cross-tenant or unknown id → 404, never 403. Don't
        // leak whether the id exists in another user's bucket.
        Err(NetcidrError::PatNotFound(_)) => {
            error_response(StatusCode::NOT_FOUND, "token not found")
        }
        Err(e) => {
            warn!(error = %e, "pat_revoke failed");
            map_pat_error(e)
        }
    }
}

/// Map storage-layer errors to HTTP. Mirrors the conservative pattern in
/// `ipam_api`: never echo raw DB messages, and treat anything we don't
/// explicitly recognize as 500.
fn map_pat_error(err: NetcidrError) -> Response {
    match err {
        NetcidrError::InvalidInput(msg) | NetcidrError::InvalidCidr(msg) => {
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        NetcidrError::PatNotFound(_) => error_response(StatusCode::NOT_FOUND, "token not found"),
        NetcidrError::DatabaseError(_) => {
            tracing::error!(error = %err, "database error in /me/tokens");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
        _ => {
            tracing::error!(error = %err, "unexpected error in /me/tokens");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    }
}
