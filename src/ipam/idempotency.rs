//! Idempotency key support for mutating IPAM endpoints.
//!
//! Clients may send `Idempotency-Key: <opaque-string>` on the three
//! allocation endpoints to make retries safe:
//!
//! - `POST /ipam/cidr-blocks/{id}/allocate` (auto-allocate)
//! - `POST /ipam/cidr-blocks/{id}/allocate-specific`
//! - `POST /ipam/batch/allocate`
//!
//! Behavior:
//! - **Same key + same request body** → return the cached response
//!   (body + status) verbatim. Side effects run exactly once.
//! - **Same key + different request body** → `409 Conflict`. The key is
//!   bound to the *first* payload it saw; reusing it for a new payload
//!   is almost always a client bug.
//! - **No key** → no caching, behavior unchanged.
//!
//! Records are scoped per-endpoint (and per-cidr_block for the
//! `allocate*` endpoints), so the same key reused on a different
//! endpoint is a fresh request — not a conflict.

use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::error::{NetcidrError, Result};
use crate::ipam::models::IdempotencyRecord;
use crate::ipam::store::IpamStore;

/// Cached records expire after this window. Long enough for retry storms
/// (network blips, retries-with-backoff in clients) without unbounded
/// growth.
pub const TTL: Duration = Duration::hours(24);

/// Maximum body size we hash + persist. Allocation request bodies are
/// tiny; a hard ceiling here prevents an attacker from filling the
/// `idempotency_keys` table with huge cached payloads.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum Outcome {
    /// No key supplied; caller proceeds normally and does not store anything.
    NoKey,
    /// Key present and unseen; caller proceeds, then records the result.
    Proceed { key: String, request_hash: String },
    /// Key present and the cached request matches; caller returns the
    /// cached response without re-running the operation.
    Replay { status: u16, body: String },
    /// Key present but bound to a *different* request body; caller must
    /// return `409 Conflict`.
    Conflict,
}

/// Look up the `Idempotency-Key` header.
pub fn key_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Stable hex SHA-256 of the request body. Used to detect a key being
/// reused with a different payload.
pub fn hash_body(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

/// Decide whether to proceed with the operation, replay a cached
/// response, or reject as a conflict.
///
/// `tenant_id` scopes the lookup so the same key reused by a different
/// tenant is treated as a fresh request.
pub async fn check(
    store: &dyn IpamStore,
    tenant_id: &str,
    headers: &HeaderMap,
    scope: &str,
    body: &[u8],
) -> Result<Outcome> {
    let Some(key) = key_from_headers(headers) else {
        return Ok(Outcome::NoKey);
    };

    let request_hash = hash_body(body);

    if let Some(existing) = store.idempotency_get(tenant_id, &key, scope).await? {
        if existing.request_hash == request_hash {
            return Ok(Outcome::Replay {
                status: existing.status_code,
                body: existing.response_body,
            });
        }
        return Ok(Outcome::Conflict);
    }

    Ok(Outcome::Proceed { key, request_hash })
}

/// Persist a `(tenant_id, key, scope, request_hash) -> response` mapping.
/// Called after the operation succeeded *or* failed deterministically
/// (e.g. 4xx) so retries return the same outcome.
pub async fn record(
    store: &dyn IpamStore,
    tenant_id: &str,
    key: &str,
    scope: &str,
    request_hash: &str,
    status: u16,
    body: &str,
) -> Result<()> {
    let now = Utc::now();
    let expires = now + TTL;
    store
        .idempotency_put(&IdempotencyRecord {
            tenant_id: tenant_id.to_string(),
            key: key.to_string(),
            scope: scope.to_string(),
            request_hash: request_hash.to_string(),
            status_code: status,
            response_body: body.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        })
        .await
}

// ---------------------------------------------------------------------------
// Wire-format-agnostic helpers for use from operations.rs.
//
// The above check/record API caches raw HTTP response bytes and is
// scoped to HTTP callers. The helpers below cache serde-serialized
// domain values so non-HTTP callers (CLI, MCP) can also get replay
// protection. Status code is hardcoded to 200 in the stored record —
// operation-layer idempotency does not carry a wire-format status.
// ---------------------------------------------------------------------------

/// Stable hash of a serializable input, used to detect a key being
/// reused with a different logical request. Unlike `hash_body`, two
/// inputs that serialize to the same `serde_json` representation will
/// hash identically even if their original wire formats differed in
/// whitespace or field ordering.
///
/// `?Sized` allows slice references (e.g. `&[BatchAllocateItem]`).
pub fn input_hash<T: Serialize + ?Sized>(input: &T) -> Result<String> {
    let bytes = serde_json::to_vec(input)?;
    Ok(hash_body(&bytes))
}

/// Look up a cached response for `(tenant_id, key, scope)`.
///
/// - `Ok(Some(value))` — cached entry exists and `request_hash` matches.
///   Caller should return `value` as a replay without re-running the op.
/// - `Ok(None)` — no cached entry. Caller proceeds with the operation
///   and should call [`record_output`] when it succeeds.
/// - `Err(IdempotencyConflict { .. })` — cached entry exists but
///   `request_hash` differs. Caller surfaces the error to its frontend.
pub async fn try_replay<T: DeserializeOwned>(
    store: &dyn IpamStore,
    tenant_id: &str,
    key: &str,
    scope: &str,
    request_hash: &str,
) -> Result<Option<T>> {
    let Some(existing) = store.idempotency_get(tenant_id, key, scope).await? else {
        return Ok(None);
    };
    if existing.request_hash != request_hash {
        return Err(NetcidrError::IdempotencyConflict {
            key: key.to_string(),
            scope: scope.to_string(),
        });
    }
    let value = serde_json::from_str::<T>(&existing.response_body)?;
    Ok(Some(value))
}

/// Persist a freshly-computed `output` so subsequent calls with the
/// same `(tenant_id, key, scope, request_hash)` replay it instead of
/// re-running the operation. Failures are returned to the caller; the
/// caller decides whether to surface them or warn-and-continue.
pub async fn record_output<T: Serialize + ?Sized>(
    store: &dyn IpamStore,
    tenant_id: &str,
    key: &str,
    scope: &str,
    request_hash: &str,
    output: &T,
) -> Result<()> {
    let body = serde_json::to_string(output)?;
    let now = Utc::now();
    let expires = now + TTL;
    store
        .idempotency_put(&IdempotencyRecord {
            tenant_id: tenant_id.to_string(),
            key: key.to_string(),
            scope: scope.to_string(),
            request_hash: request_hash.to_string(),
            status_code: 200,
            response_body: body,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        })
        .await
}
