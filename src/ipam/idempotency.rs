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
//
// This module owns the persistence + helpers for idempotency keys.
// The wire-format-agnostic `try_replay<T>` / `record_output<T>` /
// `input_hash<T>` are the canonical API; they serialize domain values
// via serde_json and are consumed by `IpamOps::*_idempotent`.
// `key_from_headers` and `MAX_BODY_BYTES` stay here for HTTP callers.
//

/// Cached records expire after this window. Long enough for retry storms
/// (network blips, retries-with-backoff in clients) without unbounded
/// growth.
pub const TTL: Duration = Duration::hours(24);

/// Maximum body size we hash + persist. Allocation request bodies are
/// tiny; a hard ceiling here prevents an attacker from filling the
/// `idempotency_keys` table with huge cached payloads.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Look up the `Idempotency-Key` header. HTTP callers use this to
/// fish out the opaque caller-supplied string before forwarding it to
/// the appropriate `IpamOps::*_idempotent` method.
pub fn key_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Hex SHA-256 of arbitrary bytes. Internal helper for [`input_hash`].
fn hash_body(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

/// Stable hash of a serializable input, used to detect a key being
/// reused with a different logical request. Two inputs that serialize
/// to the same `serde_json` representation hash identically even if
/// their original wire formats differed in whitespace or field ordering.
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
