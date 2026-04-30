//! Idempotency key support for mutating IPAM endpoints.
//!
//! Clients may send `Idempotency-Key: <opaque-string>` on the three
//! allocation endpoints to make retries safe:
//!
//! - `POST /ipam/supernets/{id}/allocate` (auto-allocate)
//! - `POST /ipam/supernets/{id}/allocate-specific`
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
//! Records are scoped per-endpoint (and per-supernet for the
//! `allocate*` endpoints), so the same key reused on a different
//! endpoint is a fresh request — not a conflict.

use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use crate::error::Result;
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
pub async fn check(
    store: &dyn IpamStore,
    headers: &HeaderMap,
    scope: &str,
    body: &[u8],
) -> Result<Outcome> {
    let Some(key) = key_from_headers(headers) else {
        return Ok(Outcome::NoKey);
    };

    let request_hash = hash_body(body);

    if let Some(existing) = store.idempotency_get(&key, scope).await? {
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

/// Persist a `(key, scope, request_hash) -> response` mapping. Called
/// after the operation succeeded *or* failed deterministically (e.g.
/// 4xx) so retries return the same outcome.
pub async fn record(
    store: &dyn IpamStore,
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
