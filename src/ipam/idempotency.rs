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
use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::error::{NetcidrError, Result};
use crate::ipam::models::IdempotencyRecord;
use crate::ipam::store::{IdempotencyLookup, IpamStore, LockScope, Plan, TxUnit};
//
// This module owns the helpers for idempotency keys. `input_hash<T>`
// fingerprints a request; single-unit operations record their result in
// their own unit (`mutation::execute`), and multi-unit ones use the
// claim-first protocol below. `key_from_headers` and `MAX_BODY_BYTES`
// stay here for HTTP callers.
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

// ---------------------------------------------------------------------------
// Claim-first protocol for operations that span several units
// ---------------------------------------------------------------------------
//
// A Mutation records its idempotency result in its own unit (see
// `mutation::execute`). `batch_allocate` runs one unit per item, so it
// can't. Instead it claims the key in a unit of its own before doing any
// work, and completes the claim with the result afterwards:
//
//   claim → (run the operation) → complete      or, on failure, abandon
//
// A claim is an ordinary record with status [`PENDING`] that expires after
// [`PENDING_TTL`]. While it is live, a second request with the same key
// and body gets `IdempotencyInProgress` instead of running the operation
// again. If the process dies mid-operation the claim simply expires.

/// `status_code` of a record that has been claimed but not completed.
pub const PENDING: u16 = 0;

/// How long a claim blocks retries if it is never completed or abandoned
/// (e.g. the process died mid-batch). Comfortably longer than a full
/// batch of 100 items each waiting out the store's lock timeout.
pub const PENDING_TTL: Duration = Duration::minutes(15);

/// What the caller supplies to make a multi-unit operation idempotent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    pub key: String,
    pub scope: String,
    pub request_hash: String,
}

/// The outcome of [`claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim<T> {
    /// The key is now held by this request: run the operation, then
    /// [`complete`] or [`abandon`].
    Claimed,
    /// An earlier request with this key and body already completed; here
    /// is its result.
    Replay(T),
}

/// Whether `record` stopped counting at `now`. A timestamp that doesn't
/// parse counts as expired, so a damaged row can't wedge a key.
fn is_expired(record: &IdempotencyRecord, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(&record.expires_at).map_or(true, |at| at <= now)
}

fn key_scope(tenant_id: &str, spec: &KeySpec) -> LockScope {
    LockScope::IdempotencyKey {
        tenant_id: tenant_id.to_string(),
        key: spec.key.clone(),
        scope: spec.scope.clone(),
    }
}

/// Run one unit under the key's Lock Scope that looks up the key's record
/// and lets `decide` choose what to write.
async fn key_unit(
    store: &dyn IpamStore,
    tenant_id: &str,
    spec: &KeySpec,
    decide: impl FnOnce(Option<IdempotencyRecord>) -> Result<Plan> + Send + 'static,
) -> Result<String> {
    store
        .transact(TxUnit {
            scope: key_scope(tenant_id, spec),
            reads: vec![],
            idempotency: Some(IdempotencyLookup {
                tenant_id: tenant_id.to_string(),
                key: spec.key.clone(),
                scope: spec.scope.clone(),
            }),
            decide: Box::new(move |loaded| decide(loaded.idempotency)),
        })
        .await
}

fn record(
    tenant_id: &str,
    spec: &KeySpec,
    status_code: u16,
    response_body: String,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> IdempotencyRecord {
    IdempotencyRecord {
        tenant_id: tenant_id.to_string(),
        key: spec.key.clone(),
        scope: spec.scope.clone(),
        request_hash: spec.request_hash.clone(),
        status_code,
        response_body,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    }
}

/// Claim `spec.key` for this request.
///
/// - No live record → write a pending claim; `Claimed`.
/// - A record for a different request body → `IdempotencyConflict`.
/// - A live claim for the same body → `IdempotencyInProgress`.
/// - A completed record for the same body → `Replay` of its result.
pub async fn claim<T: DeserializeOwned>(
    store: &dyn IpamStore,
    now: DateTime<Utc>,
    tenant_id: &str,
    spec: &KeySpec,
) -> Result<Claim<T>> {
    let tenant = tenant_id.to_string();
    let owned = spec.clone();
    // The unit's output is the completed result to replay, if any.
    let replay = key_unit(store, tenant_id, spec, move |existing| {
        match existing.filter(|r| !is_expired(r, now)) {
            None => Ok(Plan {
                idempotency: Some(record(
                    &tenant,
                    &owned,
                    PENDING,
                    String::new(),
                    now,
                    now + PENDING_TTL,
                )),
                output_json: serde_json::to_string(&None::<String>)?,
                ..Plan::default()
            }),
            Some(r) if r.request_hash != owned.request_hash => {
                Err(NetcidrError::IdempotencyConflict {
                    key: owned.key,
                    scope: owned.scope,
                })
            }
            Some(r) if r.status_code == PENDING => Err(NetcidrError::IdempotencyInProgress),
            Some(r) => Ok(Plan {
                output_json: serde_json::to_string(&Some(r.response_body))?,
                ..Plan::default()
            }),
        }
    })
    .await?;
    match serde_json::from_str::<Option<String>>(&replay)? {
        None => Ok(Claim::Claimed),
        Some(body) => Ok(Claim::Replay(serde_json::from_str(&body)?)),
    }
}

/// Complete a claim: store `output` as the key's result for [`TTL`].
pub async fn complete<T: Serialize + ?Sized>(
    store: &dyn IpamStore,
    now: DateTime<Utc>,
    tenant_id: &str,
    spec: &KeySpec,
    output: &T,
) -> Result<()> {
    let done = record(
        tenant_id,
        spec,
        200,
        serde_json::to_string(output)?,
        now,
        now + TTL,
    );
    key_unit(store, tenant_id, spec, move |_| {
        Ok(Plan {
            idempotency: Some(done),
            ..Plan::default()
        })
    })
    .await
    .map(|_| ())
}

/// Give up a claim after the operation failed, so a retry runs it again
/// instead of waiting out [`PENDING_TTL`]. The claim is expired in place.
pub async fn abandon(
    store: &dyn IpamStore,
    now: DateTime<Utc>,
    tenant_id: &str,
    spec: &KeySpec,
) -> Result<()> {
    let expired = record(tenant_id, spec, PENDING, String::new(), now, now);
    key_unit(store, tenant_id, spec, move |_| {
        Ok(Plan {
            idempotency: Some(expired),
            ..Plan::default()
        })
    })
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::ipam::sqlite::SqliteStore;

    const TENANT: &str = "t@example.com";

    async fn store() -> SqliteStore {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    fn noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
    }

    fn spec(hash: &str) -> KeySpec {
        KeySpec {
            key: "k".to_string(),
            scope: "batch-allocate".to_string(),
            request_hash: hash.to_string(),
        }
    }

    async fn claim_at(store: &SqliteStore, now: DateTime<Utc>, hash: &str) -> Result<Claim<u32>> {
        claim(store, now, TENANT, &spec(hash)).await
    }

    #[tokio::test]
    async fn a_live_claim_blocks_the_same_request_and_conflicts_with_another() {
        let store = store().await;
        assert_eq!(claim_at(&store, noon(), "h").await.unwrap(), Claim::Claimed);
        assert!(matches!(
            claim_at(&store, noon(), "h").await,
            Err(NetcidrError::IdempotencyInProgress)
        ));
        assert!(matches!(
            claim_at(&store, noon(), "other").await,
            Err(NetcidrError::IdempotencyConflict { .. })
        ));
    }

    #[tokio::test]
    async fn a_completed_claim_replays_its_result() {
        let store = store().await;
        claim_at(&store, noon(), "h").await.unwrap();
        complete(&store, noon(), TENANT, &spec("h"), &7u32)
            .await
            .unwrap();
        assert_eq!(
            claim_at(&store, noon(), "h").await.unwrap(),
            Claim::Replay(7)
        );
        let record = store
            .idempotency_get(TENANT, "k", "batch-allocate")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.status_code, 200);
        assert_eq!(record.expires_at, (noon() + TTL).to_rfc3339());
    }

    #[tokio::test]
    async fn an_abandoned_or_expired_claim_can_be_claimed_again() {
        let store = store().await;
        claim_at(&store, noon(), "h").await.unwrap();
        abandon(&store, noon(), TENANT, &spec("h")).await.unwrap();
        assert_eq!(claim_at(&store, noon(), "h").await.unwrap(), Claim::Claimed);

        // Never completed: the claim lapses after PENDING_TTL, and then
        // even a different body may take the key.
        let later = noon() + PENDING_TTL;
        assert_eq!(
            claim_at(&store, later, "other").await.unwrap(),
            Claim::Claimed
        );
    }

    #[test]
    fn an_unparseable_expiry_counts_as_expired() {
        let record = IdempotencyRecord {
            tenant_id: TENANT.to_string(),
            key: "k".to_string(),
            scope: "s".to_string(),
            request_hash: "h".to_string(),
            status_code: PENDING,
            response_body: String::new(),
            created_at: String::new(),
            expires_at: "not a time".to_string(),
        };
        assert!(is_expired(&record, noon()));
    }
}
