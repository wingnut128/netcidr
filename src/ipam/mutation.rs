//! Mutations: IPAM writes expressed as pure decisions (ADR-0007).
//!
//! A [`Mutation`] names its [`LockScope`], declares the reads it needs, and
//! decides — synchronously, without touching storage — what to write. Each
//! write is a [`Change`], which cannot exist without the audit fact that
//! records it. [`execute`] turns a Mutation into one
//! [`IpamStore::transact`] unit, so the change, its audit rows, and its
//! idempotency record commit together or not at all.

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use serde::{Serialize, de::DeserializeOwned};

use crate::audit_context::AuditContext;
use crate::error::{NetcidrError, Result};
use crate::ipam::idempotency::TTL;
use crate::ipam::models::{
    Allocation, AllocationStatus, AuditEntry, CidrBlock, HostnamePointer, IdempotencyRecord,
    PersonalAccessToken, UserRecord,
};
use crate::ipam::operations::IdempotentOutcome;
use crate::ipam::store::{
    IdempotencyLookup, IpamStore, Loaded, LockScope, Plan, Read, Rows, TxUnit, Write,
};

// ---------------------------------------------------------------------------
// Time and identity, injected so decisions are deterministic under test
// ---------------------------------------------------------------------------

/// Source of "now" for decisions.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Source of new record ids for decisions.
pub trait IdSource: Send + Sync {
    fn new_id(&self) -> String;
}

/// Random v4 UUIDs.
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidIds;

impl IdSource for UuidIds {
    fn new_id(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

/// Everything a decision may know beyond its reads: the time, the caller,
/// and a source of new ids. Captured before the unit runs, because the
/// task-local audit context is not visible on the store's worker thread.
pub struct DecideCtx {
    now: DateTime<Utc>,
    caller: AuditContext,
    ids: Arc<dyn IdSource>,
}

impl DecideCtx {
    pub fn new(now: DateTime<Utc>, caller: AuditContext, ids: Arc<dyn IdSource>) -> Self {
        Self { now, caller, ids }
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }

    pub fn caller(&self) -> &AuditContext {
        &self.caller
    }

    /// Who is making the change, for `*_by` columns and history rows: the
    /// caller's email, else their subject, else `"cli"`.
    pub fn actor(&self) -> String {
        self.caller
            .caller_email
            .clone()
            .or_else(|| self.caller.caller_sub.clone())
            .unwrap_or_else(|| "cli".to_string())
    }

    pub fn new_id(&self) -> String {
        self.ids.new_id()
    }
}

// ---------------------------------------------------------------------------
// Typed reads
// ---------------------------------------------------------------------------

/// A typed handle to one declared read; redeem it with [`Snapshot::get`].
pub struct Handle<T> {
    index: usize,
    _row: PhantomData<fn() -> T>,
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Handle<T> {}

impl<T> std::fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Handle").field(&self.index).finish()
    }
}

/// The reads a Mutation declares, in order.
#[derive(Debug, Default)]
pub struct ReadSet {
    reads: Vec<Read>,
}

impl ReadSet {
    fn push<T>(&mut self, read: Read) -> Handle<T> {
        self.reads.push(read);
        Handle {
            index: self.reads.len() - 1,
            _row: PhantomData,
        }
    }

    /// The cidr block `id` in `tenant_id`, or `None` if it doesn't exist
    /// there.
    pub fn cidr_block(&mut self, tenant_id: &str, id: &str) -> Handle<Option<CidrBlock>> {
        self.push(Read::CidrBlock {
            tenant_id: tenant_id.to_string(),
            id: id.to_string(),
        })
    }

    /// All of `tenant_id`'s cidr blocks, oldest first.
    pub fn cidr_blocks(&mut self, tenant_id: &str) -> Handle<Vec<CidrBlock>> {
        self.push(Read::CidrBlocks {
            tenant_id: tenant_id.to_string(),
        })
    }

    /// The allocation `id` in `tenant_id` (with tags), or `None`.
    pub fn allocation(&mut self, tenant_id: &str, id: &str) -> Handle<Option<Allocation>> {
        self.push(Read::Allocation {
            tenant_id: tenant_id.to_string(),
            id: id.to_string(),
        })
    }

    /// The user with this (lowercased) email, or `None`.
    pub fn user(&mut self, email: &str) -> Handle<Option<UserRecord>> {
        self.push(Read::User {
            email: email.to_string(),
        })
    }

    /// Every user, ordered by email.
    pub fn users(&mut self) -> Handle<Vec<UserRecord>> {
        self.push(Read::Users)
    }

    /// How many users are active platform admins.
    pub fn active_platform_admin_count(&mut self) -> Handle<u64> {
        self.push(Read::ActivePlatformAdminCount)
    }

    /// Whether the bootstrap marker `key` has been written.
    pub fn bootstrap_marker(&mut self, key: &str) -> Handle<bool> {
        self.push(Read::BootstrapMarker {
            key: key.to_string(),
        })
    }

    /// The PAT `id`, only if it belongs to `owner_sub` in `tenant_id`.
    pub fn pat(
        &mut self,
        tenant_id: &str,
        owner_sub: &str,
        id: &str,
    ) -> Handle<Option<PersonalAccessToken>> {
        self.push(Read::Pat {
            tenant_id: tenant_id.to_string(),
            owner_sub: owner_sub.to_string(),
            id: id.to_string(),
        })
    }

    /// How many of an owner's PATs are neither revoked nor expired at `now`.
    pub fn active_pat_count(&mut self, tenant_id: &str, owner_sub: &str, now: &str) -> Handle<u64> {
        self.push(Read::ActivePatCount {
            tenant_id: tenant_id.to_string(),
            owner_sub: owner_sub.to_string(),
            now: now.to_string(),
        })
    }

    /// The live hostname pointer for `(ip_address, hostname)` in
    /// `tenant_id`, or `None`.
    pub fn hostname_pointer(
        &mut self,
        tenant_id: &str,
        ip_address: &str,
        hostname: &str,
    ) -> Handle<Option<HostnamePointer>> {
        self.push(Read::HostnamePointer {
            tenant_id: tenant_id.to_string(),
            ip_address: ip_address.to_string(),
            hostname: hostname.to_string(),
        })
    }

    /// A cidr block's allocations in `statuses` (with tags), ordered by
    /// network address.
    pub fn allocations_in_block(
        &mut self,
        tenant_id: &str,
        cidr_block_id: &str,
        statuses: &[AllocationStatus],
    ) -> Handle<Vec<Allocation>> {
        self.push(Read::AllocationsInBlock {
            tenant_id: tenant_id.to_string(),
            cidr_block_id: cidr_block_id.to_string(),
            statuses: statuses.to_vec(),
        })
    }
}

/// A row type a [`Handle`] can resolve to.
pub trait FromRows: Sized {
    fn from_rows(rows: &Rows) -> Option<&Self>;
}

impl FromRows for Option<CidrBlock> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::CidrBlock(block) => Some(block),
            _ => None,
        }
    }
}

impl FromRows for Vec<CidrBlock> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::CidrBlocks(blocks) => Some(blocks),
            _ => None,
        }
    }
}

impl FromRows for Option<UserRecord> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::User(user) => Some(user),
            _ => None,
        }
    }
}

impl FromRows for Vec<UserRecord> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::Users(users) => Some(users),
            _ => None,
        }
    }
}

impl FromRows for Option<PersonalAccessToken> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::Pat(pat) => Some(pat),
            _ => None,
        }
    }
}

impl FromRows for u64 {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::Count(n) => Some(n),
            _ => None,
        }
    }
}

impl FromRows for bool {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::Flag(flag) => Some(flag),
            _ => None,
        }
    }
}

impl FromRows for Option<Allocation> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::Allocation(alloc) => Some(alloc),
            _ => None,
        }
    }
}

impl FromRows for Vec<Allocation> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::Allocations(allocs) => Some(allocs),
            _ => None,
        }
    }
}

impl FromRows for Option<HostnamePointer> {
    fn from_rows(rows: &Rows) -> Option<&Self> {
        match rows {
            Rows::HostnamePointer(pointer) => Some(pointer),
            _ => None,
        }
    }
}

/// The rows a unit read, under its lock.
#[derive(Debug, Default)]
pub struct Snapshot {
    rows: Vec<Rows>,
}

impl Snapshot {
    /// Build a snapshot from rows in read order. Used by the executor, and
    /// by tests that exercise a decision without a database.
    pub fn new(rows: Vec<Rows>) -> Self {
        Self { rows }
    }

    /// The rows for `handle`. A handle always matches its own read, so a
    /// mismatch means the snapshot came from a different `ReadSet`.
    pub fn get<T: FromRows>(&self, handle: Handle<T>) -> Result<&T> {
        self.rows
            .get(handle.index)
            .and_then(T::from_rows)
            .ok_or_else(|| {
                NetcidrError::DatabaseError(format!(
                    "read handle {} does not match the snapshot",
                    handle.index
                ))
            })
    }
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// The audit record of a Change. The tenant, time, and caller are filled in
/// from the unit and its [`DecideCtx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFact {
    pub action: &'static str,
    pub entity_type: &'static str,
    pub entity_id: String,
    pub details: Option<String>,
}

impl AuditFact {
    fn into_entry(self, tenant_id: &str, cx: &DecideCtx) -> AuditEntry {
        let caller = cx.caller().clone();
        AuditEntry {
            // Assigned by the database.
            id: String::new(),
            tenant_id: tenant_id.to_string(),
            entity_type: self.entity_type.to_string(),
            entity_id: self.entity_id,
            action: self.action.to_string(),
            details: self.details,
            timestamp: cx.now().to_rfc3339(),
            caller_sub: caller.caller_sub,
            caller_email: caller.caller_email,
            source_ip: caller.source_ip,
            request_id: caller.request_id,
            auth_method: caller.auth_method.unwrap_or_else(|| "oidc".to_string()),
            pat_id: caller.pat_id,
        }
    }
}

/// One write together with the audit fact that records it.
#[derive(Debug, Clone)]
pub struct Change {
    write: Write,
    also: Vec<Write>,
    audit: AuditFact,
}

impl Change {
    pub fn new(write: Write, audit: AuditFact) -> Self {
        Self {
            write,
            also: Vec::new(),
            audit,
        }
    }

    /// Another row written as part of the same change, applied after the
    /// primary write and recorded by the same audit fact — e.g. the history
    /// entry that accompanies a hostname pointer write.
    pub fn also(mut self, write: Write) -> Self {
        self.also.push(write);
        self
    }

    /// Every write in this change, primary first.
    pub fn writes(&self) -> impl Iterator<Item = &Write> {
        std::iter::once(&self.write).chain(&self.also)
    }

    pub fn audit(&self) -> &AuditFact {
        &self.audit
    }
}

/// What a Mutation concludes: its result plus the Changes to apply, applied
/// completely or not at all.
#[derive(Debug, Clone)]
pub struct Decision<T> {
    output: T,
    changes: Vec<Change>,
}

impl<T> Decision<T> {
    /// A decision that writes at least one Change.
    pub fn new(output: T, first: Change) -> Self {
        Self {
            output,
            changes: vec![first],
        }
    }

    /// Add another Change.
    pub fn and(mut self, change: Change) -> Self {
        self.changes.push(change);
        self
    }

    /// A decision that writes nothing (and so records no audit row), e.g.
    /// revoking an already-revoked token.
    pub fn unchanged(output: T) -> Self {
        Self {
            output,
            changes: Vec::new(),
        }
    }

    pub fn output(&self) -> &T {
        &self.output
    }

    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
}

/// A single IPAM write operation, expressed as a pure decision over data
/// read under its Lock Scope.
pub trait Mutation: Send + 'static {
    /// The caller-facing result. Serialized so a replayed idempotent request
    /// returns exactly what the first one did.
    type Output: Serialize + DeserializeOwned + Send + 'static;
    /// The typed handles returned by [`reads`](Self::reads).
    type Reads: Send + 'static;

    fn scope(&self) -> LockScope;

    /// Declare the reads `decide` needs.
    fn reads(&self, set: &mut ReadSet) -> Self::Reads;

    /// Decide what to write. Runs under the lock with no access to storage.
    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<Self::Output>>;
}

/// Makes a Mutation idempotent under a caller-supplied key: a retry with the
/// same request replays the first result; the same key with a different
/// request is an `IdempotencyConflict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencySpec {
    pub key: String,
    pub scope: String,
    pub request_hash: String,
}

/// Run `mutation` for `tenant_id` as one transaction unit.
pub async fn execute<M: Mutation>(
    store: &dyn IpamStore,
    clock: &dyn Clock,
    ids: Arc<dyn IdSource>,
    tenant_id: &str,
    mutation: M,
    idempotency: Option<IdempotencySpec>,
) -> Result<IdempotentOutcome<M::Output>> {
    let cx = DecideCtx::new(clock.now(), crate::audit_context::current(), ids);
    let mut set = ReadSet::default();
    let handles = mutation.reads(&mut set);
    let scope = mutation.scope();
    let lookup = idempotency.as_ref().map(|spec| IdempotencyLookup {
        tenant_id: tenant_id.to_string(),
        key: spec.key.clone(),
        scope: spec.scope.clone(),
    });

    let replayed = Arc::new(AtomicBool::new(false));
    let replay_flag = Arc::clone(&replayed);
    let tenant = tenant_id.to_string();
    let decide = Box::new(move |loaded: Loaded| -> Result<Plan> {
        if let (Some(spec), Some(existing)) = (&idempotency, &loaded.idempotency) {
            if existing.request_hash != spec.request_hash {
                return Err(NetcidrError::IdempotencyConflict {
                    key: spec.key.clone(),
                    scope: spec.scope.clone(),
                });
            }
            replay_flag.store(true, Ordering::Relaxed);
            return Ok(Plan {
                output_json: existing.response_body.clone(),
                ..Plan::default()
            });
        }

        let decision = mutation.decide(handles, &Snapshot::new(loaded.rows), &cx)?;
        let output_json = serde_json::to_string(&decision.output)?;
        let mut writes = Vec::new();
        let mut audits = Vec::new();
        for change in decision.changes {
            writes.push(change.write);
            writes.extend(change.also);
            audits.push(change.audit.into_entry(&tenant, &cx));
        }
        let record = idempotency.map(|spec| IdempotencyRecord {
            tenant_id: tenant.clone(),
            key: spec.key,
            scope: spec.scope,
            request_hash: spec.request_hash,
            status_code: 200,
            response_body: output_json.clone(),
            created_at: cx.now().to_rfc3339(),
            expires_at: (cx.now() + TTL).to_rfc3339(),
        });
        Ok(Plan {
            writes,
            audits,
            idempotency: record,
            output_json,
        })
    });

    let output_json = store
        .transact(TxUnit {
            scope,
            reads: set.reads,
            idempotency: lookup,
            decide,
        })
        .await?;
    let output = serde_json::from_str(&output_json)?;
    Ok(if replayed.load(Ordering::Relaxed) {
        IdempotentOutcome::Replayed(output)
    } else {
        IdempotentOutcome::Fresh(output)
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use chrono::TimeZone;

    use super::*;
    use crate::ipam::models::CreateCidrBlock;
    use crate::ipam::operations::IpamOps;
    use crate::ipam::sqlite::SqliteStore;

    const TENANT: &str = "t@example.com";

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Default)]
    struct SeqIds(AtomicUsize);
    impl IdSource for SeqIds {
        fn new_id(&self) -> String {
            format!("id-{}", self.0.fetch_add(1, Ordering::Relaxed))
        }
    }

    fn noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
    }

    /// Reads one cidr block and reports its name; writes nothing.
    struct NameOf(String);

    impl Mutation for NameOf {
        type Output = Option<String>;
        type Reads = Handle<Option<CidrBlock>>;

        fn scope(&self) -> LockScope {
            LockScope::CidrBlock {
                tenant_id: TENANT.to_string(),
                cidr_block_id: self.0.clone(),
            }
        }

        fn reads(&self, set: &mut ReadSet) -> Self::Reads {
            set.cidr_block(TENANT, &self.0)
        }

        fn decide(
            self,
            block: Self::Reads,
            snapshot: &Snapshot,
            _cx: &DecideCtx,
        ) -> Result<Decision<Self::Output>> {
            let block = snapshot
                .get(block)?
                .as_ref()
                .ok_or_else(|| NetcidrError::CidrBlockNotFound(self.0.clone()))?;
            Ok(Decision::unchanged(block.name.clone()))
        }
    }

    async fn ops_with_block() -> (IpamOps, Arc<dyn IpamStore>, String) {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        let store: Arc<dyn IpamStore> = Arc::new(store);
        let ops = IpamOps::with_clock_and_ids(
            Arc::clone(&store),
            Arc::new(FixedClock(noon())),
            Arc::new(SeqIds::default()),
        );
        let block = ops
            .create_cidr_block(
                TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: Some("Corp".to_string()),
                    description: None,
                },
            )
            .await
            .unwrap();
        (ops, store, block.id)
    }

    fn spec(hash: &str) -> IdempotencySpec {
        IdempotencySpec {
            key: "key-1".to_string(),
            scope: "name-of".to_string(),
            request_hash: hash.to_string(),
        }
    }

    #[tokio::test]
    async fn run_returns_the_decided_output() {
        let (ops, _store, id) = ops_with_block().await;
        let out = ops.run(TENANT, NameOf(id), None).await.unwrap();
        assert_eq!(out, IdempotentOutcome::Fresh(Some("Corp".to_string())));
    }

    #[tokio::test]
    async fn run_replays_a_repeated_idempotent_request_and_rejects_a_changed_one() {
        let (ops, store, id) = ops_with_block().await;

        let first = ops.run(TENANT, NameOf(id.clone()), Some(spec("h1"))).await;
        assert_eq!(
            first.unwrap(),
            IdempotentOutcome::Fresh(Some("Corp".to_string()))
        );

        let record = store
            .idempotency_get(TENANT, "key-1", "name-of")
            .await
            .unwrap()
            .expect("record committed with the unit");
        assert_eq!(record.response_body, "\"Corp\"");
        assert_eq!(record.created_at, noon().to_rfc3339());
        assert_eq!(record.expires_at, (noon() + TTL).to_rfc3339());

        let again = ops.run(TENANT, NameOf(id.clone()), Some(spec("h1"))).await;
        assert_eq!(
            again.unwrap(),
            IdempotentOutcome::Replayed(Some("Corp".to_string()))
        );

        let changed = ops.run(TENANT, NameOf(id), Some(spec("h2"))).await;
        assert!(matches!(
            changed,
            Err(NetcidrError::IdempotencyConflict { .. })
        ));
    }

    #[tokio::test]
    async fn a_failed_decision_records_no_idempotency_result() {
        let (ops, store, _id) = ops_with_block().await;
        let err = ops
            .run(TENANT, NameOf("missing".to_string()), Some(spec("h1")))
            .await
            .unwrap_err();
        assert!(matches!(err, NetcidrError::CidrBlockNotFound(_)));
        assert_eq!(
            store
                .idempotency_get(TENANT, "key-1", "name-of")
                .await
                .unwrap(),
            None
        );
    }

    /// Inserts two cidr blocks as one Change: the second rides along via
    /// `also`.
    struct PairOfBlocks;

    impl Mutation for PairOfBlocks {
        type Output = ();
        type Reads = ();

        fn scope(&self) -> LockScope {
            LockScope::Tenant {
                tenant_id: TENANT.to_string(),
            }
        }

        fn reads(&self, _set: &mut ReadSet) -> Self::Reads {}

        fn decide(self, _: (), _: &Snapshot, cx: &DecideCtx) -> Result<Decision<()>> {
            let block = |cidr: &str| {
                CidrBlock::from_input(
                    TENANT,
                    &CreateCidrBlock {
                        cidr: cidr.to_string(),
                        name: None,
                        description: None,
                    },
                    cx.new_id(),
                    cx.now(),
                )
            };
            let change = Change::new(
                Write::InsertCidrBlock(block("10.0.0.0/8")?),
                AuditFact {
                    action: "pair",
                    entity_type: "cidr_block",
                    entity_id: "pair".to_string(),
                    details: None,
                },
            )
            .also(Write::InsertCidrBlock(block("172.16.0.0/12")?));
            assert_eq!(change.writes().count(), 2);
            Ok(Decision::new((), change))
        }
    }

    #[tokio::test]
    async fn a_change_commits_its_extra_writes_under_one_audit_row() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        let store: Arc<dyn IpamStore> = Arc::new(store);
        let ops = IpamOps::new(Arc::clone(&store));

        ops.run(TENANT, PairOfBlocks, None).await.unwrap();

        assert_eq!(store.list_cidr_blocks(TENANT).await.unwrap().len(), 2);
        let audit = store
            .query_audit(TENANT, &crate::ipam::models::AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "pair");
    }

    #[test]
    fn a_handle_from_another_read_set_is_an_error() {
        let mut set = ReadSet::default();
        let _first = set.cidr_block(TENANT, "a");
        let second = set.cidr_block(TENANT, "b");
        let snapshot = Snapshot::new(vec![Rows::CidrBlock(None)]);
        assert!(snapshot.get(second).is_err());
    }

    #[test]
    fn handles_index_reads_in_declaration_order() {
        let mut set = ReadSet::default();
        let a = set.cidr_block(TENANT, "a");
        let b = set.cidr_block(TENANT, "b");
        let snapshot = Snapshot::new(vec![
            Rows::CidrBlock(None),
            Rows::CidrBlock(Some(CidrBlock {
                id: "b".to_string(),
                tenant_id: TENANT.to_string(),
                cidr: "10.0.0.0/8".to_string(),
                network_address: "10.0.0.0".to_string(),
                broadcast_address: "10.255.255.255".to_string(),
                prefix_length: 8,
                total_hosts: 16_777_216,
                name: None,
                description: None,
                ip_version: 4,
                created_at: String::new(),
                updated_at: String::new(),
            })),
        ]);
        assert!(snapshot.get(a).unwrap().is_none());
        assert_eq!(snapshot.get(b).unwrap().as_ref().unwrap().id, "b");
        assert_eq!(
            set.reads[1],
            Read::CidrBlock {
                tenant_id: TENANT.to_string(),
                id: "b".to_string()
            }
        );
    }

    #[test]
    fn audit_facts_take_tenant_time_and_caller_from_the_unit() {
        let caller = AuditContext {
            caller_sub: Some("sub-1".to_string()),
            caller_email: Some("a@example.com".to_string()),
            source_ip: Some("192.0.2.1".to_string()),
            request_id: Some("req-1".to_string()),
            auth_method: Some("pat".to_string()),
            pat_id: Some("pat-1".to_string()),
        };
        let cx = DecideCtx::new(noon(), caller, Arc::new(SeqIds::default()));
        let entry = AuditFact {
            action: "allocate",
            entity_type: "allocation",
            entity_id: "alloc-1".to_string(),
            details: Some("10.0.1.0/24".to_string()),
        }
        .into_entry(TENANT, &cx);

        assert_eq!(entry.tenant_id, TENANT);
        assert_eq!(entry.timestamp, noon().to_rfc3339());
        assert_eq!(entry.action, "allocate");
        assert_eq!(entry.caller_sub.as_deref(), Some("sub-1"));
        assert_eq!(entry.auth_method, "pat");
        assert_eq!(entry.pat_id.as_deref(), Some("pat-1"));
        assert_eq!(cx.new_id(), "id-0");
        assert_eq!(cx.new_id(), "id-1");
    }

    #[test]
    fn audit_facts_default_to_oidc_outside_a_request() {
        let cx = DecideCtx::new(noon(), AuditContext::default(), Arc::new(UuidIds));
        let entry = AuditFact {
            action: "a",
            entity_type: "e",
            entity_id: "x".to_string(),
            details: None,
        }
        .into_entry(TENANT, &cx);
        assert_eq!(entry.auth_method, "oidc");
        assert_eq!(entry.caller_sub, None);
    }

    #[test]
    fn the_actor_is_the_callers_email_then_subject_then_cli() {
        let cx = |email: Option<&str>, sub: Option<&str>| {
            let caller = AuditContext {
                caller_email: email.map(str::to_string),
                caller_sub: sub.map(str::to_string),
                ..AuditContext::default()
            };
            DecideCtx::new(noon(), caller, Arc::new(UuidIds))
        };
        assert_eq!(cx(Some("a@x"), Some("sub-1")).actor(), "a@x");
        assert_eq!(cx(None, Some("sub-1")).actor(), "sub-1");
        assert_eq!(cx(None, None).actor(), "cli");
    }
}
