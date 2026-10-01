use std::time::Duration;

use async_trait::async_trait;

use crate::error::Result;
use crate::ipam::models::*;

/// Build a trailing `LIMIT … OFFSET …` SQL clause for a paginated list query.
///
/// `limit`/`offset` are `u32`, so the values are pure digits — formatting them
/// directly into SQL carries no injection risk and keeps the clause backend
/// agnostic (works for both the rusqlite and sqlx builders). `None`/`None`
/// yields an empty string (unbounded, for CLI and internal callers); an offset
/// without a limit uses `LIMIT -1` as SQLite/Postgres both require a limit
/// before an offset.
pub(crate) fn limit_offset_clause(limit: Option<u32>, offset: Option<u32>) -> String {
    match (limit, offset) {
        (Some(l), Some(o)) => format!(" LIMIT {l} OFFSET {o}"),
        (Some(l), None) => format!(" LIMIT {l}"),
        (None, Some(o)) => format!(" LIMIT -1 OFFSET {o}"),
        (None, None) => String::new(),
    }
}

/// How long a transaction unit waits for its Lock Scope (or a pooled
/// connection) before failing with [`NetcidrError::StoreBusy`].
///
/// [`NetcidrError::StoreBusy`]: crate::error::NetcidrError::StoreBusy
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Decide-then-commit transaction units (ADR-0007)
// ---------------------------------------------------------------------------

/// The one thing a transaction unit holds exclusively while it decides and
/// commits. Two units with the same scope never interleave.
///
/// SQLite serializes every writer regardless of scope; Postgres takes a
/// transaction-scoped advisory lock on [`LockScope::key`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LockScope {
    /// One cidr block and its allocations (allocate, update, release, reap,
    /// tags, delete).
    CidrBlock {
        tenant_id: String,
        cidr_block_id: String,
    },
    /// A tenant's set of cidr blocks (create, load) and its hostname
    /// pointers (set, delete).
    Tenant { tenant_id: String },
    /// The global user directory (upsert, delete, seed).
    UserDirectory,
    /// One PAT Owner's tokens (mint, revoke).
    PatOwner {
        tenant_id: String,
        owner_sub: String,
    },
}

impl LockScope {
    /// Stable, namespaced identity of the scope. Fields are joined with the
    /// ASCII unit separator, which validated identifiers never contain, so
    /// distinct scopes never share a key.
    pub fn key(&self) -> String {
        const SEP: char = '\u{1f}';
        match self {
            Self::CidrBlock {
                tenant_id,
                cidr_block_id,
            } => format!("cidr_block{SEP}{tenant_id}{SEP}{cidr_block_id}"),
            Self::Tenant { tenant_id } => format!("tenant{SEP}{tenant_id}"),
            Self::UserDirectory => "user_directory".to_string(),
            Self::PatOwner {
                tenant_id,
                owner_sub,
            } => format!("pat_owner{SEP}{tenant_id}{SEP}{owner_sub}"),
        }
    }
}

/// A read a unit declares up front. Reads run after the lock is taken,
/// inside the transaction, in declaration order. Every tenant-scoped read
/// carries its tenant (ADR-0001); a row in another tenant reads as absent.
#[derive(Debug, Clone, PartialEq)]
pub enum Read {
    CidrBlock {
        tenant_id: String,
        id: String,
    },
    /// All of a tenant's cidr blocks, oldest first.
    CidrBlocks {
        tenant_id: String,
    },
    /// One allocation, with its tags.
    Allocation {
        tenant_id: String,
        id: String,
    },
    /// A cidr block's allocations in the given statuses, with their tags,
    /// ordered by network address.
    AllocationsInBlock {
        tenant_id: String,
        cidr_block_id: String,
        statuses: Vec<AllocationStatus>,
    },
    /// One user by (lowercased) email. The user directory is global.
    User {
        email: String,
    },
    /// Every user, ordered by email.
    Users,
    /// How many users are active platform admins.
    ActivePlatformAdminCount,
    /// Whether the one-shot bootstrap marker `key` has been written.
    BootstrapMarker {
        key: String,
    },
    /// One PAT, only if it belongs to this owner in this tenant.
    Pat {
        tenant_id: String,
        owner_sub: String,
        id: String,
    },
    /// How many of an owner's PATs are neither revoked nor expired at `now`.
    ActivePatCount {
        tenant_id: String,
        owner_sub: String,
        now: String,
    },
    /// The live hostname pointer for `(ip_address, hostname)` in a tenant.
    HostnamePointer {
        tenant_id: String,
        ip_address: String,
        hostname: String,
    },
}

/// The result of one [`Read`], in the same position as its read.
// One short-lived value per declared read; boxing the larger variants would
// add an allocation per read for no benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Rows {
    CidrBlock(Option<CidrBlock>),
    CidrBlocks(Vec<CidrBlock>),
    Allocation(Option<Allocation>),
    Allocations(Vec<Allocation>),
    User(Option<UserRecord>),
    Users(Vec<UserRecord>),
    Count(u64),
    Flag(bool),
    Pat(Option<PersonalAccessToken>),
    HostnamePointer(Option<HostnamePointer>),
}

/// A rule-free row write. The adapter applies it verbatim: ids, timestamps,
/// derived fields, and preconditions are all decided before it gets here.
///
/// Variants are added as operations move onto [`IpamStore::transact`]
/// (#482–#487).
#[derive(Debug, Clone)]
pub enum Write {
    /// Insert a new cidr block row.
    InsertCidrBlock(CidrBlock),
    /// Delete a cidr block together with its allocations and their tags,
    /// matched by tenant and id.
    DeleteCidrBlock { tenant_id: String, id: String },
    /// Insert a new allocation row and its tags.
    InsertAllocation(Allocation),
    /// Overwrite an existing allocation's mutable fields (status, resource,
    /// descriptive fields, `updated_at`, `released_at`, `expires_at`),
    /// matched by tenant and id. Tags are left as they are.
    ReplaceAllocation(Allocation),
    /// Insert a user, or overwrite every column of the existing row with the
    /// same email.
    PutUser(UserRecord),
    /// Delete the user with this (lowercased) email.
    DeleteUser { email: String },
    /// Record that the one-shot bootstrap step `key` has run.
    SetBootstrapMarker { key: String, applied_at: String },
    /// Insert a new PAT row (its hash, never its plaintext).
    InsertPat(PersonalAccessToken),
    /// Set `revoked_at` on an owner's PAT.
    RevokePat {
        tenant_id: String,
        owner_sub: String,
        id: String,
        revoked_at: String,
    },
    /// Insert a hostname pointer, or — when a row with its id exists in its
    /// tenant — overwrite that row's `allocation_id`, `notes`, and
    /// `updated_at`.
    PutHostnamePointer(HostnamePointer),
    /// Delete a hostname pointer, matched by tenant and id.
    DeleteHostnamePointer { tenant_id: String, id: String },
    /// Append one row to the hostname pointer history.
    AppendHostnameHistory(HostnamePointerHistoryEntry),
}

/// Looks up an existing idempotency record inside the unit, under its lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyLookup {
    pub tenant_id: String,
    pub key: String,
    pub scope: String,
}

/// Everything a unit's `decide` sees: its reads' rows, in order, and the
/// idempotency record found by its lookup (if it declared one).
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub rows: Vec<Rows>,
    pub idempotency: Option<IdempotencyRecord>,
}

/// What a unit commits: its writes, then its audit rows, then its
/// idempotency record, all in one transaction. `output_json` is returned
/// to the caller of [`IpamStore::transact`].
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub writes: Vec<Write>,
    pub audits: Vec<AuditEntry>,
    pub idempotency: Option<IdempotencyRecord>,
    pub output_json: String,
}

/// The pure, synchronous decision step of a unit. It cannot touch the
/// store, so a unit can never open a second transaction while holding the
/// first. An `Err` rolls the transaction back and is returned unchanged.
pub type DecideFn = Box<dyn FnOnce(Loaded) -> Result<Plan> + Send + 'static>;

/// One decide-then-commit transaction (ADR-0007).
pub struct TxUnit {
    pub scope: LockScope,
    pub reads: Vec<Read>,
    pub idempotency: Option<IdempotencyLookup>,
    pub decide: DecideFn,
}

impl std::fmt::Debug for TxUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxUnit")
            .field("scope", &self.scope)
            .field("reads", &self.reads)
            .field("idempotency", &self.idempotency)
            .finish_non_exhaustive()
    }
}

/// Core storage abstraction for the IPAM persistence layer.
///
/// All tenant-scoped methods take an explicit `tenant_id: &str` parameter so
/// the type system makes per-tenant filtering unforgettable. Backends must
/// add `WHERE tenant_id = ?` to every query and refuse cross-tenant
/// references with `IpamError::NotFound` (never `Forbidden`, to avoid
/// leaking existence).
#[async_trait]
pub trait IpamStore: Send + Sync {
    // --- lifecycle ---
    async fn initialize(&self) -> Result<()>;
    async fn migrate(&self) -> Result<()>;

    // --- transaction units (ADR-0007) ---
    /// Run one decide-then-commit unit: begin → take `unit.scope` → run
    /// `unit.reads` and the idempotency lookup → `decide` → apply the plan's
    /// writes, audit rows, and idempotency record → commit. Returns the
    /// plan's `output_json`.
    ///
    /// If `decide` fails, nothing persists and its error is returned as-is.
    /// Waiting longer than the store's lock timeout for the scope or a
    /// connection fails with `NetcidrError::StoreBusy`. The unit runs to
    /// completion even if the returned future is dropped.
    async fn transact(&self, unit: TxUnit) -> Result<String>;

    // --- cidr_blocks ---
    async fn get_cidr_block(&self, tenant_id: &str, id: &str) -> Result<CidrBlock>;
    async fn list_cidr_blocks(&self, tenant_id: &str) -> Result<Vec<CidrBlock>>;
    /// Like [`list_cidr_blocks`](Self::list_cidr_blocks) but with pagination for
    /// the HTTP list endpoint. `limit`/`offset` of `None` means unbounded.
    async fn list_cidr_blocks_page(
        &self,
        tenant_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<CidrBlock>>;

    // --- allocations ---
    async fn get_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation>;
    async fn list_allocations(
        &self,
        tenant_id: &str,
        filter: &AllocationFilter,
    ) -> Result<Vec<Allocation>>;
    async fn find_allocations_in_cidr_block(
        &self,
        tenant_id: &str,
        cidr_block_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>>;

    // --- tags ---
    async fn set_tags(&self, tenant_id: &str, allocation_id: &str, tags: &[Tag]) -> Result<()>;
    async fn get_tags(&self, tenant_id: &str, allocation_id: &str) -> Result<Vec<Tag>>;

    // --- hostname pointers ---
    async fn list_hostname_pointers(
        &self,
        tenant_id: &str,
        filter: &HostnamePointerFilter,
    ) -> Result<Vec<HostnamePointer>>;
    async fn list_hostname_history(
        &self,
        tenant_id: &str,
        filter: &HostnameHistoryFilter,
    ) -> Result<Vec<HostnamePointerHistoryEntry>>;

    // --- users directory (unified allowlist + roles; global, ADR-0006) ---
    /// Fetch a user row by email, or `None` if no row exists.
    async fn get_user(&self, email: &str) -> Result<Option<UserRecord>>;
    async fn list_users(&self) -> Result<Vec<UserRecord>>;
    /// Number of rows with `role = 'platform_admin' AND status = 'active'` —
    /// used for the last-platform-admin guard.
    async fn count_active_platform_admins(&self) -> Result<u64>;

    // --- audit ---
    /// `entry.tenant_id` is the source of truth (already populated by caller).
    async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn query_audit(&self, tenant_id: &str, filter: &AuditFilter) -> Result<Vec<AuditEntry>>;

    // --- idempotency ---
    async fn idempotency_get(
        &self,
        tenant_id: &str,
        key: &str,
        scope: &str,
    ) -> Result<Option<IdempotencyRecord>>;
    /// `record.tenant_id` is the source of truth.
    async fn idempotency_put(&self, record: &IdempotencyRecord) -> Result<()>;
    /// Tenant-agnostic: prunes expired rows across all tenants.
    async fn idempotency_reap_expired(&self, now_rfc3339: &str) -> Result<u64>;

    // --- personal access tokens ---

    /// Count active (non-revoked, non-expired) PATs for `(tenant_id, owner_sub)`.
    /// `now_rfc3339` is the caller's "now" used in the expiry predicate.
    async fn pat_count_active_for_owner(
        &self,
        tenant_id: &str,
        owner_sub: &str,
        now_rfc3339: &str,
    ) -> Result<u32>;

    /// Lookup an active, non-revoked, non-expired PAT by its hash.
    /// `now_rfc3339` is passed in so the caller controls "now" — the SQL
    /// predicate is `revoked_at IS NULL AND expires_at > $now`. Returns
    /// `Ok(None)` for any miss path (revoked, expired, no such hash) so the
    /// verifier's timing surface is uniform.
    async fn pat_get_by_hash(
        &self,
        token_hash: &[u8],
        now_rfc3339: &str,
    ) -> Result<Option<PersonalAccessToken>>;

    /// List every PAT belonging to the given (tenant_id, owner_sub) pair.
    /// Both keys are required as defense-in-depth: a leaked tenant_id alone
    /// shouldn't enumerate another user's tokens.
    async fn pat_list_for_owner(
        &self,
        tenant_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<PersonalAccessToken>>;

    /// Update `last_used_at = now`. Unscoped (no tenant_id arg) because the
    /// verifier has already proven possession of the secret.
    async fn pat_touch_last_used(&self, id: &str, now_rfc3339: &str) -> Result<()>;

    /// Hard-delete every row whose `expires_at < before_rfc3339`. Returns the
    /// number of rows removed. Tenant-agnostic.
    async fn pat_reap_expired(&self, before_rfc3339: &str) -> Result<u64>;
}
