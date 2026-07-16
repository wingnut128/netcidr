/// Embedded schema migrations for the SQLite IPAM backend.
/// Each migration is a (version, sql) tuple applied in order.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (1, MIGRATION_001),
    (2, MIGRATION_002),
    (3, MIGRATION_003),
    (4, MIGRATION_004),
    (5, MIGRATION_005),
    (6, MIGRATION_006),
    (7, MIGRATION_007),
    (8, MIGRATION_008),
    (9, MIGRATION_009),
    (10, MIGRATION_010),
    (11, MIGRATION_011),
    (12, MIGRATION_012),
    (13, MIGRATION_013),
];

const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS cidr_blocks (
    id                TEXT PRIMARY KEY,
    cidr              TEXT NOT NULL UNIQUE,
    network_address   TEXT NOT NULL,
    broadcast_address TEXT NOT NULL,
    prefix_length     INTEGER NOT NULL,
    total_hosts       INTEGER NOT NULL,
    name              TEXT,
    description       TEXT,
    ip_version        INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS allocations (
    id                    TEXT PRIMARY KEY,
    cidr_block_id           TEXT NOT NULL REFERENCES cidr_blocks(id),
    cidr                  TEXT NOT NULL,
    network_address       TEXT NOT NULL,
    broadcast_address     TEXT NOT NULL,
    prefix_length         INTEGER NOT NULL,
    total_hosts           INTEGER NOT NULL,
    resource_id           TEXT,
    resource_type         TEXT,
    name                  TEXT,
    description           TEXT,
    environment           TEXT,
    owner                 TEXT,
    status                TEXT NOT NULL DEFAULT 'active',
    parent_allocation_id  TEXT REFERENCES allocations(id),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    released_at           TEXT
);

CREATE INDEX IF NOT EXISTS idx_allocations_cidr_block ON allocations(cidr_block_id, status);
CREATE INDEX IF NOT EXISTS idx_allocations_resource ON allocations(resource_id);
CREATE INDEX IF NOT EXISTS idx_allocations_parent   ON allocations(parent_allocation_id);
CREATE INDEX IF NOT EXISTS idx_allocations_cidr     ON allocations(cidr);

CREATE TABLE IF NOT EXISTS allocation_tags (
    allocation_id TEXT NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    value         TEXT NOT NULL,
    PRIMARY KEY (allocation_id, key)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"#;

const MIGRATION_002: &str = r#"
ALTER TABLE allocations ADD COLUMN expires_at TEXT;
"#;

const MIGRATION_003: &str = r#"
ALTER TABLE cidr_blocks ADD COLUMN total_hosts_text TEXT;
UPDATE cidr_blocks SET total_hosts_text = CAST(total_hosts AS TEXT);

ALTER TABLE allocations ADD COLUMN total_hosts_text TEXT;
UPDATE allocations SET total_hosts_text = CAST(total_hosts AS TEXT);
"#;

const MIGRATION_004: &str = r#"
ALTER TABLE audit_log ADD COLUMN caller_sub    TEXT;
ALTER TABLE audit_log ADD COLUMN caller_email  TEXT;
ALTER TABLE audit_log ADD COLUMN source_ip     TEXT;
ALTER TABLE audit_log ADD COLUMN request_id    TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_log(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_caller_sub ON audit_log(caller_sub);
"#;

const MIGRATION_005: &str = r#"
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key           TEXT NOT NULL,
    scope         TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    PRIMARY KEY (key, scope)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_keys(expires_at);
"#;

/// Migration 006: multi-tenant isolation. Destructively drops and recreates
/// `cidr_blocks`, `allocations`, `audit_log`, `idempotency_keys`, and
/// `allocation_tags` (last one because it FKs allocations) so we can add
/// `tenant_id` columns, replace `UNIQUE(cidr)` with `UNIQUE(tenant_id, cidr)`
/// on cidr_blocks, add composite tenant indexes, and install triggers
/// enforcing the cross-table invariant
/// `allocations.tenant_id == cidr_blocks.tenant_id`.
const MIGRATION_006: &str = r#"
DROP TABLE IF EXISTS allocation_tags;
DROP TABLE IF EXISTS allocations;
DROP TABLE IF EXISTS cidr_blocks;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS idempotency_keys;

CREATE TABLE cidr_blocks (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    cidr              TEXT NOT NULL,
    network_address   TEXT NOT NULL,
    broadcast_address TEXT NOT NULL,
    prefix_length     INTEGER NOT NULL,
    total_hosts       TEXT NOT NULL,
    name              TEXT,
    description       TEXT,
    ip_version        INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE (tenant_id, cidr)
);
CREATE INDEX idx_cidr_blocks_tenant ON cidr_blocks(tenant_id);

CREATE TABLE allocations (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    cidr_block_id           TEXT NOT NULL REFERENCES cidr_blocks(id),
    cidr                  TEXT NOT NULL,
    network_address       TEXT NOT NULL,
    broadcast_address     TEXT NOT NULL,
    prefix_length         INTEGER NOT NULL,
    total_hosts           TEXT NOT NULL,
    status                TEXT NOT NULL,
    resource_id           TEXT,
    resource_type         TEXT,
    name                  TEXT,
    description           TEXT,
    environment           TEXT,
    owner                 TEXT,
    parent_allocation_id  TEXT REFERENCES allocations(id),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    released_at           TEXT,
    expires_at            TEXT
);
CREATE INDEX idx_allocations_tenant     ON allocations(tenant_id);
CREATE INDEX idx_allocations_tenant_sn  ON allocations(tenant_id, cidr_block_id);
CREATE INDEX idx_allocations_cidr_block   ON allocations(cidr_block_id);
CREATE INDEX idx_allocations_status     ON allocations(status);
CREATE INDEX idx_allocations_cidr       ON allocations(cidr);

-- Cross-table invariant: allocations.tenant_id must match the parent cidr_block's.
CREATE TRIGGER trg_allocations_tenant_match_insert
    BEFORE INSERT ON allocations
    FOR EACH ROW
    WHEN NEW.tenant_id != (SELECT tenant_id FROM cidr_blocks WHERE id = NEW.cidr_block_id)
    BEGIN
        SELECT RAISE(ABORT, 'allocation tenant_id must match parent cidr_block tenant_id');
    END;
CREATE TRIGGER trg_allocations_tenant_match_update
    BEFORE UPDATE OF tenant_id, cidr_block_id ON allocations
    FOR EACH ROW
    WHEN NEW.tenant_id != (SELECT tenant_id FROM cidr_blocks WHERE id = NEW.cidr_block_id)
    BEGIN
        SELECT RAISE(ABORT, 'allocation tenant_id must match parent cidr_block tenant_id');
    END;

CREATE TABLE allocation_tags (
    allocation_id TEXT NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    value         TEXT NOT NULL,
    PRIMARY KEY (allocation_id, key)
);

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    action        TEXT NOT NULL,
    details       TEXT,
    timestamp     TEXT NOT NULL,
    caller_sub    TEXT,
    caller_email  TEXT,
    source_ip     TEXT,
    request_id    TEXT
);
CREATE INDEX idx_audit_tenant         ON audit_log(tenant_id);
CREATE INDEX idx_audit_tenant_entity  ON audit_log(tenant_id, entity_type, entity_id);
CREATE INDEX idx_audit_request_id     ON audit_log(request_id);
CREATE INDEX idx_audit_caller_sub     ON audit_log(caller_sub);

CREATE TABLE idempotency_keys (
    tenant_id     TEXT NOT NULL,
    key           TEXT NOT NULL,
    scope         TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    PRIMARY KEY (tenant_id, key, scope)
);
CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);
"#;

/// Migration 007: personal access tokens. Additive only — new
/// `personal_access_tokens` table plus two new columns on `audit_log`
/// (`auth_method` defaulting to `'oidc'` for back-compat, and nullable
/// `pat_id`). No DROPs, no destructive ALTERs on existing data columns.
const MIGRATION_007: &str = r#"
CREATE TABLE personal_access_tokens (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    owner_sub     TEXT NOT NULL,
    owner_email   TEXT NOT NULL,
    name          TEXT NOT NULL,
    prefix        TEXT NOT NULL,
    token_hash    BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT
);
CREATE INDEX idx_pat_tenant ON personal_access_tokens(tenant_id);
CREATE INDEX idx_pat_prefix ON personal_access_tokens(prefix);
CREATE UNIQUE INDEX idx_pat_token_hash ON personal_access_tokens(token_hash);

ALTER TABLE audit_log ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'oidc';
ALTER TABLE audit_log ADD COLUMN pat_id TEXT;
"#;

/// Migration 008: per-PAT role downgrade. Adds the `role` column to
/// `personal_access_tokens` so a high-privilege user can mint a narrower
/// PAT for CI / automation. Default `'admin'` for existing rows preserves
/// pre-feature behaviour (PATs were always evaluated at the owner's
/// email-resolved role, which equals `min(owner_role, admin) = owner_role`).
/// The CHECK constraint mirrors the `Role` enum's variants.
const MIGRATION_008: &str = r#"
ALTER TABLE personal_access_tokens
    ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'
    CHECK (role IN ('reader', 'allocator', 'admin'));
"#;

const MIGRATION_009: &str = r#"
CREATE TABLE IF NOT EXISTS hostname_pointers (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    ip_address    TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    allocation_id TEXT REFERENCES allocations(id),
    notes         TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (tenant_id, ip_address, hostname)
);

CREATE INDEX IF NOT EXISTS idx_hostname_pointers_tenant ON hostname_pointers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hostname_pointers_ip     ON hostname_pointers(tenant_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_hostname_pointers_name   ON hostname_pointers(tenant_id, hostname);
CREATE INDEX IF NOT EXISTS idx_hostname_pointers_alloc  ON hostname_pointers(allocation_id);

CREATE TABLE IF NOT EXISTS hostname_pointer_history (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    pointer_id     TEXT NOT NULL,
    ip_address     TEXT NOT NULL,
    hostname       TEXT NOT NULL,
    change_kind    TEXT NOT NULL CHECK (change_kind IN ('create', 'update', 'delete')),
    previous_value TEXT,
    new_value      TEXT,
    actor          TEXT NOT NULL,
    changed_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hostname_history_tenant ON hostname_pointer_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hostname_history_ip     ON hostname_pointer_history(tenant_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_hostname_history_name   ON hostname_pointer_history(tenant_id, hostname);
"#;

const MIGRATION_010: &str = r#"
CREATE INDEX IF NOT EXISTS idx_audit_tenant_email ON audit_log(tenant_id, caller_email);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_pat   ON audit_log(tenant_id, pat_id);
"#;

const MIGRATION_011: &str = r#"
CREATE TABLE IF NOT EXISTS role_assignments (
    email      TEXT PRIMARY KEY,
    role       TEXT NOT NULL CHECK (role IN ('reader', 'allocator', 'admin')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_role ON role_assignments(role);
"#;

// Adds tenant_id to allocation_tags so tag isolation no longer relies solely on
// the parent-allocation pre-check + UUID unguessability. Backfills from the
// parent allocation and enforces the match with triggers (mirroring the
// allocations tenant-match invariant). The column is left nullable at the schema
// level — SQLite can't add a NOT NULL column to an existing table — but the
// triggers reject any NULL/mismatched tenant_id on insert/update.
const MIGRATION_012: &str = r#"
ALTER TABLE allocation_tags ADD COLUMN tenant_id TEXT;

UPDATE allocation_tags
SET tenant_id = (SELECT a.tenant_id FROM allocations a WHERE a.id = allocation_tags.allocation_id);

CREATE INDEX idx_allocation_tags_tenant ON allocation_tags(tenant_id, allocation_id);

CREATE TRIGGER trg_allocation_tags_tenant_match_insert
    BEFORE INSERT ON allocation_tags
    FOR EACH ROW
    WHEN NEW.tenant_id IS NULL
      OR NEW.tenant_id != (SELECT tenant_id FROM allocations WHERE id = NEW.allocation_id)
    BEGIN
        SELECT RAISE(ABORT, 'allocation_tags tenant_id must match parent allocation tenant_id');
    END;
CREATE TRIGGER trg_allocation_tags_tenant_match_update
    BEFORE UPDATE OF tenant_id, allocation_id ON allocation_tags
    FOR EACH ROW
    WHEN NEW.tenant_id IS NULL
      OR NEW.tenant_id != (SELECT tenant_id FROM allocations WHERE id = NEW.allocation_id)
    BEGIN
        SELECT RAISE(ABORT, 'allocation_tags tenant_id must match parent allocation tenant_id');
    END;
"#;

// Unified users directory (ADR-0006). One row per user replaces both the env
// allowlist (NETCIDR_OIDC_ALLOWED_EMAILS) and the role_assignments table:
// "allowlisted" = an active row exists; role lives on the same row.
//
// - Existing role_assignments rows are copied in; 'admin' rows are promoted to
//   'platform_admin' because pre-split Admins held user-management power
//   (/admin/users was RequireAdmin) and demoting them would strand a deployed
//   system with zero platform admins.
// - role_assignments is deliberately NOT dropped: a binary rollback after this
//   migration must still find its table. Dropping it is deferred to a later
//   release once this version is settled.
// - bootstrap_markers makes the env seed one-shot: seed-if-empty can't work
//   here because the copy above makes `users` non-empty, yet allowlist-only
//   emails (no role row today) still need rows topped up exactly once.
const MIGRATION_013: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    email       TEXT PRIMARY KEY,
    role        TEXT NOT NULL DEFAULT 'reader'
                CHECK (role IN ('reader', 'allocator', 'admin', 'platform_admin')),
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'disabled')),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    created_by  TEXT,
    updated_by  TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_role   ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

INSERT INTO users (email, role, status, created_at, updated_at, created_by)
SELECT email,
       CASE role WHEN 'admin' THEN 'platform_admin' ELSE role END,
       'active',
       created_at,
       updated_at,
       created_by
FROM role_assignments
WHERE true
ON CONFLICT (email) DO NOTHING;

CREATE TABLE IF NOT EXISTS bootstrap_markers (
    key        TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use crate::ipam::sqlite::SqliteStore;
    use crate::ipam::store::IpamStore;

    #[tokio::test]
    async fn allocation_with_mismatched_tenant_id_is_rejected_by_trigger() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        let conn = store.pool().get().expect("pool checkout");

        // Insert a cidr_block for tenant "a@x".
        conn.execute(
            r#"INSERT INTO cidr_blocks
               (id, tenant_id, cidr, network_address, broadcast_address,
                prefix_length, total_hosts, ip_version, created_at, updated_at)
               VALUES ('s1','a@x','10.0.0.0/8','10.0.0.0','10.255.255.255',
                       8,'16777216',4,'2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
            [],
        )
        .expect("insert cidr_block");

        // Attempt to insert allocation with mismatched tenant_id.
        let result = conn.execute(
            r#"INSERT INTO allocations
               (id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address,
                prefix_length, total_hosts, status, created_at, updated_at)
               VALUES ('a1','b@x','s1','10.1.0.0/16','10.1.0.0','10.1.255.255',
                       16,'65536','active','2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
            [],
        );

        assert!(
            result.is_err(),
            "trigger should reject allocation whose tenant_id != cidr_block's tenant_id"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("allocation tenant_id must match"),
            "unexpected error: {}",
            err
        );

        // Matching tenant_id should succeed.
        conn.execute(
            r#"INSERT INTO allocations
               (id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address,
                prefix_length, total_hosts, status, created_at, updated_at)
               VALUES ('a2','a@x','s1','10.1.0.0/16','10.1.0.0','10.1.255.255',
                       16,'65536','active','2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
            [],
        )
        .expect("matching tenant insert should succeed");
    }

    #[tokio::test]
    async fn migration_007_personal_access_tokens_round_trip() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        let conn = store.pool().get().expect("pool checkout");

        // Insert a row with a 32-byte BLOB hash.
        let hash: Vec<u8> = (0u8..32).collect();
        conn.execute(
            r#"INSERT INTO personal_access_tokens
               (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
                created_at, expires_at, last_used_at, revoked_at)
               VALUES ('p1','a@x','sub-1','a@x','laptop','ncdr_pat_AAA',?1,
                       '2026-05-02T00:00:00Z','2026-08-01T00:00:00Z',NULL,NULL)"#,
            rusqlite::params![hash.clone()],
        )
        .expect("insert PAT");

        let (got_hash, got_name, got_prefix): (Vec<u8>, String, String) = conn
            .query_row(
                "SELECT token_hash, name, prefix FROM personal_access_tokens WHERE id = 'p1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read PAT");
        assert_eq!(got_hash, hash, "BLOB hash bytes round-trip");
        assert_eq!(got_name, "laptop");
        assert_eq!(got_prefix, "ncdr_pat_AAA");

        // audit_log gained auth_method (default 'oidc') and pat_id (nullable).
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(audit_log)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            cols.iter().any(|c| c == "auth_method"),
            "audit_log missing auth_method column: {:?}",
            cols
        );
        assert!(
            cols.iter().any(|c| c == "pat_id"),
            "audit_log missing pat_id column: {:?}",
            cols
        );

        // Existing audit_log rows take the default 'oidc'.
        conn.execute(
            r#"INSERT INTO audit_log
               (tenant_id, entity_type, entity_id, action, timestamp)
               VALUES ('a@x','create_cidr_block','s1','create_create_cidr_block','2026-05-02T00:00:00Z')"#,
            [],
        )
        .unwrap();
        let auth_method: String = conn
            .query_row(
                "SELECT auth_method FROM audit_log WHERE entity_id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(auth_method, "oidc");

        // UNIQUE(token_hash) — second insert with same hash must fail.
        let dup = conn.execute(
            r#"INSERT INTO personal_access_tokens
               (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
                created_at, expires_at)
               VALUES ('p2','a@x','sub-1','a@x','dup','ncdr_pat_BBB',?1,
                       '2026-05-02T00:00:00Z','2026-08-01T00:00:00Z')"#,
            rusqlite::params![hash],
        );
        assert!(dup.is_err(), "duplicate token_hash must violate UNIQUE");
    }

    #[tokio::test]
    async fn migration_008_pat_role_column_exists_with_admin_default() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        let conn = store.pool().get().expect("pool checkout");

        // Insert a PAT WITHOUT supplying the role column — DB default should kick in.
        conn.execute(
            r#"INSERT INTO personal_access_tokens
               (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
                created_at, expires_at)
               VALUES ('p1','a@x','sub-1','a@x','laptop','ncdr_pat_AAA',
                       X'00',
                       '2026-05-21T00:00:00Z','2099-01-01T00:00:00Z')"#,
            [],
        )
        .expect("insert PAT without role column");

        let role: String = conn
            .query_row(
                "SELECT role FROM personal_access_tokens WHERE id = 'p1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(role, "admin", "pre-feature rows must default to admin");

        // CHECK constraint rejects unknown values.
        let bad = conn.execute(
            r#"INSERT INTO personal_access_tokens
               (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
                role, created_at, expires_at)
               VALUES ('p2','a@x','sub-1','a@x','bad','ncdr_pat_BAD',
                       X'01','god',
                       '2026-05-21T00:00:00Z','2099-01-01T00:00:00Z')"#,
            [],
        );
        assert!(bad.is_err(), "CHECK constraint must reject unknown role");
    }

    #[tokio::test]
    async fn migration_runs_twice_is_a_no_op() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        // Second invocation must not error and must not duplicate work.
        store
            .migrate()
            .await
            .expect("second migrate should be idempotent");
    }

    /// Simulate the upgrade path: a DB that ran the previous release (through
    /// migration 12) with role_assignments rows, then applies migration 13.
    /// Admin rows must be promoted to platform_admin; other roles copied
    /// verbatim; role_assignments must be left untouched (rollback safety).
    #[tokio::test]
    async fn migration_013_copies_and_promotes_role_assignments() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Apply everything before 13, then insert legacy rows.
        for &(version, sql) in super::MIGRATIONS {
            if version < 13 {
                conn.execute_batch(sql).unwrap();
            }
        }
        conn.execute_batch(
            r#"INSERT INTO role_assignments (email, role, created_at, updated_at, created_by)
               VALUES ('boss@x', 'admin',     '2026-05-29T00:00:00Z', '2026-05-29T00:00:00Z', 'bootstrap'),
                      ('ops@x',  'allocator', '2026-05-29T00:00:00Z', '2026-05-29T00:00:00Z', 'boss@x'),
                      ('view@x', 'reader',    '2026-05-29T00:00:00Z', '2026-05-29T00:00:00Z', 'boss@x')"#,
        )
        .unwrap();

        conn.execute_batch(super::MIGRATION_013).unwrap();

        let rows: Vec<(String, String, String)> = conn
            .prepare("SELECT email, role, status FROM users ORDER BY email")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("boss@x".into(), "platform_admin".into(), "active".into()),
                ("ops@x".into(), "allocator".into(), "active".into()),
                ("view@x".into(), "reader".into(), "active".into()),
            ],
            "admin promotes to platform_admin; others copy verbatim, all active"
        );

        // role_assignments is frozen, not dropped: binary rollback still works.
        let legacy: i64 = conn
            .query_row("SELECT COUNT(*) FROM role_assignments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(legacy, 3, "role_assignments must be left untouched");

        // created_at / created_by carried over from the legacy row.
        let (created_at, created_by): (String, Option<String>) = conn
            .query_row(
                "SELECT created_at, created_by FROM users WHERE email = 'boss@x'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(created_at, "2026-05-29T00:00:00Z");
        assert_eq!(created_by.as_deref(), Some("bootstrap"));
    }

    #[tokio::test]
    async fn migration_013_users_check_constraints_reject_unknown_values() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        let conn = store.pool().get().expect("pool checkout");

        // platform_admin is a valid role; unknown roles and statuses are not.
        conn.execute(
            r#"INSERT INTO users (email, role, status, created_at, updated_at)
               VALUES ('ok@x', 'platform_admin', 'active', '2026-07-16T00:00:00Z', '2026-07-16T00:00:00Z')"#,
            [],
        )
        .expect("platform_admin must satisfy the role CHECK");

        let bad_role = conn.execute(
            r#"INSERT INTO users (email, role, status, created_at, updated_at)
               VALUES ('bad@x', 'god', 'active', '2026-07-16T00:00:00Z', '2026-07-16T00:00:00Z')"#,
            [],
        );
        assert!(bad_role.is_err(), "CHECK must reject unknown role");

        let bad_status = conn.execute(
            r#"INSERT INTO users (email, role, status, created_at, updated_at)
               VALUES ('bad@x', 'reader', 'suspended', '2026-07-16T00:00:00Z', '2026-07-16T00:00:00Z')"#,
            [],
        );
        assert!(bad_status.is_err(), "CHECK must reject unknown status");

        // Defaults: role=reader, status=active.
        conn.execute(
            r#"INSERT INTO users (email, created_at, updated_at)
               VALUES ('defaults@x', '2026-07-16T00:00:00Z', '2026-07-16T00:00:00Z')"#,
            [],
        )
        .unwrap();
        let (role, status): (String, String) = conn
            .query_row(
                "SELECT role, status FROM users WHERE email = 'defaults@x'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((role.as_str(), status.as_str()), ("reader", "active"));
    }

    /// The PAT role CHECK is intentionally NOT widened: PATs are capped at
    /// admin (ADR-0006) so platform-tier access is never mintable as a token.
    #[tokio::test]
    async fn migration_013_pat_role_check_still_excludes_platform_admin() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        let conn = store.pool().get().expect("pool checkout");
        let bad = conn.execute(
            r#"INSERT INTO personal_access_tokens
               (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
                role, created_at, expires_at)
               VALUES ('p1','a@x','sub-1','a@x','esc','ncdr_pat_ESC',
                       X'02','platform_admin',
                       '2026-07-16T00:00:00Z','2099-01-01T00:00:00Z')"#,
            [],
        );
        assert!(
            bad.is_err(),
            "PAT role CHECK must keep rejecting platform_admin"
        );
    }
}
