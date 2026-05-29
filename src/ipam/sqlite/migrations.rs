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
}
