/// Embedded schema migrations for the PostgreSQL IPAM backend.
/// Each migration is a (version, sql) tuple applied in order.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (1, MIGRATION_001),
    (2, MIGRATION_002),
    (3, MIGRATION_003),
    (4, MIGRATION_004),
    (5, MIGRATION_005),
    (6, MIGRATION_006),
    (7, MIGRATION_007),
];

const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS cidr_blocks (
    id                TEXT PRIMARY KEY,
    cidr              TEXT NOT NULL UNIQUE,
    network_address   TEXT NOT NULL,
    broadcast_address TEXT NOT NULL,
    prefix_length     SMALLINT NOT NULL,
    total_hosts       BIGINT NOT NULL,
    name              TEXT,
    description       TEXT,
    ip_version        SMALLINT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS allocations (
    id                    TEXT PRIMARY KEY,
    cidr_block_id           TEXT NOT NULL REFERENCES cidr_blocks(id),
    cidr                  TEXT NOT NULL,
    network_address       TEXT NOT NULL,
    broadcast_address     TEXT NOT NULL,
    prefix_length         SMALLINT NOT NULL,
    total_hosts           BIGINT NOT NULL,
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
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
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
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS caller_sub   TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS caller_email TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS source_ip    TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS request_id   TEXT;

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

/// Migration 006: multi-tenant isolation. Mirrors the SQLite migration in
/// Postgres dialect — destructively drops and recreates the IPAM tables
/// with `tenant_id` columns, replaces `UNIQUE(cidr)` with
/// `UNIQUE(tenant_id, cidr)` on cidr_blocks, adds composite tenant indexes,
/// and installs a plpgsql trigger function enforcing the cross-table
/// invariant `allocations.tenant_id == cidr_blocks.tenant_id`.
const MIGRATION_006: &str = r#"
DROP TABLE IF EXISTS allocation_tags CASCADE;
DROP TABLE IF EXISTS allocations CASCADE;
DROP TABLE IF EXISTS cidr_blocks CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS idempotency_keys CASCADE;

CREATE TABLE cidr_blocks (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    cidr              TEXT NOT NULL,
    network_address   TEXT NOT NULL,
    broadcast_address TEXT NOT NULL,
    prefix_length     SMALLINT NOT NULL,
    total_hosts       TEXT NOT NULL,
    name              TEXT,
    description       TEXT,
    ip_version        SMALLINT NOT NULL,
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
    prefix_length         SMALLINT NOT NULL,
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
CREATE INDEX idx_allocations_tenant    ON allocations(tenant_id);
CREATE INDEX idx_allocations_tenant_sn ON allocations(tenant_id, cidr_block_id);
CREATE INDEX idx_allocations_cidr_block  ON allocations(cidr_block_id);
CREATE INDEX idx_allocations_status    ON allocations(status);
CREATE INDEX idx_allocations_cidr      ON allocations(cidr);

CREATE OR REPLACE FUNCTION assert_alloc_tenant_match() RETURNS trigger AS $$
DECLARE
    sn_tenant TEXT;
BEGIN
    SELECT tenant_id INTO sn_tenant FROM cidr_blocks WHERE id = NEW.cidr_block_id;
    IF sn_tenant IS NULL OR sn_tenant != NEW.tenant_id THEN
        RAISE EXCEPTION 'allocation tenant_id must match parent cidr_block tenant_id';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_allocations_tenant_match_insert
    BEFORE INSERT ON allocations
    FOR EACH ROW EXECUTE FUNCTION assert_alloc_tenant_match();
CREATE TRIGGER trg_allocations_tenant_match_update
    BEFORE UPDATE OF tenant_id, cidr_block_id ON allocations
    FOR EACH ROW EXECUTE FUNCTION assert_alloc_tenant_match();

CREATE TABLE allocation_tags (
    allocation_id TEXT NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    value         TEXT NOT NULL,
    PRIMARY KEY (allocation_id, key)
);

CREATE TABLE audit_log (
    id            BIGSERIAL PRIMARY KEY,
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

/// Migration 007: personal access tokens. Mirrors the SQLite migration.
/// Additive only — new `personal_access_tokens` table plus two new columns
/// on `audit_log`. `token_hash` is `bytea`; time fields stay `TEXT` to match
/// the rest of the schema's existing convention.
const MIGRATION_007: &str = r#"
CREATE TABLE personal_access_tokens (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    owner_sub     TEXT NOT NULL,
    owner_email   TEXT NOT NULL,
    name          TEXT NOT NULL,
    prefix        TEXT NOT NULL,
    token_hash    BYTEA NOT NULL,
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

#[cfg(all(test, feature = "ipam-postgres"))]
mod tests {
    use crate::ipam::config::PostgresConfig;
    use crate::ipam::postgres::PostgresStore;
    use crate::ipam::store::IpamStore;

    #[tokio::test]
    async fn pg_allocation_with_mismatched_tenant_id_is_rejected_by_trigger() {
        // Skip if no NETCIDR_TEST_DATABASE_URL set.
        let url = match std::env::var("NETCIDR_TEST_DATABASE_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("skipping: NETCIDR_TEST_DATABASE_URL not set");
                return;
            }
        };
        let config = PostgresConfig::default();
        let store = PostgresStore::new(&url, &config).await.unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        sqlx::query(
            r#"INSERT INTO cidr_blocks
               (id, tenant_id, cidr, network_address, broadcast_address,
                prefix_length, total_hosts, ip_version, created_at, updated_at)
               VALUES ('s1','a@x','10.0.0.0/8','10.0.0.0','10.255.255.255',
                       8,'16777216',4,'2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
        )
        .execute(store.pool())
        .await
        .unwrap();

        let result = sqlx::query(
            r#"INSERT INTO allocations
               (id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address,
                prefix_length, total_hosts, status, created_at, updated_at)
               VALUES ('a1','b@x','s1','10.1.0.0/16','10.1.0.0','10.1.255.255',
                       16,'65536','active','2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
        )
        .execute(store.pool())
        .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must match parent")
        );
    }
}
