/// Embedded schema migrations for the SQLite IPAM backend.
/// Each migration is a (version, sql) tuple applied in order.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (1, MIGRATION_001),
    (2, MIGRATION_002),
    (3, MIGRATION_003),
    (4, MIGRATION_004),
];

const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS supernets (
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
    supernet_id           TEXT NOT NULL REFERENCES supernets(id),
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

CREATE INDEX IF NOT EXISTS idx_allocations_supernet ON allocations(supernet_id, status);
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
ALTER TABLE supernets ADD COLUMN total_hosts_text TEXT;
UPDATE supernets SET total_hosts_text = CAST(total_hosts AS TEXT);

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
