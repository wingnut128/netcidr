/// Public so upgrade-rehearsal tests can rebuild a previous release's
/// schema by applying a prefix of the migration list.
pub mod migrations;

use async_trait::async_trait;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use std::time::Duration;

use crate::error::{NetcidrError, Result};
use crate::ipam::models::*;
use crate::ipam::read_total_hosts;
use crate::ipam::store::{DEFAULT_LOCK_TIMEOUT, IpamStore, Loaded, Read, Rows, TxUnit, Write};

type ConnPool = Pool<SqliteConnectionManager>;

pub struct SqliteStore {
    pool: ConnPool,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Result<Self> {
        Self::new_with_lock_timeout(db_path, DEFAULT_LOCK_TIMEOUT)
    }

    /// Like [`new`](Self::new), with a custom wait for locks and pooled
    /// connections before `NetcidrError::StoreBusy`.
    pub fn new_with_lock_timeout(db_path: &str, lock_timeout: Duration) -> Result<Self> {
        // Ensure parent directory exists
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path — db_path comes from CLI/config/env, not HTTP input
        if let Some(parent) = Path::new(db_path).parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                NetcidrError::DatabaseError(format!(
                    "failed to create database directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let pool = build_pool(SqliteConnectionManager::file(db_path), 8, lock_timeout)?;

        // Restrict the database file to owner-only (0600). It holds all IPAM
        // data (CIDR blocks, allocations, hostnames, audit log); the default
        // umask would otherwise leave it world-readable on a shared host.
        // The pool's eager connection has already created the file by now.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    NetcidrError::DatabaseError(format!(
                        "failed to restrict permissions on database file {db_path}: {e}"
                    ))
                },
            )?;
        }

        Ok(Self { pool })
    }

    /// Create an in-memory store (useful for testing).
    pub fn in_memory() -> Result<Self> {
        Self::in_memory_with_lock_timeout(DEFAULT_LOCK_TIMEOUT)
    }

    /// Like [`in_memory`](Self::in_memory), with a custom lock timeout.
    pub fn in_memory_with_lock_timeout(lock_timeout: Duration) -> Result<Self> {
        // A single connection: each in-memory connection is its own database.
        let pool = build_pool(SqliteConnectionManager::memory(), 1, lock_timeout)?;
        Ok(Self { pool })
    }

    fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        // r2d2 only fails a checkout after waiting `connection_timeout`
        // (the lock timeout) for a free connection.
        self.pool.get().map_err(|_| NetcidrError::StoreBusy)
    }

    /// Test-only access to the underlying connection pool, used by migration
    /// tests that need to issue raw SQL outside the normal `IpamStore` API.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &ConnPool {
        &self.pool
    }

    fn now() -> String {
        Utc::now().to_rfc3339()
    }

    fn load_tags_for_allocation(
        conn: &rusqlite::Connection,
        tenant_id: &str,
        allocation_id: &str,
    ) -> Result<Vec<Tag>> {
        let mut stmt = conn
            .prepare(
                "SELECT key, value FROM allocation_tags WHERE allocation_id = ?1 AND tenant_id = ?2",
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let tags = stmt
            .query_map(params![allocation_id, tenant_id], |row| {
                Ok(Tag {
                    key: row.get(0)?,
                    value: row.get(1)?,
                })
            })
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(tags)
    }

    fn row_to_allocation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Allocation> {
        let status_str: String = row.get("status")?;
        let status = status_str
            .parse::<AllocationStatus>()
            .unwrap_or(AllocationStatus::Active);
        let total_hosts_text: String = row.get("total_hosts")?;
        Ok(Allocation {
            id: row.get("id")?,
            tenant_id: row.get("tenant_id")?,
            cidr_block_id: row.get("cidr_block_id")?,
            cidr: row.get("cidr")?,
            network_address: row.get("network_address")?,
            broadcast_address: row.get("broadcast_address")?,
            prefix_length: row.get::<_, u8>("prefix_length")?,
            total_hosts: read_total_hosts(Some(total_hosts_text), 0),
            status,
            resource_id: row.get("resource_id")?,
            resource_type: row.get("resource_type")?,
            name: row.get("name")?,
            description: row.get("description")?,
            environment: row.get("environment")?,
            owner: row.get("owner")?,
            parent_allocation_id: row.get("parent_allocation_id")?,
            tags: Vec::new(), // loaded separately
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
            released_at: row.get("released_at")?,
            expires_at: row.get("expires_at")?,
        })
    }

    /// Verify that an allocation exists and belongs to the given tenant. Used
    /// before reading or mutating tag tables (which don't carry tenant_id
    /// directly).
    fn assert_allocation_in_tenant(
        conn: &rusqlite::Connection,
        tenant_id: &str,
        allocation_id: &str,
    ) -> Result<()> {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM allocations WHERE id = ?1 AND tenant_id = ?2",
                params![allocation_id, tenant_id],
                |row| row.get(0),
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        if !exists {
            return Err(NetcidrError::AllocationNotFound(allocation_id.to_string()));
        }
        Ok(())
    }
}

fn row_to_hostname_pointer(row: &rusqlite::Row<'_>) -> rusqlite::Result<HostnamePointer> {
    Ok(HostnamePointer {
        id: row.get("id")?,
        tenant_id: row.get("tenant_id")?,
        ip_address: row.get("ip_address")?,
        hostname: row.get("hostname")?,
        allocation_id: row.get("allocation_id")?,
        notes: row.get("notes")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn row_to_hostname_history(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<HostnamePointerHistoryEntry> {
    let kind_str: String = row.get("change_kind")?;
    let change_kind = kind_str.parse::<ChangeKind>().unwrap_or(ChangeKind::Update);
    Ok(HostnamePointerHistoryEntry {
        id: row.get("id")?,
        tenant_id: row.get("tenant_id")?,
        pointer_id: row.get("pointer_id")?,
        ip_address: row.get("ip_address")?,
        hostname: row.get("hostname")?,
        change_kind,
        previous_value: row.get("previous_value")?,
        new_value: row.get("new_value")?,
        actor: row.get("actor")?,
        changed_at: row.get("changed_at")?,
    })
}

/// Build a connection pool whose every connection waits up to
/// `lock_timeout` on a locked database and enforces foreign keys. Both are
/// per-connection settings in SQLite, so they belong in the pool's init
/// hook rather than a one-off statement.
fn build_pool(
    manager: SqliteConnectionManager,
    max_size: u32,
    lock_timeout: Duration,
) -> Result<ConnPool> {
    let manager = manager.with_init(move |c| {
        c.busy_timeout(lock_timeout)?;
        c.execute_batch("PRAGMA foreign_keys=ON;")
    });
    Pool::builder()
        .max_size(max_size)
        .connection_timeout(lock_timeout)
        .build(manager)
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
}

/// Map a rusqlite error, classifying lock contention as `StoreBusy`.
fn db_err(e: rusqlite::Error) -> NetcidrError {
    match &e {
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(
                f.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            NetcidrError::StoreBusy
        }
        _ => NetcidrError::DatabaseError(e.to_string()),
    }
}

fn read_cidr_block(conn: &Connection, tenant_id: &str, id: &str) -> Result<Option<CidrBlock>> {
    conn.query_row(
        "SELECT id, tenant_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, name, description, ip_version, created_at, updated_at FROM cidr_blocks WHERE id = ?1 AND tenant_id = ?2",
        params![id, tenant_id],
        |row| {
            let total_hosts_text: String = row.get(6)?;
            Ok(CidrBlock {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                cidr: row.get(2)?,
                network_address: row.get(3)?,
                broadcast_address: row.get(4)?,
                prefix_length: row.get(5)?,
                total_hosts: read_total_hosts(Some(total_hosts_text), 0),
                name: row.get(7)?,
                description: row.get(8)?,
                ip_version: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        },
    )
    .optional()
    .map_err(db_err)
}

fn read_idempotency(
    conn: &Connection,
    tenant_id: &str,
    key: &str,
    scope: &str,
) -> Result<Option<IdempotencyRecord>> {
    conn.query_row(
        "SELECT tenant_id, key, scope, request_hash, status_code, response_body, created_at, expires_at \
         FROM idempotency_keys WHERE tenant_id = ?1 AND key = ?2 AND scope = ?3",
        params![tenant_id, key, scope],
        |row| {
            let status_code: i64 = row.get(4)?;
            Ok(IdempotencyRecord {
                tenant_id: row.get(0)?,
                key: row.get(1)?,
                scope: row.get(2)?,
                request_hash: row.get(3)?,
                status_code: status_code as u16,
                response_body: row.get(5)?,
                created_at: row.get(6)?,
                expires_at: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(db_err)
}

fn insert_audit(conn: &Connection, entry: &AuditEntry) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_log (tenant_id, timestamp, action, entity_type, entity_id, details, caller_sub, caller_email, source_ip, request_id, auth_method, pat_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            entry.tenant_id,
            entry.timestamp,
            entry.action,
            entry.entity_type,
            entry.entity_id,
            entry.details,
            entry.caller_sub,
            entry.caller_email,
            entry.source_ip,
            entry.request_id,
            if entry.auth_method.is_empty() { "oidc".to_string() } else { entry.auth_method.clone() },
            entry.pat_id,
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn put_idempotency(conn: &Connection, record: &IdempotencyRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO idempotency_keys \
            (tenant_id, key, scope, request_hash, status_code, response_body, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT(tenant_id, key, scope) DO UPDATE SET request_hash = ?4, status_code = ?5, \
             response_body = ?6, created_at = ?7, expires_at = ?8",
        params![
            record.tenant_id,
            record.key,
            record.scope,
            record.request_hash,
            record.status_code as i64,
            record.response_body,
            record.created_at,
            record.expires_at,
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn read_cidr_blocks(
    conn: &Connection,
    tenant_id: &str,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<CidrBlock>> {
    let sql = format!(
        "SELECT id, tenant_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, name, description, ip_version, created_at, updated_at FROM cidr_blocks WHERE tenant_id = ?1 ORDER BY created_at{}",
        crate::ipam::store::limit_offset_clause(limit, offset)
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(params![tenant_id], |row| {
            let total_hosts_text: String = row.get(6)?;
            Ok(CidrBlock {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                cidr: row.get(2)?,
                network_address: row.get(3)?,
                broadcast_address: row.get(4)?,
                prefix_length: row.get(5)?,
                total_hosts: read_total_hosts(Some(total_hosts_text), 0),
                name: row.get(7)?,
                description: row.get(8)?,
                ip_version: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })
        .map_err(db_err)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_err)?;
    Ok(rows)
}

fn insert_cidr_block(conn: &Connection, b: &CidrBlock) -> Result<()> {
    conn.execute(
        "INSERT INTO cidr_blocks (id, tenant_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, name, description, ip_version, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            b.id, b.tenant_id, b.cidr, b.network_address, b.broadcast_address, b.prefix_length,
            b.total_hosts.to_string(), b.name, b.description, b.ip_version, b.created_at,
            b.updated_at
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn delete_cidr_block_rows(conn: &Connection, tenant_id: &str, id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM allocation_tags WHERE allocation_id IN (SELECT id FROM allocations WHERE cidr_block_id = ?1 AND tenant_id = ?2)",
        params![id, tenant_id],
    )
    .map_err(db_err)?;
    conn.execute(
        "DELETE FROM allocations WHERE cidr_block_id = ?1 AND tenant_id = ?2",
        params![id, tenant_id],
    )
    .map_err(db_err)?;
    let deleted = conn
        .execute(
            "DELETE FROM cidr_blocks WHERE id = ?1 AND tenant_id = ?2",
            params![id, tenant_id],
        )
        .map_err(db_err)?;
    if deleted == 0 {
        return Err(NetcidrError::CidrBlockNotFound(id.to_string()));
    }
    Ok(())
}

fn read_allocation(conn: &Connection, tenant_id: &str, id: &str) -> Result<Option<Allocation>> {
    let alloc = conn
        .query_row(
            "SELECT id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE id = ?1 AND tenant_id = ?2",
            params![id, tenant_id],
            SqliteStore::row_to_allocation,
        )
        .optional()
        .map_err(db_err)?;
    match alloc {
        Some(mut a) => {
            a.tags = SqliteStore::load_tags_for_allocation(conn, tenant_id, id)?;
            Ok(Some(a))
        }
        None => Ok(None),
    }
}

fn read_allocations_in_block(
    conn: &Connection,
    tenant_id: &str,
    cidr_block_id: &str,
    statuses: &[AllocationStatus],
) -> Result<Vec<Allocation>> {
    if statuses.is_empty() {
        return Ok(Vec::new());
    }
    // ?1 = cidr_block_id, ?2 = tenant_id, statuses start at ?3.
    let placeholders: Vec<String> = (0..statuses.len()).map(|i| format!("?{}", i + 3)).collect();
    let sql = format!(
        "SELECT id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE cidr_block_id = ?1 AND tenant_id = ?2 AND status IN ({}) ORDER BY network_address",
        placeholders.join(", ")
    );
    let mut values: Vec<String> = vec![cidr_block_id.to_string(), tenant_id.to_string()];
    values.extend(statuses.iter().map(|s| s.to_string()));
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let mut allocations = stmt
        .query_map(
            rusqlite::params_from_iter(values.iter()),
            SqliteStore::row_to_allocation,
        )
        .map_err(db_err)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_err)?;
    for alloc in &mut allocations {
        alloc.tags = SqliteStore::load_tags_for_allocation(conn, tenant_id, &alloc.id)?;
    }
    Ok(allocations)
}

fn insert_allocation(conn: &Connection, a: &Allocation) -> Result<()> {
    conn.execute(
        "INSERT INTO allocations (id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            a.id, a.tenant_id, a.cidr_block_id, a.cidr, a.network_address, a.broadcast_address,
            a.prefix_length, a.total_hosts.to_string(), a.resource_id, a.resource_type, a.name,
            a.description, a.environment, a.owner, a.status.to_string(), a.parent_allocation_id,
            a.created_at, a.updated_at, a.released_at, a.expires_at
        ],
    )
    .map_err(db_err)?;
    insert_tags(conn, &a.tenant_id, &a.id, &a.tags)
}

fn insert_tags(
    conn: &Connection,
    tenant_id: &str,
    allocation_id: &str,
    tags: &[Tag],
) -> Result<()> {
    for tag in tags {
        conn.execute(
            "INSERT INTO allocation_tags (allocation_id, tenant_id, key, value) VALUES (?1, ?2, ?3, ?4)",
            params![allocation_id, tenant_id, tag.key, tag.value],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

fn replace_tags(
    conn: &Connection,
    tenant_id: &str,
    allocation_id: &str,
    tags: &[Tag],
) -> Result<()> {
    conn.execute(
        "DELETE FROM allocation_tags WHERE allocation_id = ?1 AND tenant_id = ?2",
        params![allocation_id, tenant_id],
    )
    .map_err(db_err)?;
    insert_tags(conn, tenant_id, allocation_id, tags)
}

fn replace_allocation(conn: &Connection, a: &Allocation) -> Result<()> {
    let updated = conn
        .execute(
            "UPDATE allocations SET status = ?1, resource_id = ?2, resource_type = ?3, name = ?4, description = ?5, environment = ?6, owner = ?7, updated_at = ?8, released_at = ?9, expires_at = ?10 WHERE id = ?11 AND tenant_id = ?12",
            params![
                a.status.to_string(), a.resource_id, a.resource_type, a.name, a.description,
                a.environment, a.owner, a.updated_at, a.released_at, a.expires_at, a.id, a.tenant_id
            ],
        )
        .map_err(db_err)?;
    if updated == 0 {
        return Err(NetcidrError::AllocationNotFound(a.id.clone()));
    }
    Ok(())
}

const USER_COLUMNS: &str = "email, role, status, created_at, updated_at, created_by, updated_by";

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserColumns> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

type UserColumns = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

fn user_from_columns(
    (email, role, status, created_at, updated_at, created_by, updated_by): UserColumns,
) -> Result<UserRecord> {
    Ok(UserRecord {
        email,
        role: role.parse::<crate::auth::Role>()?,
        status: status.parse::<UserStatus>()?,
        created_at,
        updated_at,
        created_by,
        updated_by,
    })
}

fn read_user(conn: &Connection, email: &str) -> Result<Option<UserRecord>> {
    conn.query_row(
        &format!("SELECT {USER_COLUMNS} FROM users WHERE email = ?1"),
        params![email],
        row_to_user,
    )
    .optional()
    .map_err(db_err)?
    .map(user_from_columns)
    .transpose()
}

fn read_users(conn: &Connection) -> Result<Vec<UserRecord>> {
    let mut stmt = conn
        .prepare(&format!("SELECT {USER_COLUMNS} FROM users ORDER BY email"))
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], row_to_user)
        .map_err(db_err)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_err)?;
    rows.into_iter().map(user_from_columns).collect()
}

fn read_active_platform_admin_count(conn: &Connection) -> Result<u64> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'platform_admin' AND status = 'active'",
            [],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    Ok(n as u64)
}

fn read_bootstrap_marker(conn: &Connection, key: &str) -> Result<bool> {
    let found: Option<String> = conn
        .query_row(
            "SELECT key FROM bootstrap_markers WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_err)?;
    Ok(found.is_some())
}

fn put_user(conn: &Connection, u: &UserRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO users (email, role, status, created_at, updated_at, created_by, updated_by) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT(email) DO UPDATE SET role = ?2, status = ?3, created_at = ?4, \
             updated_at = ?5, created_by = ?6, updated_by = ?7",
        params![
            u.email,
            u.role.as_str(),
            u.status.as_str(),
            u.created_at,
            u.updated_at,
            u.created_by,
            u.updated_by
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn delete_user_row(conn: &Connection, email: &str) -> Result<()> {
    let deleted = conn
        .execute("DELETE FROM users WHERE email = ?1", params![email])
        .map_err(db_err)?;
    if deleted == 0 {
        return Err(NetcidrError::UserNotFound(email.to_string()));
    }
    Ok(())
}

fn set_bootstrap_marker(conn: &Connection, key: &str, applied_at: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO bootstrap_markers (key, applied_at) VALUES (?1, ?2)",
        params![key, applied_at],
    )
    .map_err(db_err)?;
    Ok(())
}

fn read_pat(
    conn: &Connection,
    tenant_id: &str,
    owner_sub: &str,
    id: &str,
) -> Result<Option<PersonalAccessToken>> {
    conn.query_row(
        "SELECT id, tenant_id, owner_sub, owner_email, name, prefix, token_hash, \
                role, created_at, expires_at, last_used_at, revoked_at \
         FROM personal_access_tokens \
         WHERE id = ?1 AND tenant_id = ?2 AND owner_sub = ?3",
        params![id, tenant_id, owner_sub],
        row_to_pat,
    )
    .optional()
    .map_err(db_err)
}

fn read_active_pat_count(
    conn: &Connection,
    tenant_id: &str,
    owner_sub: &str,
    now: &str,
) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM personal_access_tokens \
             WHERE tenant_id = ?1 AND owner_sub = ?2 \
               AND revoked_at IS NULL AND expires_at > ?3",
            params![tenant_id, owner_sub, now],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    Ok(count as u64)
}

fn insert_pat(conn: &Connection, p: &PersonalAccessToken) -> Result<()> {
    conn.execute(
        "INSERT INTO personal_access_tokens
            (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
             role, created_at, expires_at, last_used_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            p.id,
            p.tenant_id,
            p.owner_sub,
            p.owner_email,
            p.name,
            p.prefix,
            p.token_hash,
            p.role.as_str(),
            p.created_at,
            p.expires_at,
            p.last_used_at,
            p.revoked_at,
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn revoke_pat(
    conn: &Connection,
    tenant_id: &str,
    owner_sub: &str,
    id: &str,
    revoked_at: &str,
) -> Result<()> {
    let updated = conn
        .execute(
            "UPDATE personal_access_tokens SET revoked_at = ?1 \
             WHERE id = ?2 AND tenant_id = ?3 AND owner_sub = ?4",
            params![revoked_at, id, tenant_id, owner_sub],
        )
        .map_err(db_err)?;
    if updated == 0 {
        return Err(NetcidrError::PatNotFound(id.to_string()));
    }
    Ok(())
}

fn read_hostname_pointer(
    conn: &Connection,
    tenant_id: &str,
    ip_address: &str,
    hostname: &str,
) -> Result<Option<HostnamePointer>> {
    conn.query_row(
        "SELECT id, tenant_id, ip_address, hostname, allocation_id, notes, created_at, updated_at \
         FROM hostname_pointers WHERE tenant_id = ?1 AND ip_address = ?2 AND hostname = ?3",
        params![tenant_id, ip_address, hostname],
        row_to_hostname_pointer,
    )
    .optional()
    .map_err(db_err)
}

fn put_hostname_pointer(conn: &Connection, p: &HostnamePointer) -> Result<()> {
    conn.execute(
        "INSERT INTO hostname_pointers \
         (id, tenant_id, ip_address, hostname, allocation_id, notes, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT(id) DO UPDATE SET allocation_id = ?5, notes = ?6, updated_at = ?8 \
         WHERE hostname_pointers.tenant_id = ?2",
        params![
            p.id,
            p.tenant_id,
            p.ip_address,
            p.hostname,
            p.allocation_id,
            p.notes,
            p.created_at,
            p.updated_at
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn delete_hostname_pointer_row(conn: &Connection, tenant_id: &str, id: &str) -> Result<()> {
    let deleted = conn
        .execute(
            "DELETE FROM hostname_pointers WHERE id = ?1 AND tenant_id = ?2",
            params![id, tenant_id],
        )
        .map_err(db_err)?;
    if deleted == 0 {
        return Err(NetcidrError::HostnamePointerNotFound(id.to_string()));
    }
    Ok(())
}

fn append_hostname_history(conn: &Connection, h: &HostnamePointerHistoryEntry) -> Result<()> {
    conn.execute(
        "INSERT INTO hostname_pointer_history \
         (id, tenant_id, pointer_id, ip_address, hostname, change_kind, previous_value, new_value, actor, changed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            h.id,
            h.tenant_id,
            h.pointer_id,
            h.ip_address,
            h.hostname,
            h.change_kind.to_string(),
            h.previous_value,
            h.new_value,
            h.actor,
            h.changed_at
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn read_one(conn: &Connection, read: &Read) -> Result<Rows> {
    match read {
        Read::CidrBlock { tenant_id, id } => {
            Ok(Rows::CidrBlock(read_cidr_block(conn, tenant_id, id)?))
        }
        Read::CidrBlocks { tenant_id } => Ok(Rows::CidrBlocks(read_cidr_blocks(
            conn, tenant_id, None, None,
        )?)),
        Read::Allocation { tenant_id, id } => {
            Ok(Rows::Allocation(read_allocation(conn, tenant_id, id)?))
        }
        Read::AllocationsInBlock {
            tenant_id,
            cidr_block_id,
            statuses,
        } => Ok(Rows::Allocations(read_allocations_in_block(
            conn,
            tenant_id,
            cidr_block_id,
            statuses,
        )?)),
        Read::User { email } => Ok(Rows::User(read_user(conn, email)?)),
        Read::Users => Ok(Rows::Users(read_users(conn)?)),
        Read::ActivePlatformAdminCount => Ok(Rows::Count(read_active_platform_admin_count(conn)?)),
        Read::BootstrapMarker { key } => Ok(Rows::Flag(read_bootstrap_marker(conn, key)?)),
        Read::Pat {
            tenant_id,
            owner_sub,
            id,
        } => Ok(Rows::Pat(read_pat(conn, tenant_id, owner_sub, id)?)),
        Read::ActivePatCount {
            tenant_id,
            owner_sub,
            now,
        } => Ok(Rows::Count(read_active_pat_count(
            conn, tenant_id, owner_sub, now,
        )?)),
        Read::HostnamePointer {
            tenant_id,
            ip_address,
            hostname,
        } => Ok(Rows::HostnamePointer(read_hostname_pointer(
            conn, tenant_id, ip_address, hostname,
        )?)),
    }
}

fn apply_write(conn: &Connection, write: &Write) -> Result<()> {
    match write {
        Write::InsertCidrBlock(b) => insert_cidr_block(conn, b),
        Write::DeleteCidrBlock { tenant_id, id } => delete_cidr_block_rows(conn, tenant_id, id),
        Write::InsertAllocation(a) => insert_allocation(conn, a),
        Write::ReplaceAllocation(a) => replace_allocation(conn, a),
        Write::ReplaceTags {
            tenant_id,
            allocation_id,
            tags,
        } => replace_tags(conn, tenant_id, allocation_id, tags),
        Write::PutUser(u) => put_user(conn, u),
        Write::DeleteUser { email } => delete_user_row(conn, email),
        Write::SetBootstrapMarker { key, applied_at } => {
            set_bootstrap_marker(conn, key, applied_at)
        }
        Write::InsertPat(p) => insert_pat(conn, p),
        Write::RevokePat {
            tenant_id,
            owner_sub,
            id,
            revoked_at,
        } => revoke_pat(conn, tenant_id, owner_sub, id, revoked_at),
        Write::PutHostnamePointer(p) => put_hostname_pointer(conn, p),
        Write::DeleteHostnamePointer { tenant_id, id } => {
            delete_hostname_pointer_row(conn, tenant_id, id)
        }
        Write::AppendHostnameHistory(h) => append_hostname_history(conn, h),
    }
}

/// Run a transaction unit to completion on the calling (blocking) thread.
/// `BEGIN IMMEDIATE` takes SQLite's database-wide write lock up front, which
/// covers every Lock Scope; `busy_timeout` bounds the wait for it.
fn run_unit(pool: &ConnPool, unit: TxUnit) -> Result<String> {
    let mut conn = pool.get().map_err(|_| NetcidrError::StoreBusy)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(db_err)?;
    let rows = unit
        .reads
        .iter()
        .map(|r| read_one(&tx, r))
        .collect::<Result<Vec<_>>>()?;
    let idempotency = match &unit.idempotency {
        Some(l) => read_idempotency(&tx, &l.tenant_id, &l.key, &l.scope)?,
        None => None,
    };
    // An `Err` here drops `tx`, which rolls back.
    let plan = (unit.decide)(Loaded { rows, idempotency })?;
    for write in &plan.writes {
        apply_write(&tx, write)?;
    }
    for entry in &plan.audits {
        insert_audit(&tx, entry)?;
    }
    if let Some(record) = &plan.idempotency {
        put_idempotency(&tx, record)?;
    }
    tx.commit().map_err(db_err)?;
    Ok(plan.output_json)
}

#[async_trait]
impl IpamStore for SqliteStore {
    async fn initialize(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn migrate(&self) -> Result<()> {
        let conn = self.conn()?;

        // Ensure schema_version table exists
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )",
        )
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let current: u32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        for &(version, sql) in migrations::MIGRATIONS {
            if version > current {
                conn.execute_batch(sql)
                    .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    params![version, Self::now()],
                )
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            }
        }
        Ok(())
    }

    // --- cidr_blocks ---

    async fn transact(&self, unit: TxUnit) -> Result<String> {
        // The whole unit runs on one blocking thread, so the rusqlite
        // transaction never crosses an `.await` (ADR-0007). The spawned task
        // finishes or rolls back even if this future is dropped.
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || run_unit(&pool, unit))
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("transaction task failed: {e}")))?
    }

    async fn get_cidr_block(&self, tenant_id: &str, id: &str) -> Result<CidrBlock> {
        {
            let conn = self.conn()?;
            read_cidr_block(&conn, tenant_id, id)
        }?
        .ok_or_else(|| NetcidrError::CidrBlockNotFound(id.to_string()))
    }

    async fn list_cidr_blocks(&self, tenant_id: &str) -> Result<Vec<CidrBlock>> {
        self.list_cidr_blocks_page(tenant_id, None, None).await
    }

    async fn list_cidr_blocks_page(
        &self,
        tenant_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<CidrBlock>> {
        let conn = self.conn()?;
        read_cidr_blocks(&conn, tenant_id, limit, offset)
    }

    // --- allocations ---

    async fn get_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation> {
        let conn = self.conn()?;
        read_allocation(&conn, tenant_id, id)?
            .ok_or_else(|| NetcidrError::AllocationNotFound(id.to_string()))
    }

    async fn list_allocations(
        &self,
        tenant_id: &str,
        filter: &AllocationFilter,
    ) -> Result<Vec<Allocation>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE tenant_id = ?1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        param_values.push(Box::new(tenant_id.to_string()));
        let mut idx = 2;

        if let Some(ref sid) = filter.cidr_block_id {
            sql.push_str(&format!(" AND cidr_block_id = ?{}", idx));
            param_values.push(Box::new(sid.clone()));
            idx += 1;
        }
        if let Some(ref status) = filter.status {
            sql.push_str(&format!(" AND status = ?{}", idx));
            param_values.push(Box::new(status.to_string()));
            idx += 1;
        }
        if let Some(ref rid) = filter.resource_id {
            sql.push_str(&format!(" AND resource_id = ?{}", idx));
            param_values.push(Box::new(rid.clone()));
            idx += 1;
        }
        if let Some(ref rt) = filter.resource_type {
            sql.push_str(&format!(" AND resource_type = ?{}", idx));
            param_values.push(Box::new(rt.clone()));
            idx += 1;
        }
        if let Some(ref env) = filter.environment {
            sql.push_str(&format!(" AND environment = ?{}", idx));
            param_values.push(Box::new(env.clone()));
            idx += 1;
        }
        if let Some(ref owner) = filter.owner {
            sql.push_str(&format!(" AND owner = ?{}", idx));
            param_values.push(Box::new(owner.clone()));
            #[allow(unused_assignments)]
            {
                idx += 1;
            }
        }

        sql.push_str(" ORDER BY created_at");
        sql.push_str(&crate::ipam::store::limit_offset_clause(
            filter.limit,
            filter.offset,
        ));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map(params_refs.as_slice(), Self::row_to_allocation)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        // Load tags for each allocation
        let mut allocations = rows;
        for alloc in &mut allocations {
            alloc.tags = Self::load_tags_for_allocation(&conn, tenant_id, &alloc.id)?;
        }
        Ok(allocations)
    }

    async fn find_allocations_in_cidr_block(
        &self,
        tenant_id: &str,
        cidr_block_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>> {
        let conn = self.conn()?;
        read_allocations_in_block(&conn, tenant_id, cidr_block_id, statuses)
    }

    async fn get_tags(&self, tenant_id: &str, allocation_id: &str) -> Result<Vec<Tag>> {
        let conn = self.conn()?;
        Self::assert_allocation_in_tenant(&conn, tenant_id, allocation_id)?;
        Self::load_tags_for_allocation(&conn, tenant_id, allocation_id)
    }

    // --- hostname pointers ---

    async fn list_hostname_pointers(
        &self,
        tenant_id: &str,
        filter: &HostnamePointerFilter,
    ) -> Result<Vec<HostnamePointer>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, tenant_id, ip_address, hostname, allocation_id, notes, created_at, updated_at \
             FROM hostname_pointers WHERE tenant_id = ?1",
        );
        let mut binds: Vec<String> = vec![tenant_id.to_string()];
        if let Some(ref ip) = filter.ip_address {
            binds.push(ip.clone());
            sql.push_str(&format!(" AND ip_address = ?{}", binds.len()));
        }
        if let Some(ref h) = filter.hostname {
            binds.push(h.clone());
            sql.push_str(&format!(" AND hostname = ?{}", binds.len()));
        }
        if let Some(ref a) = filter.allocation_id {
            binds.push(a.clone());
            sql.push_str(&format!(" AND allocation_id = ?{}", binds.len()));
        }
        sql.push_str(" ORDER BY hostname, ip_address");
        sql.push_str(&crate::ipam::store::limit_offset_clause(
            filter.limit,
            filter.offset,
        ));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let params_ref = rusqlite::params_from_iter(binds.iter());
        let rows = stmt
            .query_map(params_ref, row_to_hostname_pointer)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows)
    }

    async fn list_hostname_history(
        &self,
        tenant_id: &str,
        filter: &HostnameHistoryFilter,
    ) -> Result<Vec<HostnamePointerHistoryEntry>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, tenant_id, pointer_id, ip_address, hostname, change_kind, previous_value, new_value, actor, changed_at \
             FROM hostname_pointer_history WHERE tenant_id = ?1",
        );
        let mut binds: Vec<String> = vec![tenant_id.to_string()];
        if let Some(ref ip) = filter.ip_address {
            binds.push(ip.clone());
            sql.push_str(&format!(" AND ip_address = ?{}", binds.len()));
        }
        if let Some(ref h) = filter.hostname {
            binds.push(h.clone());
            sql.push_str(&format!(" AND hostname = ?{}", binds.len()));
        }
        sql.push_str(" ORDER BY changed_at");
        sql.push_str(&crate::ipam::store::limit_offset_clause(
            filter.limit,
            filter.offset,
        ));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let params_ref = rusqlite::params_from_iter(binds.iter());
        let rows = stmt
            .query_map(params_ref, row_to_hostname_history)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows)
    }

    // --- users directory (unified allowlist + roles; ADR-0006) ---

    async fn get_user(&self, email: &str) -> Result<Option<UserRecord>> {
        let conn = self.conn()?;
        read_user(&conn, &email.to_ascii_lowercase())
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let conn = self.conn()?;
        read_users(&conn)
    }

    async fn count_active_platform_admins(&self) -> Result<u64> {
        let conn = self.conn()?;
        read_active_platform_admin_count(&conn)
    }

    // --- audit ---

    async fn query_audit(&self, tenant_id: &str, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, tenant_id, timestamp, action, entity_type, entity_id, details, caller_sub, caller_email, source_ip, request_id, auth_method, pat_id FROM audit_log WHERE tenant_id = ?1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        param_values.push(Box::new(tenant_id.to_string()));
        let mut idx = 2;

        if let Some(ref et) = filter.entity_type {
            sql.push_str(&format!(" AND entity_type = ?{}", idx));
            param_values.push(Box::new(et.clone()));
            idx += 1;
        }
        if let Some(ref eid) = filter.entity_id {
            sql.push_str(&format!(" AND entity_id = ?{}", idx));
            param_values.push(Box::new(eid.clone()));
            idx += 1;
        }
        if let Some(ref action) = filter.action {
            sql.push_str(&format!(" AND action = ?{}", idx));
            param_values.push(Box::new(action.clone()));
            idx += 1;
        }
        if let Some(ref email) = filter.caller_email {
            sql.push_str(&format!(" AND caller_email = ?{}", idx));
            param_values.push(Box::new(email.clone()));
            idx += 1;
        }
        if let Some(ref pat_id) = filter.pat_id {
            sql.push_str(&format!(" AND pat_id = ?{}", idx));
            param_values.push(Box::new(pat_id.clone()));
            idx += 1;
        }

        sql.push_str(" ORDER BY id DESC");

        if let Some(limit) = filter.limit {
            // Cap to prevent full-table-scan DoS; bind as parameter to avoid interpolation.
            let capped = limit.min(10_000);
            sql.push_str(&format!(" LIMIT ?{}", idx));
            param_values.push(Box::new(capped as i64));
        }

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let id_int: i64 = row.get(0)?;
                Ok(AuditEntry {
                    id: id_int.to_string(),
                    tenant_id: row.get(1)?,
                    timestamp: row.get(2)?,
                    action: row.get(3)?,
                    entity_type: row.get(4)?,
                    entity_id: row.get(5)?,
                    details: row.get(6)?,
                    caller_sub: row.get(7)?,
                    caller_email: row.get(8)?,
                    source_ip: row.get(9)?,
                    request_id: row.get(10)?,
                    auth_method: row.get(11)?,
                    pat_id: row.get(12)?,
                })
            })
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows)
    }

    async fn idempotency_get(
        &self,
        tenant_id: &str,
        key: &str,
        scope: &str,
    ) -> Result<Option<IdempotencyRecord>> {
        {
            let conn = self.conn()?;
            read_idempotency(&conn, tenant_id, key, scope)
        }
    }

    async fn idempotency_reap_expired(&self, now_rfc3339: &str) -> Result<u64> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "DELETE FROM idempotency_keys WHERE expires_at <= ?1",
                params![now_rfc3339],
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(n as u64)
    }

    // --- personal access tokens ---

    async fn pat_count_active_for_owner(
        &self,
        tenant_id: &str,
        owner_sub: &str,
        now_rfc3339: &str,
    ) -> Result<u32> {
        let conn = self.conn()?;
        Ok(read_active_pat_count(&conn, tenant_id, owner_sub, now_rfc3339)? as u32)
    }

    async fn pat_get_by_hash(
        &self,
        token_hash: &[u8],
        now_rfc3339: &str,
    ) -> Result<Option<PersonalAccessToken>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, tenant_id, owner_sub, owner_email, name, prefix, token_hash, \
                        role, created_at, expires_at, last_used_at, revoked_at \
                 FROM personal_access_tokens \
                 WHERE token_hash = ?1 AND revoked_at IS NULL AND expires_at > ?2",
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let mut rows = stmt
            .query(params![token_hash, now_rfc3339])
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
        {
            Ok(Some(
                row_to_pat(row).map_err(|e| NetcidrError::DatabaseError(e.to_string()))?,
            ))
        } else {
            Ok(None)
        }
    }

    async fn pat_list_for_owner(
        &self,
        tenant_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<PersonalAccessToken>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, tenant_id, owner_sub, owner_email, name, prefix, token_hash, \
                        role, created_at, expires_at, last_used_at, revoked_at \
                 FROM personal_access_tokens \
                 WHERE tenant_id = ?1 AND owner_sub = ?2 \
                 ORDER BY created_at",
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map(params![tenant_id, owner_sub], row_to_pat)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows)
    }

    async fn pat_touch_last_used(&self, id: &str, now_rfc3339: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE personal_access_tokens SET last_used_at = ?1 WHERE id = ?2",
            params![now_rfc3339, id],
        )
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn pat_reap_expired(&self, before_rfc3339: &str) -> Result<u64> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "DELETE FROM personal_access_tokens WHERE expires_at < ?1",
                params![before_rfc3339],
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(n as u64)
    }
}

/// Map a `personal_access_tokens` row to the model. Free function (not a
/// method) so it can be used directly with `query_map`.
fn row_to_pat(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalAccessToken> {
    let role_str: String = row.get(7)?;
    let role = role_str.parse::<crate::auth::Role>().map_err(|e| {
        // CHECK constraint guarantees the column is one of the enum variants,
        // so this should be unreachable in practice — surface as a column-type
        // error rather than DatabaseError so the SqliteStore mapping layer
        // converts it cleanly.
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )),
        )
    })?;
    Ok(PersonalAccessToken {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        owner_sub: row.get(2)?,
        owner_email: row.get(3)?,
        name: row.get(4)?,
        prefix: row.get(5)?,
        token_hash: row.get(6)?,
        role,
        created_at: row.get(8)?,
        expires_at: row.get(9)?,
        last_used_at: row.get(10)?,
        revoked_at: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::parse_cidr_metadata;

    const TEST_TENANT: &str = "test@example.com";

    /// Seed rows straight through `transact`, without `IpamOps`'s rules —
    /// what the store's old create/delete methods did.
    trait Seed {
        async fn create_cidr_block(
            &self,
            tenant_id: &str,
            input: &CreateCidrBlock,
        ) -> Result<CidrBlock>;
        async fn create_allocation(
            &self,
            tenant_id: &str,
            input: &CreateAllocation,
        ) -> Result<Allocation>;
        async fn delete_cidr_block(&self, tenant_id: &str, id: &str) -> Result<()>;
        async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
        async fn pat_create(
            &self,
            input: &CreatePersonalAccessToken,
        ) -> Result<PersonalAccessToken>;
        async fn pat_revoke(
            &self,
            tenant_id: &str,
            owner_sub: &str,
            id: &str,
            revoked_at: &str,
        ) -> Result<()>;
    }

    async fn commit(store: &SqliteStore, tenant_id: &str, write: Write) -> Result<()> {
        store
            .transact(TxUnit {
                scope: crate::ipam::store::LockScope::Tenant {
                    tenant_id: tenant_id.to_string(),
                },
                reads: vec![],
                idempotency: None,
                decide: Box::new(move |_| {
                    Ok(crate::ipam::store::Plan {
                        writes: vec![write],
                        ..Default::default()
                    })
                }),
            })
            .await
            .map(|_| ())
    }

    impl Seed for SqliteStore {
        async fn create_cidr_block(
            &self,
            tenant_id: &str,
            input: &CreateCidrBlock,
        ) -> Result<CidrBlock> {
            let block = CidrBlock::from_input(
                tenant_id,
                input,
                uuid::Uuid::new_v4().to_string(),
                Utc::now(),
            )?;
            commit(self, tenant_id, Write::InsertCidrBlock(block.clone())).await?;
            Ok(block)
        }

        async fn create_allocation(
            &self,
            tenant_id: &str,
            input: &CreateAllocation,
        ) -> Result<Allocation> {
            let alloc = Allocation::from_input(
                tenant_id,
                input,
                uuid::Uuid::new_v4().to_string(),
                Utc::now(),
            )?;
            commit(self, tenant_id, Write::InsertAllocation(alloc.clone())).await?;
            Ok(alloc)
        }

        async fn delete_cidr_block(&self, tenant_id: &str, id: &str) -> Result<()> {
            commit(
                self,
                tenant_id,
                Write::DeleteCidrBlock {
                    tenant_id: tenant_id.to_string(),
                    id: id.to_string(),
                },
            )
            .await
        }

        async fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
            let entry = entry.clone();
            self.transact(TxUnit {
                scope: crate::ipam::store::LockScope::Tenant {
                    tenant_id: entry.tenant_id.clone(),
                },
                reads: vec![],
                idempotency: None,
                decide: Box::new(move |_| {
                    Ok(crate::ipam::store::Plan {
                        audits: vec![entry],
                        ..Default::default()
                    })
                }),
            })
            .await
            .map(|_| ())
        }

        async fn pat_create(
            &self,
            input: &CreatePersonalAccessToken,
        ) -> Result<PersonalAccessToken> {
            let row = PersonalAccessToken {
                id: uuid::Uuid::new_v4().to_string(),
                tenant_id: input.tenant_id.clone(),
                owner_sub: input.owner_sub.clone(),
                owner_email: input.owner_email.clone(),
                name: input.name.clone(),
                prefix: input.prefix.clone(),
                token_hash: input.token_hash.clone(),
                role: input.role,
                created_at: Utc::now().to_rfc3339(),
                expires_at: input.expires_at.clone(),
                last_used_at: None,
                revoked_at: None,
            };
            commit(self, &input.tenant_id, Write::InsertPat(row.clone())).await?;
            Ok(row)
        }

        async fn pat_revoke(
            &self,
            tenant_id: &str,
            owner_sub: &str,
            id: &str,
            revoked_at: &str,
        ) -> Result<()> {
            commit(
                self,
                tenant_id,
                Write::RevokePat {
                    tenant_id: tenant_id.to_string(),
                    owner_sub: owner_sub.to_string(),
                    id: id.to_string(),
                    revoked_at: revoked_at.to_string(),
                },
            )
            .await
        }
    }

    async fn test_store() -> SqliteStore {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    #[tokio::test]
    async fn list_pagination_limits_and_offsets() {
        let store = test_store().await;

        // Three cidr_blocks (ordered by created_at).
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            store
                .create_cidr_block(
                    TEST_TENANT,
                    &CreateCidrBlock {
                        cidr: cidr.to_string(),
                        name: None,
                        description: None,
                    },
                )
                .await
                .unwrap();
        }

        // Unbounded (None) returns all three.
        assert_eq!(
            store
                .list_cidr_blocks_page(TEST_TENANT, None, None)
                .await
                .unwrap()
                .len(),
            3
        );
        // limit caps the page.
        assert_eq!(
            store
                .list_cidr_blocks_page(TEST_TENANT, Some(2), None)
                .await
                .unwrap()
                .len(),
            2
        );
        // offset skips, so only the third remains.
        assert_eq!(
            store
                .list_cidr_blocks_page(TEST_TENANT, Some(10), Some(2))
                .await
                .unwrap()
                .len(),
            1
        );

        // Allocations under the first block.
        let block = &store.list_cidr_blocks(TEST_TENANT).await.unwrap()[0];
        for i in 0..5u8 {
            store
                .create_allocation(
                    TEST_TENANT,
                    &CreateAllocation {
                        cidr_block_id: block.id.clone(),
                        cidr: format!("10.0.{i}.0/24"),
                        status: None,
                        resource_id: None,
                        resource_type: None,
                        name: None,
                        description: None,
                        environment: None,
                        owner: None,
                        parent_allocation_id: None,
                        tags: None,
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();
        }
        let page = store
            .list_allocations(
                TEST_TENANT,
                &AllocationFilter {
                    cidr_block_id: Some(block.id.clone()),
                    limit: Some(3),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.len(), 3, "limit must cap the allocation page");
    }

    #[tokio::test]
    async fn allocation_tags_carry_tenant_and_trigger_enforces_match() {
        let store = test_store().await;
        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();
        let alloc = store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "10.0.0.0/24".to_string(),
                    status: None,
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: Some(vec![Tag {
                        key: "env".to_string(),
                        value: "prod".to_string(),
                    }]),
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        // Tags created via create_allocation are readable for the owning tenant
        // (the tenant-filtered read still works with the new column).
        let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
        assert_eq!(tags.len(), 1);

        // A different tenant cannot read or replace them (pre-check gate).
        assert!(
            store
                .get_tags("other@example.com", &alloc.id)
                .await
                .is_err()
        );

        // DB-level defense-in-depth: the trigger rejects a tag row whose
        // tenant_id does not match the parent allocation's, even via raw SQL.
        let conn = store.conn().unwrap();
        let res = conn.execute(
            "INSERT INTO allocation_tags (allocation_id, tenant_id, key, value) VALUES (?1, ?2, ?3, ?4)",
            params![alloc.id, "other@example.com", "x", "y"],
        );
        assert!(res.is_err(), "trigger must reject mismatched tenant_id");
    }

    #[cfg(unix)]
    #[test]
    fn new_creates_db_file_with_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("netcidr.db");
        let _store = SqliteStore::new(db_path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "db file should be owner-only, got {mode:o}");
    }

    #[tokio::test]
    async fn test_cidr_block_crud() {
        let store = test_store().await;

        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: Some("RFC1918 Class A".to_string()),
                    description: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(sn.cidr, "10.0.0.0/8");
        assert_eq!(sn.network_address, "10.0.0.0");
        assert_eq!(sn.broadcast_address, "10.255.255.255");
        assert_eq!(sn.prefix_length, 8);
        assert_eq!(sn.ip_version, 4);
        assert_eq!(sn.tenant_id, TEST_TENANT);

        let fetched = store.get_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
        assert_eq!(fetched.cidr, "10.0.0.0/8");

        let all = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
        assert_eq!(all.len(), 1);

        store.delete_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
        let all = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_allocation_crud() {
        let store = test_store().await;

        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();

        let alloc = store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "10.0.0.0/24".to_string(),
                    status: None,
                    resource_id: Some("vpc-123".to_string()),
                    resource_type: Some("vpc".to_string()),
                    name: Some("test".to_string()),
                    description: None,
                    environment: Some("production".to_string()),
                    owner: Some("team-a".to_string()),
                    parent_allocation_id: None,
                    tags: Some(vec![Tag {
                        key: "env".to_string(),
                        value: "prod".to_string(),
                    }]),
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(alloc.status, AllocationStatus::Active);
        assert_eq!(alloc.tags.len(), 1);
        assert_eq!(alloc.tenant_id, TEST_TENANT);

        let fetched = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
        assert_eq!(fetched.resource_id, Some("vpc-123".to_string()));
        assert_eq!(fetched.tags.len(), 1);

        // Update and release go through the operations layer.
        let ops = crate::ipam::operations::IpamOps::new(std::sync::Arc::new(store));
        let updated = ops
            .update_allocation(
                TEST_TENANT,
                &alloc.id,
                &UpdateAllocation {
                    name: None,
                    description: Some("updated desc".to_string()),
                    resource_id: None,
                    resource_type: None,
                    environment: None,
                    owner: None,
                    status: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.description, Some("updated desc".to_string()));

        // Release
        let released = ops
            .release_allocation(TEST_TENANT, &alloc.id)
            .await
            .unwrap();
        assert_eq!(released.status, AllocationStatus::Released);
        assert!(released.released_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_cidr_block_with_active_allocations_fails() {
        let store = test_store().await;

        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();

        store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "10.0.0.0/24".to_string(),
                    status: None,
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        // The rule lives in the operations layer, which deletes atomically
        // under the block's Lock Scope.
        let err = crate::ipam::operations::IpamOps::new(std::sync::Arc::new(store))
            .delete_cidr_block(TEST_TENANT, &sn.id)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NetcidrError::CidrBlockHasActiveAllocations(_)
        ));
    }

    #[tokio::test]
    async fn test_find_allocations_by_status() {
        let store = test_store().await;

        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();

        let a1 = store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "10.0.0.0/24".to_string(),
                    status: None,
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "10.0.1.0/24".to_string(),
                    status: Some(AllocationStatus::Reserved),
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        let store = std::sync::Arc::new(store);
        crate::ipam::operations::IpamOps::new(store.clone())
            .release_allocation(TEST_TENANT, &a1.id)
            .await
            .unwrap();

        let active = store
            .find_allocations_in_cidr_block(
                TEST_TENANT,
                &sn.id,
                &[AllocationStatus::Active, AllocationStatus::Reserved],
            )
            .await
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, AllocationStatus::Reserved);
    }

    #[tokio::test]
    async fn test_audit_log() {
        let store = test_store().await;

        store
            .append_audit(&AuditEntry {
                id: String::new(),
                tenant_id: TEST_TENANT.to_string(),
                entity_type: "cidr_block".to_string(),
                entity_id: "sn-1".to_string(),
                action: "create_cidr_block".to_string(),
                details: Some(r#"{"cidr":"10.0.0.0/8"}"#.to_string()),
                timestamp: "2026-03-04T00:00:00Z".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        let entries = store
            .query_audit(
                TEST_TENANT,
                &AuditFilter {
                    entity_id: Some("sn-1".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "create_cidr_block");
    }

    #[tokio::test]
    async fn test_tags() {
        let store = test_store().await;

        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();

        let alloc = store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "10.0.0.0/24".to_string(),
                    status: None,
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        commit(
            &store,
            TEST_TENANT,
            Write::ReplaceTags {
                tenant_id: TEST_TENANT.to_string(),
                allocation_id: alloc.id.clone(),
                tags: vec![
                    Tag {
                        key: "env".to_string(),
                        value: "prod".to_string(),
                    },
                    Tag {
                        key: "team".to_string(),
                        value: "platform".to_string(),
                    },
                ],
            },
        )
        .await
        .unwrap();

        let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
        assert_eq!(tags.len(), 2);

        // Replace tags
        commit(
            &store,
            TEST_TENANT,
            Write::ReplaceTags {
                tenant_id: TEST_TENANT.to_string(),
                allocation_id: alloc.id.clone(),
                tags: vec![Tag {
                    key: "env".to_string(),
                    value: "staging".to_string(),
                }],
            },
        )
        .await
        .unwrap();
        let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].value, "staging");
    }

    #[test]
    fn test_parse_cidr_metadata_v4() {
        let (net, bcast, prefix, total, ver) = parse_cidr_metadata("192.168.1.0/24").unwrap();
        assert_eq!(net, "192.168.1.0");
        assert_eq!(bcast, "192.168.1.255");
        assert_eq!(prefix, 24);
        assert_eq!(total, 256);
        assert_eq!(ver, 4);
    }

    #[test]
    fn test_parse_cidr_metadata_v6() {
        let (net, _bcast, prefix, total, ver) = parse_cidr_metadata("2001:db8::/32").unwrap();
        assert_eq!(net, "2001:db8::");
        assert_eq!(prefix, 32);
        // /32 has 2^96 addresses
        assert_eq!(total, 1u128 << 96);
        assert_eq!(ver, 6);
    }

    #[test]
    fn test_parse_cidr_metadata_v6_prefix_0() {
        // /0 is the entire IPv6 address space — must not panic
        let (_net, _bcast, prefix, total, ver) = parse_cidr_metadata("::/0").unwrap();
        assert_eq!(prefix, 0);
        assert_eq!(total, u128::MAX);
        assert_eq!(ver, 6);
    }

    #[test]
    fn test_parse_cidr_metadata_v6_prefix_128() {
        let (net, bcast, prefix, total, ver) = parse_cidr_metadata("2001:db8::1/128").unwrap();
        assert_eq!(net, "2001:db8::1");
        assert_eq!(bcast, "2001:db8::1");
        assert_eq!(prefix, 128);
        assert_eq!(total, 1);
        assert_eq!(ver, 6);
    }

    #[test]
    fn test_read_total_hosts_prefers_text() {
        use crate::ipam::read_total_hosts;
        // Text column present and valid: use it
        let val = read_total_hosts(Some("79228162514264337593543950336".to_string()), 100);
        assert_eq!(val, 1u128 << 96);
    }

    #[test]
    fn test_read_total_hosts_falls_back_to_i64() {
        use crate::ipam::read_total_hosts;
        // Text column absent: fall back to i64
        let val = read_total_hosts(None, 256);
        assert_eq!(val, 256);
    }

    #[tokio::test]
    async fn test_ipv6_cidr_block_total_hosts_roundtrip() {
        let store = test_store().await;

        // Create an IPv6 /32 cidr_block (2^96 addresses > i64::MAX)
        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "2001:db8::/32".to_string(),
                    name: Some("IPv6 test".to_string()),
                    description: None,
                },
            )
            .await
            .unwrap();

        let expected = 1u128 << 96;
        assert_eq!(sn.total_hosts, expected);
        assert_eq!(sn.ip_version, 6);

        // Verify roundtrip through get
        let fetched = store.get_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
        assert_eq!(fetched.total_hosts, expected);

        // Verify roundtrip through list
        let all = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
        assert_eq!(all[0].total_hosts, expected);
    }

    #[tokio::test]
    async fn test_ipv6_allocation_total_hosts_roundtrip() {
        let store = test_store().await;

        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "2001:db8::/32".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();

        let alloc = store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn.id.clone(),
                    cidr: "2001:db8::/48".to_string(),
                    status: None,
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        let expected = 1u128 << 80; // /48 has 2^80 addresses
        assert_eq!(alloc.total_hosts, expected);

        // Verify roundtrip through get
        let fetched = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
        assert_eq!(fetched.total_hosts, expected);
    }

    // -----------------------------------------------------------------------
    // Audit LIMIT cap (M1 fix)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_audit_limit_cap_returns_at_most_10000() {
        let store = test_store().await;

        // Insert 5 entries — enough to verify the cap doesn't break normal queries.
        for i in 0..5 {
            store
                .append_audit(&AuditEntry {
                    id: String::new(),
                    tenant_id: TEST_TENANT.to_string(),
                    entity_type: "cidr_block".to_string(),
                    entity_id: format!("sn-{i}"),
                    action: "create_cidr_block".to_string(),
                    details: None,
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        // A limit larger than 10_000 must be silently capped — query must succeed.
        let entries = store
            .query_audit(
                TEST_TENANT,
                &AuditFilter {
                    limit: Some(u32::MAX),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // All 5 entries are returned (well within the cap).
        assert_eq!(entries.len(), 5);
    }

    #[tokio::test]
    async fn test_audit_limit_respected() {
        let store = test_store().await;

        for i in 0..10 {
            store
                .append_audit(&AuditEntry {
                    id: String::new(),
                    tenant_id: TEST_TENANT.to_string(),
                    entity_type: "cidr_block".to_string(),
                    entity_id: format!("sn-{i}"),
                    action: "create_cidr_block".to_string(),
                    details: None,
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        let entries = store
            .query_audit(
                TEST_TENANT,
                &AuditFilter {
                    limit: Some(3),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(entries.len(), 3);
    }

    // ---- personal access tokens ----

    fn pat_input(
        tenant: &str,
        owner_sub: &str,
        name: &str,
        hash_byte: u8,
        expires_at: &str,
    ) -> CreatePersonalAccessToken {
        CreatePersonalAccessToken {
            tenant_id: tenant.to_string(),
            owner_sub: owner_sub.to_string(),
            owner_email: tenant.to_string(),
            name: name.to_string(),
            prefix: format!("ncdr_pat_{name:>3.3}"),
            token_hash: vec![hash_byte; 32],
            role: crate::auth::Role::Admin,
            expires_at: expires_at.to_string(),
        }
    }

    #[tokio::test]
    async fn pat_create_then_get_by_hash_round_trip() {
        let store = test_store().await;
        let input = pat_input(TEST_TENANT, "sub-1", "laptop", 0xAA, "2099-01-01T00:00:00Z");
        let created = store.pat_create(&input).await.unwrap();
        assert_eq!(created.tenant_id, TEST_TENANT);
        assert_eq!(created.token_hash, vec![0xAA; 32]);
        assert!(created.last_used_at.is_none());

        let found = store
            .pat_get_by_hash(&created.token_hash, "2026-05-02T00:00:00Z")
            .await
            .unwrap()
            .expect("active token should hit");
        assert_eq!(found.id, created.id);
    }

    #[tokio::test]
    async fn pat_get_by_hash_misses_revoked_expired_and_wrong_hash() {
        let store = test_store().await;

        // Active.
        let active = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "active",
                0x01,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();

        // Already-expired.
        let expired = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "expired",
                0x02,
                "2020-01-01T00:00:00Z",
            ))
            .await
            .unwrap();

        // Revoked.
        let revoked = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "revoked",
                0x03,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        store
            .pat_revoke(TEST_TENANT, "sub-1", &revoked.id, "2026-05-02T00:00:00Z")
            .await
            .unwrap();

        let now = "2026-05-02T00:00:00Z";

        // Active hits.
        assert!(
            store
                .pat_get_by_hash(&active.token_hash, now)
                .await
                .unwrap()
                .is_some()
        );

        // Expired misses.
        assert!(
            store
                .pat_get_by_hash(&expired.token_hash, now)
                .await
                .unwrap()
                .is_none()
        );

        // Revoked misses.
        assert!(
            store
                .pat_get_by_hash(&revoked.token_hash, now)
                .await
                .unwrap()
                .is_none()
        );

        // Wrong hash misses.
        assert!(
            store
                .pat_get_by_hash(&[0xFFu8; 32], now)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn pat_list_for_owner_isolates_across_tenants_and_owners() {
        let store = test_store().await;

        // tenant a / owner sub-a1
        let a1 = store
            .pat_create(&pat_input(
                "a@x",
                "sub-a1",
                "a1",
                0x10,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        // tenant a / owner sub-a2 (same tenant, different owner)
        let a2 = store
            .pat_create(&pat_input(
                "a@x",
                "sub-a2",
                "a2",
                0x11,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        // tenant b / owner sub-b1
        let b1 = store
            .pat_create(&pat_input(
                "b@x",
                "sub-b1",
                "b1",
                0x12,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();

        let listed = store.pat_list_for_owner("a@x", "sub-a1").await.unwrap();
        let ids: Vec<&str> = listed.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec![a1.id.as_str()]);

        let listed_other = store.pat_list_for_owner("a@x", "sub-a2").await.unwrap();
        assert_eq!(listed_other.len(), 1);
        assert_eq!(listed_other[0].id, a2.id);

        let listed_b = store.pat_list_for_owner("b@x", "sub-b1").await.unwrap();
        assert_eq!(listed_b.len(), 1);
        assert_eq!(listed_b[0].id, b1.id);

        // Wrong tenant for owner sub-a1 → empty.
        let cross = store.pat_list_for_owner("b@x", "sub-a1").await.unwrap();
        assert!(cross.is_empty());
    }

    #[tokio::test]
    async fn pat_touch_last_used_updates_timestamp() {
        let store = test_store().await;
        let t = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "tok",
                0x41,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        store
            .pat_touch_last_used(&t.id, "2026-05-02T12:00:00Z")
            .await
            .unwrap();
        let after = store
            .pat_list_for_owner(TEST_TENANT, "sub-1")
            .await
            .unwrap();
        assert_eq!(
            after[0].last_used_at.as_deref(),
            Some("2026-05-02T12:00:00Z")
        );
    }

    #[tokio::test]
    async fn pat_reap_expired_returns_count_and_removes_rows() {
        let store = test_store().await;
        // Two expired, one still-valid.
        let _e1 = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "e1",
                0x51,
                "2020-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        let _e2 = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "e2",
                0x52,
                "2020-02-01T00:00:00Z",
            ))
            .await
            .unwrap();
        let valid = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "v1",
                0x53,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();

        let n = store
            .pat_reap_expired("2025-01-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(n, 2);

        let remaining = store
            .pat_list_for_owner(TEST_TENANT, "sub-1")
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, valid.id);
    }

    #[tokio::test]
    async fn pat_count_active_excludes_revoked_and_expired() {
        let store = test_store().await;
        let now = "2026-06-01T00:00:00Z";

        // Active
        let active = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "a1",
                0x60,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();

        // Expired
        store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "e1",
                0x61,
                "2020-01-01T00:00:00Z",
            ))
            .await
            .unwrap();

        // Revoked
        let rev = store
            .pat_create(&pat_input(
                TEST_TENANT,
                "sub-1",
                "r1",
                0x62,
                "2099-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        store
            .pat_revoke(TEST_TENANT, "sub-1", &rev.id, now)
            .await
            .unwrap();

        let count = store
            .pat_count_active_for_owner(TEST_TENANT, "sub-1", now)
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "only the non-expired non-revoked token should count"
        );

        // Revoke the last active one → count drops to zero.
        store
            .pat_revoke(TEST_TENANT, "sub-1", &active.id, now)
            .await
            .unwrap();
        let count_after = store
            .pat_count_active_for_owner(TEST_TENANT, "sub-1", now)
            .await
            .unwrap();
        assert_eq!(count_after, 0);
    }
}
