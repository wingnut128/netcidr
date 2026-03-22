mod migrations;

use async_trait::async_trait;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::path::Path;

use crate::error::{NetcidrError, Result};
use crate::ipam::models::*;
use crate::ipam::store::IpamStore;
use crate::ipam::{parse_cidr_metadata, read_total_hosts, total_hosts_as_i64};

type ConnPool = Pool<SqliteConnectionManager>;

pub struct SqliteStore {
    pool: ConnPool,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Result<Self> {
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

        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Create an in-memory store (useful for testing).
    pub fn in_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1) // single connection for in-memory DB
            .build(manager)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(Self { pool })
    }

    fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool
            .get()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
    }

    fn now() -> String {
        Utc::now().to_rfc3339()
    }

    fn load_tags_for_allocation(
        conn: &rusqlite::Connection,
        allocation_id: &str,
    ) -> Result<Vec<Tag>> {
        let mut stmt = conn
            .prepare("SELECT key, value FROM allocation_tags WHERE allocation_id = ?1")
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let tags = stmt
            .query_map(params![allocation_id], |row| {
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
        let total_hosts_i64: i64 = row.get("total_hosts")?;
        let total_hosts_text: Option<String> = row.get("total_hosts_text")?;
        Ok(Allocation {
            id: row.get("id")?,
            supernet_id: row.get("supernet_id")?,
            cidr: row.get("cidr")?,
            network_address: row.get("network_address")?,
            broadcast_address: row.get("broadcast_address")?,
            prefix_length: row.get::<_, u8>("prefix_length")?,
            total_hosts: read_total_hosts(total_hosts_text, total_hosts_i64),
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

    // --- supernets ---

    async fn create_supernet(&self, input: &CreateSupernet) -> Result<Supernet> {
        let conn = self.conn()?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Self::now();

        // Parse CIDR to extract computed fields
        let (network, broadcast, prefix, total, ip_version) = parse_cidr_metadata(&input.cidr)?;

        conn.execute(
            "INSERT INTO supernets (id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, name, description, ip_version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![id, input.cidr, network, broadcast, prefix, total_hosts_as_i64(total), total.to_string(), input.name, input.description, ip_version, now, now],
        ).map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(Supernet {
            id,
            cidr: input.cidr.clone(),
            network_address: network,
            broadcast_address: broadcast,
            prefix_length: prefix,
            total_hosts: total,
            name: input.name.clone(),
            description: input.description.clone(),
            ip_version,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    async fn get_supernet(&self, id: &str) -> Result<Supernet> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, name, description, ip_version, created_at, updated_at FROM supernets WHERE id = ?1",
            params![id],
            |row| {
                let total_hosts_i64: i64 = row.get(5)?;
                let total_hosts_text: Option<String> = row.get(6)?;
                Ok(Supernet {
                    id: row.get(0)?,
                    cidr: row.get(1)?,
                    network_address: row.get(2)?,
                    broadcast_address: row.get(3)?,
                    prefix_length: row.get(4)?,
                    total_hosts: read_total_hosts(total_hosts_text, total_hosts_i64),
                    name: row.get(7)?,
                    description: row.get(8)?,
                    ip_version: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => NetcidrError::SupernetNotFound(id.to_string()),
            _ => NetcidrError::DatabaseError(e.to_string()),
        })
    }

    async fn list_supernets(&self) -> Result<Vec<Supernet>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, name, description, ip_version, created_at, updated_at FROM supernets ORDER BY created_at")
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let total_hosts_i64: i64 = row.get(5)?;
                let total_hosts_text: Option<String> = row.get(6)?;
                Ok(Supernet {
                    id: row.get(0)?,
                    cidr: row.get(1)?,
                    network_address: row.get(2)?,
                    broadcast_address: row.get(3)?,
                    prefix_length: row.get(4)?,
                    total_hosts: read_total_hosts(total_hosts_text, total_hosts_i64),
                    name: row.get(7)?,
                    description: row.get(8)?,
                    ip_version: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            })
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows)
    }

    async fn delete_supernet(&self, id: &str) -> Result<()> {
        let conn = self.conn()?;

        // Check for active allocations
        let active_count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM allocations WHERE supernet_id = ?1 AND status != 'released'",
                params![id],
                |row| row.get(0),
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if active_count > 0 {
            return Err(NetcidrError::SupernetHasActiveAllocations(id.to_string()));
        }

        // Delete released allocations' tags, then allocations, then supernet
        conn.execute(
            "DELETE FROM allocation_tags WHERE allocation_id IN (SELECT id FROM allocations WHERE supernet_id = ?1)",
            params![id],
        ).map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        conn.execute(
            "DELETE FROM allocations WHERE supernet_id = ?1",
            params![id],
        )
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let deleted = conn
            .execute("DELETE FROM supernets WHERE id = ?1", params![id])
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if deleted == 0 {
            return Err(NetcidrError::SupernetNotFound(id.to_string()));
        }
        Ok(())
    }

    // --- allocations ---

    async fn create_allocation(&self, input: &CreateAllocation) -> Result<Allocation> {
        let conn = self.conn()?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Self::now();
        let status = input
            .status
            .as_ref()
            .unwrap_or(&AllocationStatus::Active)
            .to_string();

        let (network, broadcast, prefix, total, _ip_version) = parse_cidr_metadata(&input.cidr)?;

        let expires_at = input
            .ttl_seconds
            .map(|ttl| (Utc::now() + chrono::Duration::seconds(ttl as i64)).to_rfc3339());

        conn.execute(
            "INSERT INTO allocations (id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                id, input.supernet_id, input.cidr, network, broadcast, prefix,
                total_hosts_as_i64(total), total.to_string(),
                input.resource_id, input.resource_type, input.name, input.description,
                input.environment, input.owner, status, input.parent_allocation_id, now, now,
                expires_at
            ],
        ).map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        // Insert tags
        if let Some(ref tags) = input.tags {
            for tag in tags {
                conn.execute(
                    "INSERT INTO allocation_tags (allocation_id, key, value) VALUES (?1, ?2, ?3)",
                    params![id, tag.key, tag.value],
                )
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            }
        }

        let tags = input.tags.clone().unwrap_or_default();
        Ok(Allocation {
            id,
            supernet_id: input.supernet_id.clone(),
            cidr: input.cidr.clone(),
            network_address: network,
            broadcast_address: broadcast,
            prefix_length: prefix,
            total_hosts: total,
            status: input.status.clone().unwrap_or(AllocationStatus::Active),
            resource_id: input.resource_id.clone(),
            resource_type: input.resource_type.clone(),
            name: input.name.clone(),
            description: input.description.clone(),
            environment: input.environment.clone(),
            owner: input.owner.clone(),
            parent_allocation_id: input.parent_allocation_id.clone(),
            tags,
            created_at: now.clone(),
            updated_at: now,
            released_at: None,
            expires_at,
        })
    }

    async fn get_allocation(&self, id: &str) -> Result<Allocation> {
        let conn = self.conn()?;
        let mut alloc = conn
            .query_row(
                "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE id = ?1",
                params![id],
                Self::row_to_allocation,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => NetcidrError::AllocationNotFound(id.to_string()),
                _ => NetcidrError::DatabaseError(e.to_string()),
            })?;
        alloc.tags = Self::load_tags_for_allocation(&conn, id)?;
        Ok(alloc)
    }

    async fn list_allocations(&self, filter: &AllocationFilter) -> Result<Vec<Allocation>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref sid) = filter.supernet_id {
            sql.push_str(&format!(" AND supernet_id = ?{}", idx));
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
            alloc.tags = Self::load_tags_for_allocation(&conn, &alloc.id)?;
        }
        Ok(allocations)
    }

    async fn update_allocation(&self, id: &str, input: &UpdateAllocation) -> Result<Allocation> {
        let conn = self.conn()?;
        let now = Self::now();

        // Verify allocation exists
        conn.query_row(
            "SELECT id FROM allocations WHERE id = ?1",
            params![id],
            |_| Ok(()),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                NetcidrError::AllocationNotFound(id.to_string())
            }
            _ => NetcidrError::DatabaseError(e.to_string()),
        })?;

        let mut sets = vec!["updated_at = ?1".to_string()];
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(now)];
        let mut idx = 2;

        macro_rules! set_field {
            ($field:ident, $col:expr) => {
                if let Some(ref val) = input.$field {
                    sets.push(format!("{} = ?{}", $col, idx));
                    param_values.push(Box::new(val.to_string()));
                    idx += 1;
                }
            };
        }
        set_field!(name, "name");
        set_field!(description, "description");
        set_field!(resource_id, "resource_id");
        set_field!(resource_type, "resource_type");
        set_field!(environment, "environment");
        set_field!(owner, "owner");
        set_field!(status, "status");

        // Clear released_at when reactivating (status changes to active/reserved)
        if let Some(ref status) = input.status {
            let s = status.to_string();
            if s == "active" || s == "reserved" {
                sets.push("released_at = NULL".to_string());
            }
        }

        let sql = format!(
            "UPDATE allocations SET {} WHERE id = ?{}",
            sets.join(", "),
            idx
        );
        param_values.push(Box::new(id.to_string()));
        #[allow(unused_assignments)]
        {
            idx += 1;
        }

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        conn.execute(&sql, params_refs.as_slice())
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        // Fetch updated allocation using same connection
        let mut alloc = conn
            .query_row(
                "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE id = ?1",
                params![id],
                Self::row_to_allocation,
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        alloc.tags = Self::load_tags_for_allocation(&conn, id)?;
        Ok(alloc)
    }

    async fn release_allocation(&self, id: &str) -> Result<Allocation> {
        let conn = self.conn()?;
        let now = Self::now();

        let updated = conn
            .execute(
                "UPDATE allocations SET status = 'released', released_at = ?1, updated_at = ?1 WHERE id = ?2 AND status != 'released'",
                params![now, id],
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if updated == 0 {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM allocations WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            if !exists {
                return Err(NetcidrError::AllocationNotFound(id.to_string()));
            }
        }

        // Fetch using same connection to avoid pool exhaustion
        let mut alloc = conn
            .query_row(
                "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE id = ?1",
                params![id],
                Self::row_to_allocation,
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        alloc.tags = Self::load_tags_for_allocation(&conn, id)?;
        Ok(alloc)
    }

    async fn find_allocations_in_supernet(
        &self,
        supernet_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>> {
        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn()?;
        let placeholders: Vec<String> =
            (0..statuses.len()).map(|i| format!("?{}", i + 2)).collect();
        let sql = format!(
            "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE supernet_id = ?1 AND status IN ({}) ORDER BY network_address",
            placeholders.join(", ")
        );

        let mut params_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        params_values.push(Box::new(supernet_id.to_string()));
        for s in statuses {
            params_values.push(Box::new(s.to_string()));
        }
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let rows = stmt
            .query_map(params_refs.as_slice(), Self::row_to_allocation)
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let mut allocations = rows;
        for alloc in &mut allocations {
            alloc.tags = Self::load_tags_for_allocation(&conn, &alloc.id)?;
        }
        Ok(allocations)
    }

    // --- tags ---

    async fn set_tags(&self, allocation_id: &str, tags: &[Tag]) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM allocation_tags WHERE allocation_id = ?1",
            params![allocation_id],
        )
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        for tag in tags {
            conn.execute(
                "INSERT INTO allocation_tags (allocation_id, key, value) VALUES (?1, ?2, ?3)",
                params![allocation_id, tag.key, tag.value],
            )
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }

    async fn get_tags(&self, allocation_id: &str) -> Result<Vec<Tag>> {
        let conn = self.conn()?;
        Self::load_tags_for_allocation(&conn, allocation_id)
    }

    // --- audit ---

    async fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![entry.timestamp, entry.action, entry.entity_type, entry.entity_id, entry.details],
        ).map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, timestamp, action, entity_type, entity_id, details FROM audit_log WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

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
            #[allow(unused_assignments)]
            {
                idx += 1;
            }
        }

        sql.push_str(" ORDER BY id DESC");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
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
                    timestamp: row.get(1)?,
                    action: row.get(2)?,
                    entity_type: row.get(3)?,
                    entity_id: row.get(4)?,
                    details: row.get(5)?,
                })
            })
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::parse_cidr_metadata;

    async fn test_store() -> SqliteStore {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    #[tokio::test]
    async fn test_supernet_crud() {
        let store = test_store().await;

        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: Some("RFC1918 Class A".to_string()),
                description: None,
            })
            .await
            .unwrap();

        assert_eq!(sn.cidr, "10.0.0.0/8");
        assert_eq!(sn.network_address, "10.0.0.0");
        assert_eq!(sn.broadcast_address, "10.255.255.255");
        assert_eq!(sn.prefix_length, 8);
        assert_eq!(sn.ip_version, 4);

        let fetched = store.get_supernet(&sn.id).await.unwrap();
        assert_eq!(fetched.cidr, "10.0.0.0/8");

        let all = store.list_supernets().await.unwrap();
        assert_eq!(all.len(), 1);

        store.delete_supernet(&sn.id).await.unwrap();
        let all = store.list_supernets().await.unwrap();
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_allocation_crud() {
        let store = test_store().await;

        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        let alloc = store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        assert_eq!(alloc.status, AllocationStatus::Active);
        assert_eq!(alloc.tags.len(), 1);

        let fetched = store.get_allocation(&alloc.id).await.unwrap();
        assert_eq!(fetched.resource_id, Some("vpc-123".to_string()));
        assert_eq!(fetched.tags.len(), 1);

        // Update
        let updated = store
            .update_allocation(
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
        let released = store.release_allocation(&alloc.id).await.unwrap();
        assert_eq!(released.status, AllocationStatus::Released);
        assert!(released.released_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_supernet_with_active_allocations_fails() {
        let store = test_store().await;

        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        let err = store.delete_supernet(&sn.id).await.unwrap_err();
        assert!(matches!(err, NetcidrError::SupernetHasActiveAllocations(_)));
    }

    #[tokio::test]
    async fn test_find_allocations_by_status() {
        let store = test_store().await;

        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        let a1 = store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        store.release_allocation(&a1.id).await.unwrap();

        let active = store
            .find_allocations_in_supernet(
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
                entity_type: "supernet".to_string(),
                entity_id: "sn-1".to_string(),
                action: "create_supernet".to_string(),
                details: Some(r#"{"cidr":"10.0.0.0/8"}"#.to_string()),
                timestamp: "2026-03-04T00:00:00Z".to_string(),
            })
            .await
            .unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                entity_id: Some("sn-1".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "create_supernet");
    }

    #[tokio::test]
    async fn test_tags() {
        let store = test_store().await;

        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        let alloc = store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        store
            .set_tags(
                &alloc.id,
                &[
                    Tag {
                        key: "env".to_string(),
                        value: "prod".to_string(),
                    },
                    Tag {
                        key: "team".to_string(),
                        value: "platform".to_string(),
                    },
                ],
            )
            .await
            .unwrap();

        let tags = store.get_tags(&alloc.id).await.unwrap();
        assert_eq!(tags.len(), 2);

        // Replace tags
        store
            .set_tags(
                &alloc.id,
                &[Tag {
                    key: "env".to_string(),
                    value: "staging".to_string(),
                }],
            )
            .await
            .unwrap();
        let tags = store.get_tags(&alloc.id).await.unwrap();
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

    #[test]
    fn test_total_hosts_as_i64_clamps() {
        use crate::ipam::total_hosts_as_i64;
        assert_eq!(total_hosts_as_i64(256), 256);
        assert_eq!(total_hosts_as_i64(1u128 << 96), i64::MAX);
    }

    #[tokio::test]
    async fn test_ipv6_supernet_total_hosts_roundtrip() {
        let store = test_store().await;

        // Create an IPv6 /32 supernet (2^96 addresses > i64::MAX)
        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "2001:db8::/32".to_string(),
                name: Some("IPv6 test".to_string()),
                description: None,
            })
            .await
            .unwrap();

        let expected = 1u128 << 96;
        assert_eq!(sn.total_hosts, expected);
        assert_eq!(sn.ip_version, 6);

        // Verify roundtrip through get
        let fetched = store.get_supernet(&sn.id).await.unwrap();
        assert_eq!(fetched.total_hosts, expected);

        // Verify roundtrip through list
        let all = store.list_supernets().await.unwrap();
        assert_eq!(all[0].total_hosts, expected);
    }

    #[tokio::test]
    async fn test_ipv6_allocation_total_hosts_roundtrip() {
        let store = test_store().await;

        let sn = store
            .create_supernet(&CreateSupernet {
                cidr: "2001:db8::/32".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        let alloc = store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        let expected = 1u128 << 80; // /48 has 2^80 addresses
        assert_eq!(alloc.total_hosts, expected);

        // Verify roundtrip through get
        let fetched = store.get_allocation(&alloc.id).await.unwrap();
        assert_eq!(fetched.total_hosts, expected);
    }
}
