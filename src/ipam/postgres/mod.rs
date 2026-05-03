mod migrations;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::error::{NetcidrError, Result};
use crate::ipam::config::PostgresConfig;
use crate::ipam::models::*;
use crate::ipam::store::IpamStore;
use crate::ipam::{parse_cidr_metadata, read_total_hosts};

pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn new(url: &str, config: &PostgresConfig) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .connect(url)
            .await
            .map_err(|e| {
                NetcidrError::DatabaseError(format!("PostgreSQL connection failed: {e}"))
            })?;
        Ok(Self { pool })
    }

    /// Test-only access to the underlying connection pool, used by migration
    /// tests that need to issue raw SQL outside the normal `IpamStore` API.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn now() -> String {
        Utc::now().to_rfc3339()
    }

    async fn load_tags_for_allocation(&self, allocation_id: &str) -> Result<Vec<Tag>> {
        let rows = sqlx::query("SELECT key, value FROM allocation_tags WHERE allocation_id = $1")
            .bind(allocation_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows
            .iter()
            .map(|row| Tag {
                key: row.get("key"),
                value: row.get("value"),
            })
            .collect())
    }

    async fn assert_allocation_in_tenant(
        &self,
        tenant_id: &str,
        allocation_id: &str,
    ) -> Result<()> {
        let row =
            sqlx::query("SELECT COUNT(*) as cnt FROM allocations WHERE id = $1 AND tenant_id = $2")
                .bind(allocation_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let cnt: i64 = row.get("cnt");
        if cnt == 0 {
            return Err(NetcidrError::AllocationNotFound(allocation_id.to_string()));
        }
        Ok(())
    }

    fn row_to_allocation(row: &sqlx::postgres::PgRow) -> Allocation {
        let status_str: String = row.get("status");
        let status = status_str
            .parse::<AllocationStatus>()
            .unwrap_or(AllocationStatus::Active);
        let total_hosts_text: String = row.get("total_hosts");
        Allocation {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            supernet_id: row.get("supernet_id"),
            cidr: row.get("cidr"),
            network_address: row.get("network_address"),
            broadcast_address: row.get("broadcast_address"),
            prefix_length: {
                let v: i16 = row.get("prefix_length");
                v as u8
            },
            total_hosts: read_total_hosts(Some(total_hosts_text), 0),
            status,
            resource_id: row.get("resource_id"),
            resource_type: row.get("resource_type"),
            name: row.get("name"),
            description: row.get("description"),
            environment: row.get("environment"),
            owner: row.get("owner"),
            parent_allocation_id: row.get("parent_allocation_id"),
            tags: Vec::new(), // loaded separately
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            released_at: row.get("released_at"),
            expires_at: row.get("expires_at"),
        }
    }
}

#[async_trait]
impl IpamStore for PostgresStore {
    async fn initialize(&self) -> Result<()> {
        // No PRAGMAs needed for PostgreSQL — connection pool handles setup
        Ok(())
    }

    async fn migrate(&self) -> Result<()> {
        // Ensure schema_version table exists
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let row = sqlx::query("SELECT COALESCE(MAX(version), 0) as v FROM schema_version")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let current: i32 = row.get("v");
        let current = current as u32;

        for &(version, sql) in migrations::MIGRATIONS {
            if version > current {
                // Migration 006 contains a plpgsql CREATE FUNCTION whose body
                // includes semicolons. Naively splitting on ';' would break
                // it. Detect the function block and execute it as a single
                // statement; everything else stays one-statement-per-split.
                Self::execute_migration_sql(&self.pool, sql).await?;
                sqlx::query("INSERT INTO schema_version (version, applied_at) VALUES ($1, $2)")
                    .bind(version as i32)
                    .bind(Self::now())
                    .execute(&self.pool)
                    .await
                    .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            }
        }
        Ok(())
    }

    // --- supernets ---

    async fn create_supernet(&self, tenant_id: &str, input: &CreateSupernet) -> Result<Supernet> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Self::now();
        let (network, broadcast, prefix, total, ip_version) = parse_cidr_metadata(&input.cidr)?;

        sqlx::query(
            "INSERT INTO supernets (id, tenant_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, name, description, ip_version, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(&input.cidr)
        .bind(&network)
        .bind(&broadcast)
        .bind(prefix as i16)
        .bind(total.to_string())
        .bind(&input.name)
        .bind(&input.description)
        .bind(ip_version as i16)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(Supernet {
            id,
            tenant_id: tenant_id.to_string(),
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

    async fn get_supernet(&self, tenant_id: &str, id: &str) -> Result<Supernet> {
        let row = sqlx::query(
            "SELECT id, tenant_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, name, description, ip_version, created_at, updated_at FROM supernets WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| NetcidrError::SupernetNotFound(id.to_string()))?;

        let total_hosts_text: String = row.get("total_hosts");
        let prefix_length: i16 = row.get("prefix_length");
        let ip_version: i16 = row.get("ip_version");
        Ok(Supernet {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            cidr: row.get("cidr"),
            network_address: row.get("network_address"),
            broadcast_address: row.get("broadcast_address"),
            prefix_length: prefix_length as u8,
            total_hosts: read_total_hosts(Some(total_hosts_text), 0),
            name: row.get("name"),
            description: row.get("description"),
            ip_version: ip_version as u8,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn list_supernets(&self, tenant_id: &str) -> Result<Vec<Supernet>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, name, description, ip_version, created_at, updated_at FROM supernets WHERE tenant_id = $1 ORDER BY created_at",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row| {
                let total_hosts_text: String = row.get("total_hosts");
                let prefix_length: i16 = row.get("prefix_length");
                let ip_version: i16 = row.get("ip_version");
                Supernet {
                    id: row.get("id"),
                    tenant_id: row.get("tenant_id"),
                    cidr: row.get("cidr"),
                    network_address: row.get("network_address"),
                    broadcast_address: row.get("broadcast_address"),
                    prefix_length: prefix_length as u8,
                    total_hosts: read_total_hosts(Some(total_hosts_text), 0),
                    name: row.get("name"),
                    description: row.get("description"),
                    ip_version: ip_version as u8,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }
            })
            .collect())
    }

    async fn delete_supernet(&self, tenant_id: &str, id: &str) -> Result<()> {
        // Verify supernet exists in this tenant; cross-tenant ⇒ NotFound.
        let exists_row =
            sqlx::query("SELECT COUNT(*) as cnt FROM supernets WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let exists_cnt: i64 = exists_row.get("cnt");
        if exists_cnt == 0 {
            return Err(NetcidrError::SupernetNotFound(id.to_string()));
        }

        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM allocations WHERE supernet_id = $1 AND tenant_id = $2 AND status != 'released'",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let active_count: i64 = row.get("cnt");

        if active_count > 0 {
            return Err(NetcidrError::SupernetHasActiveAllocations(id.to_string()));
        }

        // Delete released allocations' tags, then allocations, then supernet
        sqlx::query(
            "DELETE FROM allocation_tags WHERE allocation_id IN (SELECT id FROM allocations WHERE supernet_id = $1 AND tenant_id = $2)",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        sqlx::query("DELETE FROM allocations WHERE supernet_id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let result = sqlx::query("DELETE FROM supernets WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(NetcidrError::SupernetNotFound(id.to_string()));
        }
        Ok(())
    }

    // --- allocations ---

    async fn create_allocation(
        &self,
        tenant_id: &str,
        input: &CreateAllocation,
    ) -> Result<Allocation> {
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

        // Application-level cross-tenant invariant: confirm the parent
        // supernet belongs to this tenant. NotFound (not Forbidden) hides
        // existence. The DB trigger is belt-and-suspenders.
        let supernet_row =
            sqlx::query("SELECT COUNT(*) as cnt FROM supernets WHERE id = $1 AND tenant_id = $2")
                .bind(&input.supernet_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let supernet_cnt: i64 = supernet_row.get("cnt");
        if supernet_cnt == 0 {
            return Err(NetcidrError::SupernetNotFound(input.supernet_id.clone()));
        }

        sqlx::query(
            "INSERT INTO allocations (id, tenant_id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(&input.supernet_id)
        .bind(&input.cidr)
        .bind(&network)
        .bind(&broadcast)
        .bind(prefix as i16)
        .bind(total.to_string())
        .bind(&input.resource_id)
        .bind(&input.resource_type)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.environment)
        .bind(&input.owner)
        .bind(&status)
        .bind(&input.parent_allocation_id)
        .bind(&now)
        .bind(&now)
        .bind(&expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        // Insert tags
        if let Some(ref tags) = input.tags {
            for tag in tags {
                sqlx::query(
                    "INSERT INTO allocation_tags (allocation_id, key, value) VALUES ($1, $2, $3)",
                )
                .bind(&id)
                .bind(&tag.key)
                .bind(&tag.value)
                .execute(&self.pool)
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            }
        }

        let tags = input.tags.clone().unwrap_or_default();
        Ok(Allocation {
            id,
            tenant_id: tenant_id.to_string(),
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

    async fn get_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation> {
        let row = sqlx::query(
            "SELECT id, tenant_id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| NetcidrError::AllocationNotFound(id.to_string()))?;

        let mut alloc = Self::row_to_allocation(&row);
        alloc.tags = self.load_tags_for_allocation(id).await?;
        Ok(alloc)
    }

    async fn list_allocations(
        &self,
        tenant_id: &str,
        filter: &AllocationFilter,
    ) -> Result<Vec<Allocation>> {
        let mut sql = String::from(
            "SELECT id, tenant_id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE tenant_id = $1",
        );
        let mut param_values: Vec<String> = Vec::new();
        param_values.push(tenant_id.to_string());
        let mut idx = 2;

        if let Some(ref sid) = filter.supernet_id {
            sql.push_str(&format!(" AND supernet_id = ${idx}"));
            param_values.push(sid.clone());
            idx += 1;
        }
        if let Some(ref status) = filter.status {
            sql.push_str(&format!(" AND status = ${idx}"));
            param_values.push(status.to_string());
            idx += 1;
        }
        if let Some(ref rid) = filter.resource_id {
            sql.push_str(&format!(" AND resource_id = ${idx}"));
            param_values.push(rid.clone());
            idx += 1;
        }
        if let Some(ref rt) = filter.resource_type {
            sql.push_str(&format!(" AND resource_type = ${idx}"));
            param_values.push(rt.clone());
            idx += 1;
        }
        if let Some(ref env) = filter.environment {
            sql.push_str(&format!(" AND environment = ${idx}"));
            param_values.push(env.clone());
            idx += 1;
        }
        if let Some(ref owner) = filter.owner {
            sql.push_str(&format!(" AND owner = ${idx}"));
            param_values.push(owner.clone());
            #[allow(unused_assignments)]
            {
                idx += 1;
            }
        }

        sql.push_str(" ORDER BY created_at");

        let mut query = sqlx::query(&sql);
        for val in &param_values {
            query = query.bind(val);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let mut allocations: Vec<Allocation> = rows.iter().map(Self::row_to_allocation).collect();
        for alloc in &mut allocations {
            alloc.tags = self.load_tags_for_allocation(&alloc.id).await?;
        }
        Ok(allocations)
    }

    async fn update_allocation(
        &self,
        tenant_id: &str,
        id: &str,
        input: &UpdateAllocation,
    ) -> Result<Allocation> {
        let now = Self::now();

        // Verify allocation exists in this tenant
        self.assert_allocation_in_tenant(tenant_id, id).await?;

        let mut sets = vec!["updated_at = $1".to_string()];
        let mut param_values: Vec<String> = vec![now];
        let mut idx = 2;

        macro_rules! set_field {
            ($field:ident, $col:expr) => {
                if let Some(ref val) = input.$field {
                    sets.push(format!("{} = ${}", $col, idx));
                    param_values.push(val.to_string());
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

        let id_idx = idx;
        let tenant_idx = idx + 1;
        let sql = format!(
            "UPDATE allocations SET {} WHERE id = ${} AND tenant_id = ${}",
            sets.join(", "),
            id_idx,
            tenant_idx,
        );
        param_values.push(id.to_string());
        param_values.push(tenant_id.to_string());

        let mut query = sqlx::query(&sql);
        for val in &param_values {
            query = query.bind(val);
        }
        query
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        self.get_allocation(tenant_id, id).await
    }

    async fn release_allocation(&self, tenant_id: &str, id: &str) -> Result<Allocation> {
        let now = Self::now();

        let result = sqlx::query(
            "UPDATE allocations SET status = 'released', released_at = $1, updated_at = $1 WHERE id = $2 AND tenant_id = $3 AND status != 'released'",
        )
        .bind(&now)
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            let exists = sqlx::query(
                "SELECT COUNT(*) as cnt FROM allocations WHERE id = $1 AND tenant_id = $2",
            )
            .bind(id)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            let cnt: i64 = exists.get("cnt");
            if cnt == 0 {
                return Err(NetcidrError::AllocationNotFound(id.to_string()));
            }
        }

        self.get_allocation(tenant_id, id).await
    }

    async fn find_allocations_in_supernet(
        &self,
        tenant_id: &str,
        supernet_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>> {
        if statuses.is_empty() {
            return Ok(Vec::new());
        }

        let mut placeholders = Vec::new();
        // $1 = supernet_id, $2 = tenant_id, statuses start at $3.
        for i in 0..statuses.len() {
            placeholders.push(format!("${}", i + 3));
        }

        let sql = format!(
            "SELECT id, tenant_id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE supernet_id = $1 AND tenant_id = $2 AND status IN ({}) ORDER BY network_address",
            placeholders.join(", ")
        );

        let mut query = sqlx::query(&sql).bind(supernet_id).bind(tenant_id);
        for s in statuses {
            query = query.bind(s.to_string());
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let mut allocations: Vec<Allocation> = rows.iter().map(Self::row_to_allocation).collect();
        for alloc in &mut allocations {
            alloc.tags = self.load_tags_for_allocation(&alloc.id).await?;
        }
        Ok(allocations)
    }

    // --- tags ---

    async fn set_tags(&self, tenant_id: &str, allocation_id: &str, tags: &[Tag]) -> Result<()> {
        self.assert_allocation_in_tenant(tenant_id, allocation_id)
            .await?;

        sqlx::query("DELETE FROM allocation_tags WHERE allocation_id = $1")
            .bind(allocation_id)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        for tag in tags {
            sqlx::query(
                "INSERT INTO allocation_tags (allocation_id, key, value) VALUES ($1, $2, $3)",
            )
            .bind(allocation_id)
            .bind(&tag.key)
            .bind(&tag.value)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }

    async fn get_tags(&self, tenant_id: &str, allocation_id: &str) -> Result<Vec<Tag>> {
        self.assert_allocation_in_tenant(tenant_id, allocation_id)
            .await?;
        self.load_tags_for_allocation(allocation_id).await
    }

    // --- audit ---

    async fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (tenant_id, timestamp, action, entity_type, entity_id, details, caller_sub, caller_email, source_ip, request_id, auth_method, pat_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&entry.tenant_id)
        .bind(&entry.timestamp)
        .bind(&entry.action)
        .bind(&entry.entity_type)
        .bind(&entry.entity_id)
        .bind(&entry.details)
        .bind(&entry.caller_sub)
        .bind(&entry.caller_email)
        .bind(&entry.source_ip)
        .bind(&entry.request_id)
        .bind(if entry.auth_method.is_empty() { "oidc".to_string() } else { entry.auth_method.clone() })
        .bind(&entry.pat_id)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn query_audit(&self, tenant_id: &str, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            "SELECT id, tenant_id, timestamp, action, entity_type, entity_id, details, caller_sub, caller_email, source_ip, request_id, auth_method, pat_id FROM audit_log WHERE tenant_id = $1",
        );
        let mut param_values: Vec<String> = Vec::new();
        param_values.push(tenant_id.to_string());
        let mut idx = 2;

        if let Some(ref et) = filter.entity_type {
            sql.push_str(&format!(" AND entity_type = ${idx}"));
            param_values.push(et.clone());
            idx += 1;
        }
        if let Some(ref eid) = filter.entity_id {
            sql.push_str(&format!(" AND entity_id = ${idx}"));
            param_values.push(eid.clone());
            idx += 1;
        }
        if let Some(ref action) = filter.action {
            sql.push_str(&format!(" AND action = ${idx}"));
            param_values.push(action.clone());
            idx += 1;
        }

        sql.push_str(" ORDER BY id DESC");

        // Cap to prevent full-table-scan DoS. Applied after building the string
        // params so the integer can be bound separately at the end.
        let capped_limit: Option<i64> = filter.limit.map(|l| l.min(10_000) as i64);
        if capped_limit.is_some() {
            sql.push_str(&format!(" LIMIT ${idx}"));
        }

        let mut query = sqlx::query(&sql);
        for val in &param_values {
            query = query.bind(val);
        }
        if let Some(lim) = capped_limit {
            query = query.bind(lim);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row| {
                let id_i64: i64 = row.get("id");
                AuditEntry {
                    id: id_i64.to_string(),
                    tenant_id: row.get("tenant_id"),
                    timestamp: row.get("timestamp"),
                    action: row.get("action"),
                    entity_type: row.get("entity_type"),
                    entity_id: row.get("entity_id"),
                    details: row.get("details"),
                    caller_sub: row.try_get("caller_sub").ok(),
                    caller_email: row.try_get("caller_email").ok(),
                    source_ip: row.try_get("source_ip").ok(),
                    request_id: row.try_get("request_id").ok(),
                    auth_method: row
                        .try_get::<String, _>("auth_method")
                        .unwrap_or_else(|_| "oidc".to_string()),
                    pat_id: row.try_get("pat_id").ok(),
                }
            })
            .collect())
    }

    async fn idempotency_get(
        &self,
        tenant_id: &str,
        key: &str,
        scope: &str,
    ) -> Result<Option<IdempotencyRecord>> {
        let row = sqlx::query(
            "SELECT tenant_id, key, scope, request_hash, status_code, response_body, created_at, expires_at \
             FROM idempotency_keys WHERE tenant_id = $1 AND key = $2 AND scope = $3",
        )
        .bind(tenant_id)
        .bind(key)
        .bind(scope)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(row.map(|row| {
            let status_code: i32 = row.get("status_code");
            IdempotencyRecord {
                tenant_id: row.get("tenant_id"),
                key: row.get("key"),
                scope: row.get("scope"),
                request_hash: row.get("request_hash"),
                status_code: status_code as u16,
                response_body: row.get("response_body"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
            }
        }))
    }

    async fn idempotency_put(&self, record: &IdempotencyRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO idempotency_keys \
                (tenant_id, key, scope, request_hash, status_code, response_body, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (tenant_id, key, scope) DO NOTHING",
        )
        .bind(&record.tenant_id)
        .bind(&record.key)
        .bind(&record.scope)
        .bind(&record.request_hash)
        .bind(record.status_code as i32)
        .bind(&record.response_body)
        .bind(&record.created_at)
        .bind(&record.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn idempotency_reap_expired(&self, now_rfc3339: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM idempotency_keys WHERE expires_at <= $1")
            .bind(now_rfc3339)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(result.rows_affected())
    }

    // --- personal access tokens ---

    async fn pat_create(&self, input: &CreatePersonalAccessToken) -> Result<PersonalAccessToken> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Self::now();

        sqlx::query(
            "INSERT INTO personal_access_tokens
                (id, tenant_id, owner_sub, owner_email, name, prefix, token_hash,
                 created_at, expires_at, last_used_at, revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NULL)",
        )
        .bind(&id)
        .bind(&input.tenant_id)
        .bind(&input.owner_sub)
        .bind(&input.owner_email)
        .bind(&input.name)
        .bind(&input.prefix)
        .bind(&input.token_hash)
        .bind(&now)
        .bind(&input.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(PersonalAccessToken {
            id,
            tenant_id: input.tenant_id.clone(),
            owner_sub: input.owner_sub.clone(),
            owner_email: input.owner_email.clone(),
            name: input.name.clone(),
            prefix: input.prefix.clone(),
            token_hash: input.token_hash.clone(),
            created_at: now,
            expires_at: input.expires_at.clone(),
            last_used_at: None,
            revoked_at: None,
        })
    }

    async fn pat_get_by_hash(
        &self,
        token_hash: &[u8],
        now_rfc3339: &str,
    ) -> Result<Option<PersonalAccessToken>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, owner_sub, owner_email, name, prefix, token_hash, \
                    created_at, expires_at, last_used_at, revoked_at \
             FROM personal_access_tokens \
             WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
        )
        .bind(token_hash)
        .bind(now_rfc3339)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(row.map(pg_row_to_pat))
    }

    async fn pat_list_for_owner(
        &self,
        tenant_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<PersonalAccessToken>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, owner_sub, owner_email, name, prefix, token_hash, \
                    created_at, expires_at, last_used_at, revoked_at \
             FROM personal_access_tokens \
             WHERE tenant_id = $1 AND owner_sub = $2 \
             ORDER BY created_at",
        )
        .bind(tenant_id)
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(rows.into_iter().map(pg_row_to_pat).collect())
    }

    async fn pat_revoke(
        &self,
        tenant_id: &str,
        owner_sub: &str,
        id: &str,
        now_rfc3339: &str,
    ) -> Result<PersonalAccessToken> {
        let existing = sqlx::query(
            "SELECT id, tenant_id, owner_sub, owner_email, name, prefix, token_hash, \
                    created_at, expires_at, last_used_at, revoked_at \
             FROM personal_access_tokens \
             WHERE id = $1 AND tenant_id = $2 AND owner_sub = $3",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let mut row = match existing.map(pg_row_to_pat) {
            Some(r) => r,
            None => return Err(NetcidrError::PatNotFound(id.to_string())),
        };

        if row.revoked_at.is_some() {
            return Ok(row);
        }

        sqlx::query(
            "UPDATE personal_access_tokens SET revoked_at = $1 \
             WHERE id = $2 AND tenant_id = $3 AND owner_sub = $4",
        )
        .bind(now_rfc3339)
        .bind(id)
        .bind(tenant_id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        row.revoked_at = Some(now_rfc3339.to_string());
        Ok(row)
    }

    async fn pat_touch_last_used(&self, id: &str, now_rfc3339: &str) -> Result<()> {
        sqlx::query("UPDATE personal_access_tokens SET last_used_at = $1 WHERE id = $2")
            .bind(now_rfc3339)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn pat_reap_expired(&self, before_rfc3339: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM personal_access_tokens WHERE expires_at < $1")
            .bind(before_rfc3339)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(result.rows_affected())
    }
}

fn pg_row_to_pat(row: sqlx::postgres::PgRow) -> PersonalAccessToken {
    PersonalAccessToken {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        owner_sub: row.get("owner_sub"),
        owner_email: row.get("owner_email"),
        name: row.get("name"),
        prefix: row.get("prefix"),
        token_hash: row.get("token_hash"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        last_used_at: row.get("last_used_at"),
        revoked_at: row.get("revoked_at"),
    }
}

impl PostgresStore {
    /// Execute a migration SQL blob. Postgres prepared statements only support
    /// one statement, so we split on `;` — but plpgsql function bodies
    /// (`$$ ... $$`) themselves contain `;`. Track whether we're inside a
    /// dollar-quoted block and don't split there.
    async fn execute_migration_sql(pool: &PgPool, sql: &str) -> Result<()> {
        let mut buf = String::new();
        let mut in_dollar = false;
        let bytes = sql.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // Detect $$ delimiter.
            if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'$' {
                buf.push('$');
                buf.push('$');
                in_dollar = !in_dollar;
                i += 2;
                continue;
            }
            let c = bytes[i] as char;
            if c == ';' && !in_dollar {
                let stmt = buf.trim();
                if !stmt.is_empty() {
                    sqlx::query(stmt)
                        .execute(pool)
                        .await
                        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
                }
                buf.clear();
            } else {
                buf.push(c);
            }
            i += 1;
        }
        let tail = buf.trim();
        if !tail.is_empty() {
            sqlx::query(tail)
                .execute(pool)
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }
}
