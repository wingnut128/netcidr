mod migrations;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::error::{NetcidrError, Result};
use crate::ipam::config::PostgresConfig;
use crate::ipam::models::*;
use crate::ipam::store::IpamStore;
use crate::ipam::{parse_cidr_metadata, read_total_hosts, total_hosts_as_i64};

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

    fn row_to_allocation(row: &sqlx::postgres::PgRow) -> Allocation {
        let status_str: String = row.get("status");
        let status = status_str
            .parse::<AllocationStatus>()
            .unwrap_or(AllocationStatus::Active);
        let total_hosts_i64: i64 = row.get("total_hosts");
        let total_hosts_text: Option<String> = row.get("total_hosts_text");
        Allocation {
            id: row.get("id"),
            supernet_id: row.get("supernet_id"),
            cidr: row.get("cidr"),
            network_address: row.get("network_address"),
            broadcast_address: row.get("broadcast_address"),
            prefix_length: {
                let v: i16 = row.get("prefix_length");
                v as u8
            },
            total_hosts: read_total_hosts(total_hosts_text, total_hosts_i64),
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
                // PostgreSQL prepared statements don't support multiple commands,
                // so split on semicolons and execute each statement individually.
                for stmt in sql.split(';') {
                    let stmt = stmt.trim();
                    if stmt.is_empty() {
                        continue;
                    }
                    sqlx::query(stmt)
                        .execute(&self.pool)
                        .await
                        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
                }
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

    async fn create_supernet(&self, input: &CreateSupernet) -> Result<Supernet> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Self::now();
        let (network, broadcast, prefix, total, ip_version) = parse_cidr_metadata(&input.cidr)?;

        sqlx::query(
            "INSERT INTO supernets (id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, name, description, ip_version, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&id)
        .bind(&input.cidr)
        .bind(&network)
        .bind(&broadcast)
        .bind(prefix as i16)
        .bind(total_hosts_as_i64(total))
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
        let row = sqlx::query(
            "SELECT id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, name, description, ip_version, created_at, updated_at FROM supernets WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| NetcidrError::SupernetNotFound(id.to_string()))?;

        let total_hosts_i64: i64 = row.get("total_hosts");
        let total_hosts_text: Option<String> = row.get("total_hosts_text");
        let prefix_length: i16 = row.get("prefix_length");
        let ip_version: i16 = row.get("ip_version");
        Ok(Supernet {
            id: row.get("id"),
            cidr: row.get("cidr"),
            network_address: row.get("network_address"),
            broadcast_address: row.get("broadcast_address"),
            prefix_length: prefix_length as u8,
            total_hosts: read_total_hosts(total_hosts_text, total_hosts_i64),
            name: row.get("name"),
            description: row.get("description"),
            ip_version: ip_version as u8,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn list_supernets(&self) -> Result<Vec<Supernet>> {
        let rows = sqlx::query(
            "SELECT id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, name, description, ip_version, created_at, updated_at FROM supernets ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row| {
                let total_hosts_i64: i64 = row.get("total_hosts");
                let total_hosts_text: Option<String> = row.get("total_hosts_text");
                let prefix_length: i16 = row.get("prefix_length");
                let ip_version: i16 = row.get("ip_version");
                Supernet {
                    id: row.get("id"),
                    cidr: row.get("cidr"),
                    network_address: row.get("network_address"),
                    broadcast_address: row.get("broadcast_address"),
                    prefix_length: prefix_length as u8,
                    total_hosts: read_total_hosts(total_hosts_text, total_hosts_i64),
                    name: row.get("name"),
                    description: row.get("description"),
                    ip_version: ip_version as u8,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }
            })
            .collect())
    }

    async fn delete_supernet(&self, id: &str) -> Result<()> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM allocations WHERE supernet_id = $1 AND status != 'released'",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        let active_count: i64 = row.get("cnt");

        if active_count > 0 {
            return Err(NetcidrError::SupernetHasActiveAllocations(id.to_string()));
        }

        // Delete released allocations' tags, then allocations, then supernet
        sqlx::query(
            "DELETE FROM allocation_tags WHERE allocation_id IN (SELECT id FROM allocations WHERE supernet_id = $1)",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        sqlx::query("DELETE FROM allocations WHERE supernet_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        let result = sqlx::query("DELETE FROM supernets WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(NetcidrError::SupernetNotFound(id.to_string()));
        }
        Ok(())
    }

    // --- allocations ---

    async fn create_allocation(&self, input: &CreateAllocation) -> Result<Allocation> {
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

        sqlx::query(
            "INSERT INTO allocations (id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
        )
        .bind(&id)
        .bind(&input.supernet_id)
        .bind(&input.cidr)
        .bind(&network)
        .bind(&broadcast)
        .bind(prefix as i16)
        .bind(total_hosts_as_i64(total))
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
        let row = sqlx::query(
            "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| NetcidrError::AllocationNotFound(id.to_string()))?;

        let mut alloc = Self::row_to_allocation(&row);
        alloc.tags = self.load_tags_for_allocation(id).await?;
        Ok(alloc)
    }

    async fn list_allocations(&self, filter: &AllocationFilter) -> Result<Vec<Allocation>> {
        let mut sql = String::from(
            "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE true",
        );
        let mut param_values: Vec<String> = Vec::new();
        let mut idx = 1;

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

    async fn update_allocation(&self, id: &str, input: &UpdateAllocation) -> Result<Allocation> {
        let now = Self::now();

        // Verify allocation exists
        let exists = sqlx::query("SELECT id FROM allocations WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if exists.is_none() {
            return Err(NetcidrError::AllocationNotFound(id.to_string()));
        }

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

        let sql = format!(
            "UPDATE allocations SET {} WHERE id = ${}",
            sets.join(", "),
            idx
        );
        param_values.push(id.to_string());
        #[allow(unused_assignments)]
        {
            idx += 1;
        }

        let mut query = sqlx::query(&sql);
        for val in &param_values {
            query = query.bind(val);
        }
        query
            .execute(&self.pool)
            .await
            .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        self.get_allocation(id).await
    }

    async fn release_allocation(&self, id: &str) -> Result<Allocation> {
        let now = Self::now();

        let result = sqlx::query(
            "UPDATE allocations SET status = 'released', released_at = $1, updated_at = $1 WHERE id = $2 AND status != 'released'",
        )
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            let exists = sqlx::query("SELECT COUNT(*) as cnt FROM allocations WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            let cnt: i64 = exists.get("cnt");
            if cnt == 0 {
                return Err(NetcidrError::AllocationNotFound(id.to_string()));
            }
        }

        self.get_allocation(id).await
    }

    async fn find_allocations_in_supernet(
        &self,
        supernet_id: &str,
        statuses: &[AllocationStatus],
    ) -> Result<Vec<Allocation>> {
        if statuses.is_empty() {
            return Ok(Vec::new());
        }

        let mut placeholders = Vec::new();
        // $1 is supernet_id, statuses start at $2
        for i in 0..statuses.len() {
            placeholders.push(format!("${}", i + 2));
        }

        let sql = format!(
            "SELECT id, supernet_id, cidr, network_address, broadcast_address, prefix_length, total_hosts, total_hosts_text, resource_id, resource_type, name, description, environment, owner, status, parent_allocation_id, created_at, updated_at, released_at, expires_at FROM allocations WHERE supernet_id = $1 AND status IN ({}) ORDER BY network_address",
            placeholders.join(", ")
        );

        let mut query = sqlx::query(&sql).bind(supernet_id);
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

    async fn set_tags(&self, allocation_id: &str, tags: &[Tag]) -> Result<()> {
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

    async fn get_tags(&self, allocation_id: &str) -> Result<Vec<Tag>> {
        self.load_tags_for_allocation(allocation_id).await
    }

    // --- audit ---

    async fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details, caller_sub, caller_email, source_ip, request_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&entry.timestamp)
        .bind(&entry.action)
        .bind(&entry.entity_type)
        .bind(&entry.entity_id)
        .bind(&entry.details)
        .bind(&entry.caller_sub)
        .bind(&entry.caller_email)
        .bind(&entry.source_ip)
        .bind(&entry.request_id)
        .execute(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            "SELECT id, timestamp, action, entity_type, entity_id, details, caller_sub, caller_email, source_ip, request_id FROM audit_log WHERE true",
        );
        let mut param_values: Vec<String> = Vec::new();
        let mut idx = 1;

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
            #[allow(unused_assignments)]
            {
                idx += 1;
            }
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
                    timestamp: row.get("timestamp"),
                    action: row.get("action"),
                    entity_type: row.get("entity_type"),
                    entity_id: row.get("entity_id"),
                    details: row.get("details"),
                    caller_sub: row.try_get("caller_sub").ok(),
                    caller_email: row.try_get("caller_email").ok(),
                    source_ip: row.try_get("source_ip").ok(),
                    request_id: row.try_get("request_id").ok(),
                }
            })
            .collect())
    }

    async fn idempotency_get(&self, key: &str, scope: &str) -> Result<Option<IdempotencyRecord>> {
        let row = sqlx::query(
            "SELECT key, scope, request_hash, status_code, response_body, created_at, expires_at \
             FROM idempotency_keys WHERE key = $1 AND scope = $2",
        )
        .bind(key)
        .bind(scope)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
        Ok(row.map(|row| {
            let status_code: i32 = row.get("status_code");
            IdempotencyRecord {
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
                (key, scope, request_hash, status_code, response_body, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (key, scope) DO NOTHING",
        )
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
}
