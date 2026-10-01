#![cfg(feature = "ipam-postgres")]

//! PostgreSQL integration tests.
//!
//! Exercises `PostgresStore` and the operations layer on a per-test
//! database. See `store_support` for how the Postgres server is found
//! (`NETCIDR_TEST_DATABASE_URL`, or a local Docker container).
//!
//! Run with: `cargo test --features ipam-postgres --test postgres_integration`

mod store_support;

use store_support::Seed;

use std::sync::Arc;

use netcidr::ipam::models::*;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::postgres::PostgresStore;
use netcidr::ipam::store::IpamStore;

const TEST_TENANT: &str = "test@example.com";

#[tokio::test]
async fn test_postgres_backend() {
    let (store, _db) = store_support::postgres_store().await.into_parts();

    // --- idempotent migrate ---
    store
        .migrate()
        .await
        .expect("second migrate should be idempotent");

    cidr_block_crud(&store).await;
    allocation_lifecycle(&store).await;
    tags(&store).await;
    audit_log(&store).await;
    personal_access_tokens(&store).await;

    // --- operations layer (auto-allocate, utilization, free blocks) ---
    operations_layer(store).await;
}

/// The `allocations` tenant trigger rejects an allocation whose tenant
/// differs from its cidr block's, even for raw SQL that bypasses IpamOps.
#[tokio::test]
async fn allocation_with_mismatched_tenant_id_is_rejected_by_trigger() {
    let db = store_support::pg::test_database().await;
    let _store = store_support::open_postgres(&db.url()).await; // runs migrations
    let pool = sqlx::PgPool::connect(&db.url()).await.unwrap();

    sqlx::query(
        r#"INSERT INTO cidr_blocks
           (id, tenant_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, ip_version, created_at, updated_at)
           VALUES ('s1','a@x','10.0.0.0/8','10.0.0.0','10.255.255.255',
                   8,'16777216',4,'2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let result = sqlx::query(
        r#"INSERT INTO allocations
           (id, tenant_id, cidr_block_id, cidr, network_address, broadcast_address,
            prefix_length, total_hosts, status, created_at, updated_at)
           VALUES ('a1','b@x','s1','10.1.0.0/16','10.1.0.0','10.1.255.255',
                   16,'65536','active','2026-05-02T00:00:00Z','2026-05-02T00:00:00Z')"#,
    )
    .execute(&pool)
    .await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("must match parent")
    );
    pool.close().await;
}

/// Commit one `ReplaceAllocation` through a transaction unit.
async fn replace(store: &PostgresStore, alloc: Allocation) {
    store
        .transact(netcidr::ipam::store::TxUnit {
            scope: netcidr::ipam::store::LockScope::CidrBlock {
                tenant_id: alloc.tenant_id.clone(),
                cidr_block_id: alloc.cidr_block_id.clone(),
            },
            reads: vec![],
            idempotency: None,
            decide: Box::new(move |_| {
                Ok(netcidr::ipam::store::Plan {
                    writes: vec![netcidr::ipam::store::Write::ReplaceAllocation(alloc)],
                    ..Default::default()
                })
            }),
        })
        .await
        .unwrap();
}

fn released_row(mut alloc: Allocation) -> Allocation {
    let now = chrono::Utc::now().to_rfc3339();
    alloc.status = AllocationStatus::Released;
    alloc.released_at = Some(now.clone());
    alloc.updated_at = now;
    alloc
}

async fn cidr_block_crud(store: &PostgresStore) {
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

    let fetched = store.get_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
    assert_eq!(fetched.cidr, "10.0.0.0/8");
    assert_eq!(fetched.name, Some("RFC1918 Class A".to_string()));

    let all = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
    assert!(all.iter().any(|s| s.id == sn.id));

    store.delete_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
    let err = store.get_cidr_block(TEST_TENANT, &sn.id).await;
    assert!(err.is_err());
}

async fn allocation_lifecycle(store: &PostgresStore) {
    let sn = store
        .create_cidr_block(
            TEST_TENANT,
            &CreateCidrBlock {
                cidr: "172.16.0.0/12".to_string(),
                name: Some("Private".to_string()),
                description: None,
            },
        )
        .await
        .unwrap();

    // Allocate with tags
    let alloc = store
        .create_allocation(
            TEST_TENANT,
            &CreateAllocation {
                cidr_block_id: sn.id.clone(),
                cidr: "172.16.0.0/24".to_string(),
                status: None,
                resource_id: Some("vpc-abc".to_string()),
                resource_type: Some("vpc".to_string()),
                name: Some("web-tier".to_string()),
                description: None,
                environment: Some("production".to_string()),
                owner: Some("platform".to_string()),
                parent_allocation_id: None,
                tags: Some(vec![Tag {
                    key: "team".to_string(),
                    value: "infra".to_string(),
                }]),
                ttl_seconds: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(alloc.status, AllocationStatus::Active);
    assert_eq!(alloc.tags.len(), 1);
    assert_eq!(alloc.prefix_length, 24);

    // Get
    let fetched = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
    assert_eq!(fetched.resource_id, Some("vpc-abc".to_string()));
    assert_eq!(fetched.tags.len(), 1);
    assert_eq!(fetched.tags[0].key, "team");

    // Replace mutable fields
    let mut changed = fetched.clone();
    changed.description = Some("updated".to_string());
    changed.owner = Some("new-team".to_string());
    replace(store, changed).await;
    let updated = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
    assert_eq!(updated.description, Some("updated".to_string()));
    assert_eq!(updated.owner, Some("new-team".to_string()));

    // List with filter
    let filtered = store
        .list_allocations(
            TEST_TENANT,
            &AllocationFilter {
                cidr_block_id: Some(sn.id.clone()),
                status: Some(AllocationStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);

    // Release
    replace(store, released_row(updated)).await;
    let released = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
    assert_eq!(released.status, AllocationStatus::Released);
    assert!(released.released_at.is_some());

    // Find by status — should be empty (all released)
    let active = store
        .find_allocations_in_cidr_block(
            TEST_TENANT,
            &sn.id,
            &[AllocationStatus::Active, AllocationStatus::Reserved],
        )
        .await
        .unwrap();
    assert!(active.is_empty());

    // Delete cidr_block (allocations are released)
    store.delete_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
}

async fn tags(store: &PostgresStore) {
    let sn = store
        .create_cidr_block(
            TEST_TENANT,
            &CreateCidrBlock {
                cidr: "192.168.0.0/16".to_string(),
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
                cidr: "192.168.1.0/24".to_string(),
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

    // Set tags
    store
        .set_tags(
            TEST_TENANT,
            &alloc.id,
            &[
                Tag {
                    key: "env".to_string(),
                    value: "prod".to_string(),
                },
                Tag {
                    key: "cost-center".to_string(),
                    value: "eng".to_string(),
                },
            ],
        )
        .await
        .unwrap();
    let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
    assert_eq!(tags.len(), 2);

    // Replace tags
    store
        .set_tags(
            TEST_TENANT,
            &alloc.id,
            &[Tag {
                key: "env".to_string(),
                value: "staging".to_string(),
            }],
        )
        .await
        .unwrap();
    let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].value, "staging");

    // Cleanup
    let current = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
    replace(store, released_row(current)).await;
    store.delete_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
}

async fn audit_log(store: &PostgresStore) {
    store
        .append_audit(&AuditEntry {
            id: String::new(),
            tenant_id: TEST_TENANT.to_string(),
            entity_type: "cidr_block".to_string(),
            entity_id: "sn-1".to_string(),
            action: "create_cidr_block".to_string(),
            details: Some(r#"{"cidr":"10.0.0.0/8"}"#.to_string()),
            timestamp: "2026-03-06T00:00:00Z".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .append_audit(&AuditEntry {
            id: String::new(),
            tenant_id: TEST_TENANT.to_string(),
            entity_type: "allocation".to_string(),
            entity_id: "alloc-1".to_string(),
            action: "allocate".to_string(),
            details: None,
            timestamp: "2026-03-06T00:01:00Z".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    // Query all
    let entries = store
        .query_audit(TEST_TENANT, &AuditFilter::default())
        .await
        .unwrap();
    assert!(entries.len() >= 2);

    // Query filtered by entity_id
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

    // Query with limit
    let entries = store
        .query_audit(
            TEST_TENANT,
            &AuditFilter {
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
}

async fn personal_access_tokens(store: &PostgresStore) {
    // Round-trip create + get_by_hash.
    let created = store
        .pat_create(&CreatePersonalAccessToken {
            tenant_id: TEST_TENANT.to_string(),
            owner_sub: "sub-pat-1".to_string(),
            owner_email: TEST_TENANT.to_string(),
            name: "smoke".to_string(),
            prefix: "ncdr_pat_SMK".to_string(),
            token_hash: vec![0xA1u8; 32],
            role: netcidr::auth::Role::Admin,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        })
        .await
        .unwrap();

    let hit = store
        .pat_get_by_hash(&created.token_hash, "2026-05-02T00:00:00Z")
        .await
        .unwrap()
        .expect("active PAT should hit");
    assert_eq!(hit.id, created.id);
    assert_eq!(hit.token_hash, vec![0xA1u8; 32]);

    // Listing scoped to (tenant, owner_sub).
    let listed = store
        .pat_list_for_owner(TEST_TENANT, "sub-pat-1")
        .await
        .unwrap();
    assert!(listed.iter().any(|t| t.id == created.id));

    // Idempotent revoke.
    store
        .pat_revoke(
            TEST_TENANT,
            "sub-pat-1",
            &created.id,
            "2026-05-02T00:00:00Z",
        )
        .await
        .unwrap();

    // Revoked tokens miss `pat_get_by_hash`.
    let miss = store
        .pat_get_by_hash(&created.token_hash, "2026-05-02T00:00:00Z")
        .await
        .unwrap();
    assert!(miss.is_none());

    // Reap expired removes only the expired row.
    store
        .pat_create(&CreatePersonalAccessToken {
            tenant_id: TEST_TENANT.to_string(),
            owner_sub: "sub-pat-1".to_string(),
            owner_email: TEST_TENANT.to_string(),
            name: "old".to_string(),
            prefix: "ncdr_pat_OLD".to_string(),
            token_hash: vec![0xA2u8; 32],
            role: netcidr::auth::Role::Admin,
            expires_at: "2020-01-01T00:00:00Z".to_string(),
        })
        .await
        .unwrap();
    let n = store
        .pat_reap_expired("2025-01-01T00:00:00Z")
        .await
        .unwrap();
    assert!(n >= 1);
}

async fn operations_layer(store: PostgresStore) {
    let ops = IpamOps::new(Arc::new(store));

    let sn = ops
        .create_cidr_block(
            TEST_TENANT,
            &CreateCidrBlock {
                cidr: "10.100.0.0/16".to_string(),
                name: Some("ops-test".to_string()),
                description: None,
            },
        )
        .await
        .unwrap();

    // Auto-allocate 3 x /24
    let allocs = ops
        .allocate_auto(
            TEST_TENANT,
            &AutoAllocateRequest {
                cidr_block_id: sn.id.clone(),
                prefix_length: 24,
                count: Some(3),
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
    assert_eq!(allocs.len(), 3);
    assert_eq!(allocs[0].cidr, "10.100.0.0/24");
    assert_eq!(allocs[1].cidr, "10.100.1.0/24");
    assert_eq!(allocs[2].cidr, "10.100.2.0/24");

    // Utilization
    let util = ops.utilization(TEST_TENANT, &sn.id).await.unwrap();
    assert_eq!(util.allocation_count, 3);
    assert!(util.utilization_percent > 0.0);

    // Free blocks
    let free = ops.free_blocks(TEST_TENANT, &sn.id, None).await.unwrap();
    assert!(!free.blocks.is_empty());
    assert!(free.total_free > 0);

    // Re-allocating a released CIDR creates a new record; the released one
    // stays as history and nothing is inherited from it.
    let released = ops
        .release_allocation(TEST_TENANT, &allocs[0].id)
        .await
        .unwrap();
    let fresh = ops
        .allocate_specific(
            TEST_TENANT,
            &CreateAllocation {
                cidr_block_id: sn.id.clone(),
                cidr: released.cidr.clone(),
                status: None,
                resource_id: None,
                resource_type: None,
                name: Some("reused".to_string()),
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
    assert_ne!(fresh.id, released.id);
    assert_eq!(fresh.name.as_deref(), Some("reused"));
    let old = ops
        .list_allocations(
            TEST_TENANT,
            &AllocationFilter {
                cidr_block_id: Some(sn.id.clone()),
                status: Some(AllocationStatus::Released),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].id, released.id);
}
