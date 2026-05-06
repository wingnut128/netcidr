#![cfg(feature = "ipam-postgres")]

//! PostgreSQL integration tests.
//!
//! These tests start a Docker container running PostgreSQL, exercise the
//! `PostgresStore` implementation against it, then tear the container down.
//!
//! Requirements: Docker must be running locally.
//! Run with: `cargo test --features ipam-postgres --test postgres_integration`

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use netcidr::ipam::config::PostgresConfig;
use netcidr::ipam::models::*;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::postgres::PostgresStore;
use netcidr::ipam::store::IpamStore;

const TEST_TENANT: &str = "test@example.com";

const CONTAINER_NAME: &str = "netcidr-test-pg";
const PG_PORT: u16 = 15432;
const PG_DB: &str = "netcidr_test";
const PG_USER: &str = "postgres";

fn pg_url() -> String {
    format!("postgresql://{PG_USER}@127.0.0.1:{PG_PORT}/{PG_DB}")
}

fn start_container() {
    // Remove any leftover container from a previous run
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER_NAME])
        .output();

    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            CONTAINER_NAME,
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            &format!("POSTGRES_DB={PG_DB}"),
            "-e",
            &format!("POSTGRES_USER={PG_USER}"),
            "-p",
            &format!("{PG_PORT}:5432"),
            "postgres:16-alpine",
        ])
        .status()
        .expect("failed to start postgres container — is Docker running?");
    assert!(status.success(), "docker run failed");
}

fn stop_container() {
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER_NAME])
        .output();
}

fn wait_for_pg() {
    for _ in 0..30 {
        let output = Command::new("docker")
            .args(["exec", CONTAINER_NAME, "pg_isready", "-U", PG_USER])
            .output()
            .expect("failed to run pg_isready");
        if output.status.success() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("PostgreSQL did not become ready within 15 seconds");
}

async fn new_store() -> PostgresStore {
    let config = PostgresConfig {
        url: Some(pg_url()),
        max_connections: 5,
        min_connections: 1,
    };
    let store = PostgresStore::new(&pg_url(), &config)
        .await
        .expect("failed to connect to PostgreSQL");
    store.initialize().await.expect("initialize failed");
    store.migrate().await.expect("migrate failed");
    store
}

/// Single test function that runs all PostgreSQL assertions sequentially
/// against one container to avoid port/container conflicts.
#[tokio::test]
async fn test_postgres_backend() {
    start_container();
    wait_for_pg();

    // Wrap in a closure so we always stop the container, even on panic
    let result = tokio::spawn(async {
        let store = new_store().await;

        // --- idempotent migrate ---
        store
            .migrate()
            .await
            .expect("second migrate should be idempotent");

        // --- cidr_block CRUD ---
        cidr_block_crud(&store).await;

        // --- allocation lifecycle ---
        allocation_lifecycle(&store).await;

        // --- tags ---
        tags(&store).await;

        // --- audit log ---
        audit_log(&store).await;

        // --- personal access tokens smoke ---
        personal_access_tokens(&store).await;

        // --- operations layer (auto-allocate, utilization, free blocks) ---
        operations_layer(store).await;
    })
    .await;

    stop_container();
    result.expect("test panicked inside spawned task");
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

    // Update
    let updated = store
        .update_allocation(
            TEST_TENANT,
            &alloc.id,
            &UpdateAllocation {
                name: None,
                description: Some("updated".to_string()),
                resource_id: None,
                resource_type: None,
                environment: None,
                owner: Some("new-team".to_string()),
                status: None,
            },
        )
        .await
        .unwrap();
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
    let released = store
        .release_allocation(TEST_TENANT, &alloc.id)
        .await
        .unwrap();
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
    store
        .release_allocation(TEST_TENANT, &alloc.id)
        .await
        .unwrap();
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
    let r1 = store
        .pat_revoke(
            TEST_TENANT,
            "sub-pat-1",
            &created.id,
            "2026-05-02T00:00:00Z",
        )
        .await
        .unwrap();
    assert!(r1.revoked_at.is_some());
    let r2 = store
        .pat_revoke(
            TEST_TENANT,
            "sub-pat-1",
            &created.id,
            "2026-06-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert_eq!(r1.revoked_at, r2.revoked_at);

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
}
