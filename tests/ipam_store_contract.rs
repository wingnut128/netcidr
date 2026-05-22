//! Trait-contract test suite for IpamStore backend parity.
//!
//! These tests verify that any IpamStore implementation behaves identically.
//! Run against SQLite in-memory by default; Postgres via Docker with
//! `--features ipam-postgres`.

use netcidr::error::NetcidrError;
use netcidr::ipam::models::*;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;

const TEST_TENANT: &str = "test@example.com";

// ---------------------------------------------------------------------------
// Test harness: macro generates identical tests for each backend
// ---------------------------------------------------------------------------

/// Creates a ready-to-use SQLite in-memory store.
async fn sqlite_store() -> impl IpamStore {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    store
}

/// Macro that generates a full contract test suite for a given store factory.
macro_rules! store_contract_tests {
    ($factory:ident) => {
        // ---- CidrBlock CRUD ----

        #[tokio::test]
        async fn contract_cidr_block_create_and_get() {
            let store = $factory().await;

            let sn = store
                .create_cidr_block(
                    TEST_TENANT,
                    &CreateCidrBlock {
                        cidr: "10.0.0.0/8".to_string(),
                        name: Some("Corp".to_string()),
                        description: Some("Corporate network".to_string()),
                    },
                )
                .await
                .unwrap();

            assert_eq!(sn.cidr, "10.0.0.0/8");
            assert_eq!(sn.network_address, "10.0.0.0");
            assert_eq!(sn.broadcast_address, "10.255.255.255");
            assert_eq!(sn.prefix_length, 8);
            assert_eq!(sn.total_hosts, 16_777_216);
            assert_eq!(sn.ip_version, 4);
            assert_eq!(sn.name, Some("Corp".to_string()));
            assert_eq!(sn.description, Some("Corporate network".to_string()));
            assert!(!sn.id.is_empty());
            assert!(!sn.created_at.is_empty());

            let fetched = store.get_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
            assert_eq!(fetched.cidr, sn.cidr);
            assert_eq!(fetched.name, sn.name);
        }

        #[tokio::test]
        async fn contract_cidr_block_list() {
            let store = $factory().await;

            store
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
                .create_cidr_block(
                    TEST_TENANT,
                    &CreateCidrBlock {
                        cidr: "172.16.0.0/12".to_string(),
                        name: None,
                        description: None,
                    },
                )
                .await
                .unwrap();

            let all = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
            assert_eq!(all.len(), 2);
        }

        #[tokio::test]
        async fn contract_cidr_block_delete() {
            let store = $factory().await;

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

            store.delete_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
            let all = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
            assert!(all.is_empty());
        }

        #[tokio::test]
        async fn contract_cidr_block_delete_with_active_allocations_fails() {
            let store = $factory().await;

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

            let err = store
                .delete_cidr_block(TEST_TENANT, &sn.id)
                .await
                .unwrap_err();
            assert!(
                matches!(err, NetcidrError::CidrBlockHasActiveAllocations(_)),
                "expected CidrBlockHasActiveAllocations, got: {:?}",
                err
            );
        }

        #[tokio::test]
        async fn contract_cidr_block_get_not_found() {
            let store = $factory().await;
            let err = store
                .get_cidr_block(TEST_TENANT, "nonexistent-id")
                .await
                .unwrap_err();
            assert!(
                matches!(err, NetcidrError::CidrBlockNotFound(_)),
                "expected CidrBlockNotFound, got: {:?}",
                err
            );
        }

        #[tokio::test]
        async fn contract_cidr_block_duplicate_cidr_fails() {
            let store = $factory().await;

            store
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

            let err = store
                .create_cidr_block(
                    TEST_TENANT,
                    &CreateCidrBlock {
                        cidr: "10.0.0.0/8".to_string(),
                        name: None,
                        description: None,
                    },
                )
                .await
                .unwrap_err();

            // Should fail due to UNIQUE constraint on cidr
            assert!(
                matches!(err, NetcidrError::DatabaseError(_)),
                "expected DatabaseError for duplicate CIDR, got: {:?}",
                err
            );
        }

        // ---- Allocation CRUD ----

        #[tokio::test]
        async fn contract_allocation_create_defaults() {
            let store = $factory().await;

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

            assert_eq!(alloc.cidr, "10.0.0.0/24");
            assert_eq!(alloc.network_address, "10.0.0.0");
            assert_eq!(alloc.broadcast_address, "10.0.0.255");
            assert_eq!(alloc.prefix_length, 24);
            assert_eq!(alloc.total_hosts, 256);
            assert_eq!(alloc.status, AllocationStatus::Active);
            assert_eq!(alloc.cidr_block_id, sn.id);
            assert!(alloc.released_at.is_none());
            assert!(alloc.tags.is_empty());
        }

        #[tokio::test]
        async fn contract_allocation_create_with_all_fields() {
            let store = $factory().await;

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
                        status: Some(AllocationStatus::Reserved),
                        resource_id: Some("vpc-123".to_string()),
                        resource_type: Some("vpc".to_string()),
                        name: Some("web-tier".to_string()),
                        description: Some("Web tier subnet".to_string()),
                        environment: Some("production".to_string()),
                        owner: Some("team-a".to_string()),
                        parent_allocation_id: None,
                        tags: Some(vec![
                            Tag {
                                key: "env".to_string(),
                                value: "prod".to_string(),
                            },
                            Tag {
                                key: "cost-center".to_string(),
                                value: "eng".to_string(),
                            },
                        ]),
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();

            assert_eq!(alloc.status, AllocationStatus::Reserved);
            assert_eq!(alloc.resource_id, Some("vpc-123".to_string()));
            assert_eq!(alloc.resource_type, Some("vpc".to_string()));
            assert_eq!(alloc.name, Some("web-tier".to_string()));
            assert_eq!(alloc.description, Some("Web tier subnet".to_string()));
            assert_eq!(alloc.environment, Some("production".to_string()));
            assert_eq!(alloc.owner, Some("team-a".to_string()));
            assert_eq!(alloc.tags.len(), 2);

            // Verify get returns the same data
            let fetched = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
            assert_eq!(fetched.resource_id, alloc.resource_id);
            assert_eq!(fetched.tags.len(), 2);
        }

        #[tokio::test]
        async fn contract_allocation_update_partial() {
            let store = $factory().await;

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
                        resource_type: None,
                        name: Some("original".to_string()),
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

            // Update only description — name and resource_id should be preserved
            let updated = store
                .update_allocation(
                    TEST_TENANT,
                    &alloc.id,
                    &UpdateAllocation {
                        name: None,
                        description: Some("new desc".to_string()),
                        resource_id: None,
                        resource_type: None,
                        environment: None,
                        owner: None,
                        status: None,
                    },
                )
                .await
                .unwrap();

            assert_eq!(updated.description, Some("new desc".to_string()));
            assert_eq!(updated.name, Some("original".to_string()));
            assert_eq!(updated.resource_id, Some("vpc-123".to_string()));
        }

        #[tokio::test]
        async fn contract_allocation_release() {
            let store = $factory().await;

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

            let released = store
                .release_allocation(TEST_TENANT, &alloc.id)
                .await
                .unwrap();
            assert_eq!(released.status, AllocationStatus::Released);
            assert!(released.released_at.is_some());
        }

        #[tokio::test]
        async fn contract_allocation_get_not_found() {
            let store = $factory().await;
            let err = store
                .get_allocation(TEST_TENANT, "nonexistent-id")
                .await
                .unwrap_err();
            assert!(
                matches!(err, NetcidrError::AllocationNotFound(_)),
                "expected AllocationNotFound, got: {:?}",
                err
            );
        }

        // ---- Allocation filtering ----

        #[tokio::test]
        async fn contract_list_allocations_filters() {
            let store = $factory().await;

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
                        resource_id: Some("vpc-1".to_string()),
                        resource_type: Some("vpc".to_string()),
                        name: None,
                        description: None,
                        environment: Some("prod".to_string()),
                        owner: Some("team-a".to_string()),
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
                        resource_id: Some("vpc-2".to_string()),
                        resource_type: Some("vpc".to_string()),
                        name: None,
                        description: None,
                        environment: Some("staging".to_string()),
                        owner: Some("team-b".to_string()),
                        parent_allocation_id: None,
                        tags: None,
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();

            // Filter by cidr_block
            let by_sn = store
                .list_allocations(
                    TEST_TENANT,
                    &AllocationFilter {
                        cidr_block_id: Some(sn.id.clone()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_sn.len(), 2);

            // Filter by status
            let reserved = store
                .list_allocations(
                    TEST_TENANT,
                    &AllocationFilter {
                        status: Some(AllocationStatus::Reserved),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(reserved.len(), 1);
            assert_eq!(reserved[0].cidr, "10.0.1.0/24");

            // Filter by resource_id
            let by_res = store
                .list_allocations(
                    TEST_TENANT,
                    &AllocationFilter {
                        resource_id: Some("vpc-1".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_res.len(), 1);
            assert_eq!(by_res[0].cidr, "10.0.0.0/24");

            // Filter by environment
            let by_env = store
                .list_allocations(
                    TEST_TENANT,
                    &AllocationFilter {
                        environment: Some("staging".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_env.len(), 1);

            // Filter by owner
            let by_owner = store
                .list_allocations(
                    TEST_TENANT,
                    &AllocationFilter {
                        owner: Some("team-a".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_owner.len(), 1);
        }

        #[tokio::test]
        async fn contract_find_allocations_in_cidr_block_by_status() {
            let store = $factory().await;

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

            store.release_allocation(TEST_TENANT, &a1.id).await.unwrap();

            // Only reserved should remain in active+reserved query
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

            // Released query
            let released = store
                .find_allocations_in_cidr_block(TEST_TENANT, &sn.id, &[AllocationStatus::Released])
                .await
                .unwrap();
            assert_eq!(released.len(), 1);
            assert_eq!(released[0].status, AllocationStatus::Released);
        }

        // ---- Tags ----

        #[tokio::test]
        async fn contract_tags_set_get_replace() {
            let store = $factory().await;

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

            // Set initial tags
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
                            key: "team".to_string(),
                            value: "platform".to_string(),
                        },
                    ],
                )
                .await
                .unwrap();

            let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
            assert_eq!(tags.len(), 2);

            // Replace with different tags
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
            assert_eq!(tags[0].key, "env");
            assert_eq!(tags[0].value, "staging");
        }

        #[tokio::test]
        async fn contract_tags_included_in_allocation_get() {
            let store = $factory().await;

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

            // Tags should be present when fetching the allocation
            let fetched = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
            assert_eq!(fetched.tags.len(), 1);
            assert_eq!(fetched.tags[0].key, "env");
        }

        // ---- Audit ----

        #[tokio::test]
        async fn contract_audit_append_and_query() {
            let store = $factory().await;

            store
                .append_audit(&AuditEntry {
                    id: String::new(),
                    tenant_id: TEST_TENANT.to_string(),
                    entity_type: "cidr_block".to_string(),
                    entity_id: "sn-1".to_string(),
                    action: "create_cidr_block".to_string(),
                    details: Some("10.0.0.0/8".to_string()),
                    timestamp: "2026-03-16T00:00:00Z".to_string(),
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
                    timestamp: "2026-03-16T00:01:00Z".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap();

            // Query all
            let all = store
                .query_audit(TEST_TENANT, &AuditFilter::default())
                .await
                .unwrap();
            assert_eq!(all.len(), 2);

            // Filter by entity_type
            let cidr_blocks = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        entity_type: Some("cidr_block".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(cidr_blocks.len(), 1);
            assert_eq!(cidr_blocks[0].action, "create_cidr_block");

            // Filter by entity_id
            let by_id = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        entity_id: Some("alloc-1".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_id.len(), 1);

            // Filter by action
            let by_action = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        action: Some("allocate".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_action.len(), 1);

            // Limit
            let limited = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        limit: Some(1),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(limited.len(), 1);
        }

        // ---- Parent allocation ----

        #[tokio::test]
        async fn contract_parent_allocation() {
            let store = $factory().await;

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

            let parent = store
                .create_allocation(
                    TEST_TENANT,
                    &CreateAllocation {
                        cidr_block_id: sn.id.clone(),
                        cidr: "10.0.0.0/16".to_string(),
                        status: None,
                        resource_id: None,
                        resource_type: None,
                        name: Some("parent".to_string()),
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

            let child = store
                .create_allocation(
                    TEST_TENANT,
                    &CreateAllocation {
                        cidr_block_id: sn.id.clone(),
                        cidr: "10.0.1.0/24".to_string(),
                        status: None,
                        resource_id: None,
                        resource_type: None,
                        name: Some("child".to_string()),
                        description: None,
                        environment: None,
                        owner: None,
                        parent_allocation_id: Some(parent.id.clone()),
                        tags: None,
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();

            assert_eq!(child.parent_allocation_id, Some(parent.id));
        }

        // ---- Idempotent migration ----

        #[tokio::test]
        async fn contract_migrate_idempotent() {
            let store = $factory().await;

            // Migrate again — should be a no-op
            store.migrate().await.unwrap();

            // Store should still work
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
            assert_eq!(sn.cidr, "10.0.0.0/8");
        }

        // ---- Personal Access Tokens ----

        #[tokio::test]
        async fn contract_pat_round_trip_create_and_get() {
            let store = $factory().await;
            let created = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: TEST_TENANT.to_string(),
                    owner_sub: "sub-1".to_string(),
                    owner_email: TEST_TENANT.to_string(),
                    name: "laptop".to_string(),
                    prefix: "ncdr_pat_AAA".to_string(),
                    token_hash: vec![0xAAu8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2099-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();
            assert_eq!(created.token_hash, vec![0xAAu8; 32]);

            let hit = store
                .pat_get_by_hash(&created.token_hash, "2026-05-02T00:00:00Z")
                .await
                .unwrap()
                .expect("active PAT should hit");
            assert_eq!(hit.id, created.id);
        }

        #[tokio::test]
        async fn contract_pat_get_by_hash_misses_expired_and_revoked() {
            let store = $factory().await;
            let expired = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: TEST_TENANT.to_string(),
                    owner_sub: "sub-1".to_string(),
                    owner_email: TEST_TENANT.to_string(),
                    name: "expired".to_string(),
                    prefix: "ncdr_pat_EXP".to_string(),
                    token_hash: vec![0xBBu8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2020-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();
            let revoked = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: TEST_TENANT.to_string(),
                    owner_sub: "sub-1".to_string(),
                    owner_email: TEST_TENANT.to_string(),
                    name: "revoked".to_string(),
                    prefix: "ncdr_pat_REV".to_string(),
                    token_hash: vec![0xCCu8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2099-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();
            store
                .pat_revoke(TEST_TENANT, "sub-1", &revoked.id, "2026-05-02T00:00:00Z")
                .await
                .unwrap();

            let now = "2026-05-02T00:00:00Z";
            assert!(
                store
                    .pat_get_by_hash(&expired.token_hash, now)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .pat_get_by_hash(&revoked.token_hash, now)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn contract_pat_list_isolates_owners_and_tenants() {
            let store = $factory().await;
            let a1 = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: "a@x".to_string(),
                    owner_sub: "sub-a1".to_string(),
                    owner_email: "a@x".to_string(),
                    name: "a1".to_string(),
                    prefix: "ncdr_pat_A1".to_string(),
                    token_hash: vec![0x01u8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2099-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();
            let _a2 = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: "a@x".to_string(),
                    owner_sub: "sub-a2".to_string(),
                    owner_email: "a@x".to_string(),
                    name: "a2".to_string(),
                    prefix: "ncdr_pat_A2".to_string(),
                    token_hash: vec![0x02u8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2099-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();
            let _b1 = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: "b@x".to_string(),
                    owner_sub: "sub-b1".to_string(),
                    owner_email: "b@x".to_string(),
                    name: "b1".to_string(),
                    prefix: "ncdr_pat_B1".to_string(),
                    token_hash: vec![0x03u8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2099-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();

            let listed = store.pat_list_for_owner("a@x", "sub-a1").await.unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, a1.id);
        }

        #[tokio::test]
        async fn contract_pat_revoke_idempotent_and_cross_owner_not_found() {
            let store = $factory().await;
            let t = store
                .pat_create(&CreatePersonalAccessToken {
                    tenant_id: "a@x".to_string(),
                    owner_sub: "sub-a1".to_string(),
                    owner_email: "a@x".to_string(),
                    name: "tok".to_string(),
                    prefix: "ncdr_pat_TOK".to_string(),
                    token_hash: vec![0xD1u8; 32],
                    role: netcidr::auth::Role::Admin,
                    expires_at: "2099-01-01T00:00:00Z".to_string(),
                })
                .await
                .unwrap();

            let first = store
                .pat_revoke("a@x", "sub-a1", &t.id, "2026-05-02T00:00:00Z")
                .await
                .unwrap();
            assert!(first.revoked_at.is_some());
            // Idempotent.
            let second = store
                .pat_revoke("a@x", "sub-a1", &t.id, "2026-06-01T00:00:00Z")
                .await
                .unwrap();
            assert_eq!(second.revoked_at, first.revoked_at);

            // Cross-owner lookup → PatNotFound.
            let cross = store
                .pat_revoke("a@x", "sub-other", &t.id, "2026-05-02T00:00:00Z")
                .await;
            assert!(matches!(cross, Err(NetcidrError::PatNotFound(_))));
        }

        #[tokio::test]
        async fn contract_pat_reap_expired_count() {
            let store = $factory().await;
            for (i, expires_at) in [
                "2020-01-01T00:00:00Z",
                "2020-02-01T00:00:00Z",
                "2099-01-01T00:00:00Z",
            ]
            .iter()
            .enumerate()
            {
                store
                    .pat_create(&CreatePersonalAccessToken {
                        tenant_id: TEST_TENANT.to_string(),
                        owner_sub: "sub-1".to_string(),
                        owner_email: TEST_TENANT.to_string(),
                        name: format!("t{i}"),
                        prefix: format!("ncdr_pat_{i:03}"),
                        token_hash: vec![0xE0u8 + i as u8; 32],
                        role: netcidr::auth::Role::Admin,
                        expires_at: (*expires_at).to_string(),
                    })
                    .await
                    .unwrap();
            }
            let removed = store
                .pat_reap_expired("2025-01-01T00:00:00Z")
                .await
                .unwrap();
            assert_eq!(removed, 2);
        }
    };
}

// ---------------------------------------------------------------------------
// Run contract tests against SQLite
// ---------------------------------------------------------------------------

mod sqlite_contract {
    use super::*;
    store_contract_tests!(sqlite_store);
}

// ---------------------------------------------------------------------------
// Migration upgrade path tests
// ---------------------------------------------------------------------------

mod migration_upgrade {
    use super::*;

    /// Verify that data inserted at v1 survives re-migration (idempotency).
    #[tokio::test]
    async fn data_survives_remigration() {
        let store = sqlite_store().await;

        // Insert data at current schema version
        let sn = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: Some("Corp".to_string()),
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
                    resource_id: Some("vpc-1".to_string()),
                    resource_type: Some("vpc".to_string()),
                    name: Some("web".to_string()),
                    description: Some("Web subnet".to_string()),
                    environment: Some("prod".to_string()),
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

        store
            .append_audit(&AuditEntry {
                id: String::new(),
                tenant_id: TEST_TENANT.to_string(),
                entity_type: "allocation".to_string(),
                entity_id: alloc.id.clone(),
                action: "allocate".to_string(),
                details: Some("10.0.0.0/24".to_string()),
                timestamp: "2026-03-16T00:00:00Z".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Re-run migrations
        store.migrate().await.unwrap();

        // Verify all data intact
        let fetched_sn = store.get_cidr_block(TEST_TENANT, &sn.id).await.unwrap();
        assert_eq!(fetched_sn.cidr, "10.0.0.0/8");
        assert_eq!(fetched_sn.name, Some("Corp".to_string()));

        let fetched_alloc = store.get_allocation(TEST_TENANT, &alloc.id).await.unwrap();
        assert_eq!(fetched_alloc.cidr, "10.0.0.0/24");
        assert_eq!(fetched_alloc.resource_id, Some("vpc-1".to_string()));
        assert_eq!(fetched_alloc.name, Some("web".to_string()));
        assert_eq!(fetched_alloc.tags.len(), 1);

        let audit = store
            .query_audit(
                TEST_TENANT,
                &AuditFilter {
                    entity_id: Some(alloc.id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
    }

    /// Verify that a complex state (multiple cidr_blocks, allocations, releases,
    /// tags, audit entries) survives re-migration without corruption.
    #[tokio::test]
    async fn complex_state_survives_remigration() {
        let store = sqlite_store().await;

        // Create two cidr_blocks
        let sn1 = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: Some("Corp".to_string()),
                    description: None,
                },
            )
            .await
            .unwrap();

        let sn2 = store
            .create_cidr_block(
                TEST_TENANT,
                &CreateCidrBlock {
                    cidr: "172.16.0.0/12".to_string(),
                    name: Some("Cloud".to_string()),
                    description: None,
                },
            )
            .await
            .unwrap();

        // Create allocations in both
        let a1 = store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn1.id.clone(),
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
                    cidr_block_id: sn1.id.clone(),
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

        store
            .create_allocation(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn2.id.clone(),
                    cidr: "172.16.0.0/24".to_string(),
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

        // Release one
        store.release_allocation(TEST_TENANT, &a1.id).await.unwrap();

        // Set tags
        store
            .set_tags(
                TEST_TENANT,
                &a1.id,
                &[Tag {
                    key: "decom".to_string(),
                    value: "true".to_string(),
                }],
            )
            .await
            .unwrap();

        // Re-migrate
        store.migrate().await.unwrap();

        // Verify counts
        let cidr_blocks = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
        assert_eq!(cidr_blocks.len(), 2);

        let all_allocs = store
            .list_allocations(TEST_TENANT, &AllocationFilter::default())
            .await
            .unwrap();
        assert_eq!(all_allocs.len(), 3);

        // Verify release survived
        let released = store.get_allocation(TEST_TENANT, &a1.id).await.unwrap();
        assert_eq!(released.status, AllocationStatus::Released);
        assert!(released.released_at.is_some());

        // Verify tags survived
        let tags = store.get_tags(TEST_TENANT, &a1.id).await.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].key, "decom");
    }

    /// Verify schema_version is tracked correctly after migration.
    #[tokio::test]
    async fn schema_version_tracked() {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();

        // The store should work after migration
        let cidr_blocks = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
        assert!(cidr_blocks.is_empty());

        // Re-migrate should be safe
        store.migrate().await.unwrap();
        let cidr_blocks = store.list_cidr_blocks(TEST_TENANT).await.unwrap();
        assert!(cidr_blocks.is_empty());
    }
}
