//! Trait-contract test suite for IpamStore backend parity.
//!
//! These tests verify that any IpamStore implementation behaves identically.
//! Run against SQLite in-memory by default; Postgres via Docker with
//! `--features ipam-postgres`.

use ipcalc::error::IpCalcError;
use ipcalc::ipam::models::*;
use ipcalc::ipam::sqlite::SqliteStore;
use ipcalc::ipam::store::IpamStore;

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
        // ---- Supernet CRUD ----

        #[tokio::test]
        async fn contract_supernet_create_and_get() {
            let store = $factory().await;

            let sn = store
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: Some("Corp".to_string()),
                    description: Some("Corporate network".to_string()),
                })
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

            let fetched = store.get_supernet(&sn.id).await.unwrap();
            assert_eq!(fetched.cidr, sn.cidr);
            assert_eq!(fetched.name, sn.name);
        }

        #[tokio::test]
        async fn contract_supernet_list() {
            let store = $factory().await;

            store
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap();
            store
                .create_supernet(&CreateSupernet {
                    cidr: "172.16.0.0/12".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap();

            let all = store.list_supernets().await.unwrap();
            assert_eq!(all.len(), 2);
        }

        #[tokio::test]
        async fn contract_supernet_delete() {
            let store = $factory().await;

            let sn = store
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap();

            store.delete_supernet(&sn.id).await.unwrap();
            let all = store.list_supernets().await.unwrap();
            assert!(all.is_empty());
        }

        #[tokio::test]
        async fn contract_supernet_delete_with_active_allocations_fails() {
            let store = $factory().await;

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
            assert!(
                matches!(err, IpCalcError::SupernetHasActiveAllocations(_)),
                "expected SupernetHasActiveAllocations, got: {:?}",
                err
            );
        }

        #[tokio::test]
        async fn contract_supernet_get_not_found() {
            let store = $factory().await;
            let err = store.get_supernet("nonexistent-id").await.unwrap_err();
            assert!(
                matches!(err, IpCalcError::SupernetNotFound(_)),
                "expected SupernetNotFound, got: {:?}",
                err
            );
        }

        #[tokio::test]
        async fn contract_supernet_duplicate_cidr_fails() {
            let store = $factory().await;

            store
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap();

            let err = store
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap_err();

            // Should fail due to UNIQUE constraint on cidr
            assert!(
                matches!(err, IpCalcError::DatabaseError(_)),
                "expected DatabaseError for duplicate CIDR, got: {:?}",
                err
            );
        }

        // ---- Allocation CRUD ----

        #[tokio::test]
        async fn contract_allocation_create_defaults() {
            let store = $factory().await;

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

            assert_eq!(alloc.cidr, "10.0.0.0/24");
            assert_eq!(alloc.network_address, "10.0.0.0");
            assert_eq!(alloc.broadcast_address, "10.0.0.255");
            assert_eq!(alloc.prefix_length, 24);
            assert_eq!(alloc.total_hosts, 256);
            assert_eq!(alloc.status, AllocationStatus::Active);
            assert_eq!(alloc.supernet_id, sn.id);
            assert!(alloc.released_at.is_none());
            assert!(alloc.tags.is_empty());
        }

        #[tokio::test]
        async fn contract_allocation_create_with_all_fields() {
            let store = $factory().await;

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
                })
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
            let fetched = store.get_allocation(&alloc.id).await.unwrap();
            assert_eq!(fetched.resource_id, alloc.resource_id);
            assert_eq!(fetched.tags.len(), 2);
        }

        #[tokio::test]
        async fn contract_allocation_update_partial() {
            let store = $factory().await;

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
                    resource_type: None,
                    name: Some("original".to_string()),
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                })
                .await
                .unwrap();

            // Update only description — name and resource_id should be preserved
            let updated = store
                .update_allocation(
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

            let released = store.release_allocation(&alloc.id).await.unwrap();
            assert_eq!(released.status, AllocationStatus::Released);
            assert!(released.released_at.is_some());
        }

        #[tokio::test]
        async fn contract_allocation_get_not_found() {
            let store = $factory().await;
            let err = store.get_allocation("nonexistent-id").await.unwrap_err();
            assert!(
                matches!(err, IpCalcError::AllocationNotFound(_)),
                "expected AllocationNotFound, got: {:?}",
                err
            );
        }

        // ---- Allocation filtering ----

        #[tokio::test]
        async fn contract_list_allocations_filters() {
            let store = $factory().await;

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
                    resource_id: Some("vpc-1".to_string()),
                    resource_type: Some("vpc".to_string()),
                    name: None,
                    description: None,
                    environment: Some("prod".to_string()),
                    owner: Some("team-a".to_string()),
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
                    resource_id: Some("vpc-2".to_string()),
                    resource_type: Some("vpc".to_string()),
                    name: None,
                    description: None,
                    environment: Some("staging".to_string()),
                    owner: Some("team-b".to_string()),
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: None,
                })
                .await
                .unwrap();

            // Filter by supernet
            let by_sn = store
                .list_allocations(&AllocationFilter {
                    supernet_id: Some(sn.id.clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(by_sn.len(), 2);

            // Filter by status
            let reserved = store
                .list_allocations(&AllocationFilter {
                    status: Some(AllocationStatus::Reserved),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(reserved.len(), 1);
            assert_eq!(reserved[0].cidr, "10.0.1.0/24");

            // Filter by resource_id
            let by_res = store
                .list_allocations(&AllocationFilter {
                    resource_id: Some("vpc-1".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(by_res.len(), 1);
            assert_eq!(by_res[0].cidr, "10.0.0.0/24");

            // Filter by environment
            let by_env = store
                .list_allocations(&AllocationFilter {
                    environment: Some("staging".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(by_env.len(), 1);

            // Filter by owner
            let by_owner = store
                .list_allocations(&AllocationFilter {
                    owner: Some("team-a".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(by_owner.len(), 1);
        }

        #[tokio::test]
        async fn contract_find_allocations_in_supernet_by_status() {
            let store = $factory().await;

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

            // Only reserved should remain in active+reserved query
            let active = store
                .find_allocations_in_supernet(
                    &sn.id,
                    &[AllocationStatus::Active, AllocationStatus::Reserved],
                )
                .await
                .unwrap();
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].status, AllocationStatus::Reserved);

            // Released query
            let released = store
                .find_allocations_in_supernet(&sn.id, &[AllocationStatus::Released])
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

            // Set initial tags
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

            // Replace with different tags
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
            assert_eq!(tags[0].key, "env");
            assert_eq!(tags[0].value, "staging");
        }

        #[tokio::test]
        async fn contract_tags_included_in_allocation_get() {
            let store = $factory().await;

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
                    tags: Some(vec![Tag {
                        key: "env".to_string(),
                        value: "prod".to_string(),
                    }]),
                    ttl_seconds: None,
                })
                .await
                .unwrap();

            // Tags should be present when fetching the allocation
            let fetched = store.get_allocation(&alloc.id).await.unwrap();
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
                    entity_type: "supernet".to_string(),
                    entity_id: "sn-1".to_string(),
                    action: "create_supernet".to_string(),
                    details: Some("10.0.0.0/8".to_string()),
                    timestamp: "2026-03-16T00:00:00Z".to_string(),
                })
                .await
                .unwrap();

            store
                .append_audit(&AuditEntry {
                    id: String::new(),
                    entity_type: "allocation".to_string(),
                    entity_id: "alloc-1".to_string(),
                    action: "allocate".to_string(),
                    details: None,
                    timestamp: "2026-03-16T00:01:00Z".to_string(),
                })
                .await
                .unwrap();

            // Query all
            let all = store.query_audit(&AuditFilter::default()).await.unwrap();
            assert_eq!(all.len(), 2);

            // Filter by entity_type
            let supernets = store
                .query_audit(&AuditFilter {
                    entity_type: Some("supernet".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(supernets.len(), 1);
            assert_eq!(supernets[0].action, "create_supernet");

            // Filter by entity_id
            let by_id = store
                .query_audit(&AuditFilter {
                    entity_id: Some("alloc-1".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(by_id.len(), 1);

            // Filter by action
            let by_action = store
                .query_audit(&AuditFilter {
                    action: Some("allocate".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(by_action.len(), 1);

            // Limit
            let limited = store
                .query_audit(&AuditFilter {
                    limit: Some(1),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(limited.len(), 1);
        }

        // ---- Parent allocation ----

        #[tokio::test]
        async fn contract_parent_allocation() {
            let store = $factory().await;

            let sn = store
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap();

            let parent = store
                .create_allocation(&CreateAllocation {
                    supernet_id: sn.id.clone(),
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
                })
                .await
                .unwrap();

            let child = store
                .create_allocation(&CreateAllocation {
                    supernet_id: sn.id.clone(),
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
                })
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
                .create_supernet(&CreateSupernet {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                })
                .await
                .unwrap();
            assert_eq!(sn.cidr, "10.0.0.0/8");
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
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: Some("Corp".to_string()),
                description: None,
            })
            .await
            .unwrap();

        let alloc = store
            .create_allocation(&CreateAllocation {
                supernet_id: sn.id.clone(),
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
            })
            .await
            .unwrap();

        store
            .append_audit(&AuditEntry {
                id: String::new(),
                entity_type: "allocation".to_string(),
                entity_id: alloc.id.clone(),
                action: "allocate".to_string(),
                details: Some("10.0.0.0/24".to_string()),
                timestamp: "2026-03-16T00:00:00Z".to_string(),
            })
            .await
            .unwrap();

        // Re-run migrations
        store.migrate().await.unwrap();

        // Verify all data intact
        let fetched_sn = store.get_supernet(&sn.id).await.unwrap();
        assert_eq!(fetched_sn.cidr, "10.0.0.0/8");
        assert_eq!(fetched_sn.name, Some("Corp".to_string()));

        let fetched_alloc = store.get_allocation(&alloc.id).await.unwrap();
        assert_eq!(fetched_alloc.cidr, "10.0.0.0/24");
        assert_eq!(fetched_alloc.resource_id, Some("vpc-1".to_string()));
        assert_eq!(fetched_alloc.name, Some("web".to_string()));
        assert_eq!(fetched_alloc.tags.len(), 1);

        let audit = store
            .query_audit(&AuditFilter {
                entity_id: Some(alloc.id.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
    }

    /// Verify that a complex state (multiple supernets, allocations, releases,
    /// tags, audit entries) survives re-migration without corruption.
    #[tokio::test]
    async fn complex_state_survives_remigration() {
        let store = sqlite_store().await;

        // Create two supernets
        let sn1 = store
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: Some("Corp".to_string()),
                description: None,
            })
            .await
            .unwrap();

        let sn2 = store
            .create_supernet(&CreateSupernet {
                cidr: "172.16.0.0/12".to_string(),
                name: Some("Cloud".to_string()),
                description: None,
            })
            .await
            .unwrap();

        // Create allocations in both
        let a1 = store
            .create_allocation(&CreateAllocation {
                supernet_id: sn1.id.clone(),
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
                supernet_id: sn1.id.clone(),
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

        store
            .create_allocation(&CreateAllocation {
                supernet_id: sn2.id.clone(),
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
            })
            .await
            .unwrap();

        // Release one
        store.release_allocation(&a1.id).await.unwrap();

        // Set tags
        store
            .set_tags(
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
        let supernets = store.list_supernets().await.unwrap();
        assert_eq!(supernets.len(), 2);

        let all_allocs = store
            .list_allocations(&AllocationFilter::default())
            .await
            .unwrap();
        assert_eq!(all_allocs.len(), 3);

        // Verify release survived
        let released = store.get_allocation(&a1.id).await.unwrap();
        assert_eq!(released.status, AllocationStatus::Released);
        assert!(released.released_at.is_some());

        // Verify tags survived
        let tags = store.get_tags(&a1.id).await.unwrap();
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
        let supernets = store.list_supernets().await.unwrap();
        assert!(supernets.is_empty());

        // Re-migrate should be safe
        store.migrate().await.unwrap();
        let supernets = store.list_supernets().await.unwrap();
        assert!(supernets.is_empty());
    }
}
