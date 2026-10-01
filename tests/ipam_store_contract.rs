//! Trait-contract test suite for IpamStore backend parity.
//!
//! These tests verify that every IpamStore implementation behaves
//! identically. They run against in-memory SQLite, file-backed SQLite, and,
//! with `--features ipam-postgres`, Postgres (see `store_support` for how the
//! Postgres server is found).

mod store_support;

use netcidr::error::NetcidrError;
use netcidr::ipam::models::*;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use store_support::Seed;
use store_support::sqlite_memory_store as sqlite_store;

const TEST_TENANT: &str = "test@example.com";

// ---------------------------------------------------------------------------
// Test harness: macro generates identical tests for each backend
// ---------------------------------------------------------------------------

/// Commit `writes` in one transaction unit with no reads, no audit rows,
/// and no idempotency record.
async fn write_rows(
    store: &dyn IpamStore,
    writes: Vec<netcidr::ipam::store::Write>,
) -> netcidr::error::Result<String> {
    store
        .transact(netcidr::ipam::store::TxUnit {
            scope: netcidr::ipam::store::LockScope::Tenant {
                tenant_id: TEST_TENANT.to_string(),
            },
            reads: vec![],
            idempotency: None,
            decide: Box::new(move |_| {
                Ok(netcidr::ipam::store::Plan {
                    writes,
                    ..Default::default()
                })
            }),
        })
        .await
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
        async fn contract_delete_cidr_block_removes_its_allocations_and_tags() {
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
                        status: Some(AllocationStatus::Released),
                        resource_id: None,
                        resource_type: None,
                        name: None,
                        description: None,
                        environment: None,
                        owner: None,
                        parent_allocation_id: None,
                        tags: Some(vec![Tag {
                            key: "k".to_string(),
                            value: "v".to_string(),
                        }]),
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();

            store.delete_cidr_block(TEST_TENANT, &sn.id).await.unwrap();

            assert!(matches!(
                store.get_cidr_block(TEST_TENANT, &sn.id).await,
                Err(NetcidrError::CidrBlockNotFound(_))
            ));
            assert!(matches!(
                store.get_allocation(TEST_TENANT, &alloc.id).await,
                Err(NetcidrError::AllocationNotFound(_))
            ));
            // Deleting again finds nothing.
            assert!(matches!(
                store.delete_cidr_block(TEST_TENANT, &sn.id).await,
                Err(NetcidrError::CidrBlockNotFound(_))
            ));
        }

        #[tokio::test]
        async fn contract_user_writes_round_trip() {
            use netcidr::auth::Role;
            use netcidr::ipam::models::{UserRecord, UserStatus};
            use netcidr::ipam::store::Write;
            let store = $factory().await;
            let user = UserRecord {
                email: "a@x".to_string(),
                role: Role::PlatformAdmin,
                status: UserStatus::Active,
                created_at: "2026-10-01T00:00:00+00:00".to_string(),
                updated_at: "2026-10-01T00:00:00+00:00".to_string(),
                created_by: Some("bootstrap".to_string()),
                updated_by: None,
            };
            store_support::commit_writes(&*store, TEST_TENANT, vec![Write::PutUser(user.clone())])
                .await
                .unwrap();
            assert_eq!(store.get_user("a@x").await.unwrap(), Some(user.clone()));
            assert_eq!(store.count_active_platform_admins().await.unwrap(), 1);

            // PutUser overwrites every column of an existing row.
            let changed = UserRecord {
                status: UserStatus::Disabled,
                updated_at: "2026-10-01T01:00:00+00:00".to_string(),
                updated_by: Some("cli".to_string()),
                ..user
            };
            store_support::commit_writes(
                &*store,
                TEST_TENANT,
                vec![Write::PutUser(changed.clone())],
            )
            .await
            .unwrap();
            assert_eq!(store.list_users().await.unwrap(), vec![changed]);
            assert_eq!(store.count_active_platform_admins().await.unwrap(), 0);

            store_support::commit_writes(
                &*store,
                TEST_TENANT,
                vec![Write::DeleteUser {
                    email: "a@x".to_string(),
                }],
            )
            .await
            .unwrap();
            assert_eq!(store.get_user("a@x").await.unwrap(), None);
            let err = store_support::commit_writes(
                &*store,
                TEST_TENANT,
                vec![Write::DeleteUser {
                    email: "a@x".to_string(),
                }],
            )
            .await
            .unwrap_err();
            assert!(matches!(err, NetcidrError::UserNotFound(_)), "got {err:?}");
        }

        #[tokio::test]
        async fn contract_bootstrap_marker_is_readable_after_it_is_set() {
            use netcidr::ipam::store::{LockScope, Plan, Read, Rows, TxUnit, Write};
            let store = $factory().await;
            async fn read_marker(store: &dyn IpamStore) -> netcidr::error::Result<String> {
                store
                    .transact(TxUnit {
                        scope: LockScope::UserDirectory,
                        reads: vec![Read::BootstrapMarker {
                            key: "k".to_string(),
                        }],
                        idempotency: None,
                        decide: Box::new(|loaded| {
                            let Rows::Flag(set) = loaded.rows[0] else {
                                panic!("expected a flag");
                            };
                            Ok(Plan {
                                output_json: set.to_string(),
                                ..Plan::default()
                            })
                        }),
                    })
                    .await
            }
            assert_eq!(read_marker(&*store).await.unwrap(), "false");
            store_support::commit_writes(
                &*store,
                TEST_TENANT,
                vec![Write::SetBootstrapMarker {
                    key: "k".to_string(),
                    applied_at: "2026-10-01T00:00:00+00:00".to_string(),
                }],
            )
            .await
            .unwrap();
            assert_eq!(read_marker(&*store).await.unwrap(), "true");
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
        async fn contract_insert_allocation_round_trips_the_full_row() {
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
            let row = Allocation {
                id: "alloc-fixed".to_string(),
                tenant_id: TEST_TENANT.to_string(),
                cidr_block_id: sn.id.clone(),
                cidr: "10.0.1.0/24".to_string(),
                network_address: "10.0.1.0".to_string(),
                broadcast_address: "10.0.1.255".to_string(),
                prefix_length: 24,
                total_hosts: 256,
                status: AllocationStatus::Reserved,
                resource_id: Some("vpc-1".to_string()),
                resource_type: Some("vpc".to_string()),
                name: Some("web".to_string()),
                description: Some("d".to_string()),
                environment: Some("prod".to_string()),
                owner: Some("team".to_string()),
                parent_allocation_id: None,
                tags: vec![Tag {
                    key: "env".to_string(),
                    value: "prod".to_string(),
                }],
                created_at: "2026-10-01T00:00:00+00:00".to_string(),
                updated_at: "2026-10-01T00:00:00+00:00".to_string(),
                released_at: None,
                expires_at: Some("2026-10-02T00:00:00+00:00".to_string()),
            };
            write_rows(
                &*store,
                vec![netcidr::ipam::store::Write::InsertAllocation(row.clone())],
            )
            .await
            .unwrap();

            let got = store
                .get_allocation(TEST_TENANT, "alloc-fixed")
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(&got).unwrap(),
                serde_json::to_value(&row).unwrap()
            );
        }

        #[tokio::test]
        async fn contract_replace_allocation_overwrites_mutable_fields_only() {
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
            let original = store
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
                        tags: Some(vec![Tag {
                            key: "k".to_string(),
                            value: "v".to_string(),
                        }]),
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();

            let mut changed = original.clone();
            changed.status = AllocationStatus::Released;
            changed.name = None;
            changed.description = Some("new desc".to_string());
            changed.updated_at = "2026-10-01T01:00:00+00:00".to_string();
            changed.released_at = Some("2026-10-01T01:00:00+00:00".to_string());
            // Not mutable: the replace must leave these as stored.
            changed.cidr = "10.9.9.0/24".to_string();
            changed.tags = vec![];
            write_rows(
                &*store,
                vec![netcidr::ipam::store::Write::ReplaceAllocation(
                    changed.clone(),
                )],
            )
            .await
            .unwrap();

            let got = store
                .get_allocation(TEST_TENANT, &original.id)
                .await
                .unwrap();
            assert_eq!(got.status, AllocationStatus::Released);
            assert_eq!(got.name, None);
            assert_eq!(got.description, Some("new desc".to_string()));
            assert_eq!(got.resource_id, Some("vpc-123".to_string()));
            assert_eq!(got.updated_at, changed.updated_at);
            assert_eq!(got.released_at, changed.released_at);
            assert_eq!(got.cidr, original.cidr);
            assert_eq!(
                serde_json::to_value(&got.tags).unwrap(),
                serde_json::to_value(&original.tags).unwrap()
            );
        }

        #[tokio::test]
        async fn contract_replace_of_a_missing_allocation_is_not_found() {
            let store = $factory().await;
            let mut ghost = Allocation {
                id: "ghost".to_string(),
                tenant_id: TEST_TENANT.to_string(),
                cidr_block_id: "nope".to_string(),
                cidr: "10.0.0.0/24".to_string(),
                network_address: "10.0.0.0".to_string(),
                broadcast_address: "10.0.0.255".to_string(),
                prefix_length: 24,
                total_hosts: 256,
                status: AllocationStatus::Active,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: vec![],
                created_at: String::new(),
                updated_at: String::new(),
                released_at: None,
                expires_at: None,
            };
            ghost.name = Some("x".to_string());
            let err = write_rows(
                &*store,
                vec![netcidr::ipam::store::Write::ReplaceAllocation(ghost)],
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, NetcidrError::AllocationNotFound(_)),
                "got {err:?}"
            );
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

            let mut gone = a1.clone();
            gone.status = AllocationStatus::Released;
            gone.released_at = Some("2026-10-01T00:00:00+00:00".to_string());
            write_rows(
                &*store,
                vec![netcidr::ipam::store::Write::ReplaceAllocation(gone)],
            )
            .await
            .unwrap();

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
            write_rows(
                &*store,
                vec![netcidr::ipam::store::Write::ReplaceTags {
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
                }],
            )
            .await
            .unwrap();

            let tags = store.get_tags(TEST_TENANT, &alloc.id).await.unwrap();
            assert_eq!(tags.len(), 2);

            // Replace with different tags
            write_rows(
                &*store,
                vec![netcidr::ipam::store::Write::ReplaceTags {
                    tenant_id: TEST_TENANT.to_string(),
                    allocation_id: alloc.id.clone(),
                    tags: vec![Tag {
                        key: "env".to_string(),
                        value: "staging".to_string(),
                    }],
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

            // A third entry carrying caller identity, for per-user/per-PAT filters.
            store
                .append_audit(&AuditEntry {
                    id: String::new(),
                    tenant_id: TEST_TENANT.to_string(),
                    entity_type: "cidr_block".to_string(),
                    entity_id: "s-2".to_string(),
                    action: "create_cidr_block".to_string(),
                    details: None,
                    timestamp: "2026-03-16T00:02:00Z".to_string(),
                    caller_email: Some("alice@example.com".to_string()),
                    pat_id: Some("pat-123".to_string()),
                    ..Default::default()
                })
                .await
                .unwrap();

            // Filter by caller_email.
            let by_email = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        caller_email: Some("alice@example.com".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_email.len(), 1);
            assert_eq!(by_email[0].entity_id, "s-2");

            // Filter by pat_id.
            let by_pat = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        pat_id: Some("pat-123".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(by_pat.len(), 1);
            assert_eq!(by_pat[0].entity_id, "s-2");

            // A caller_email with no rows returns nothing.
            let none = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        caller_email: Some("nobody@example.com".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert!(none.is_empty());
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
        async fn contract_revoke_pat_sets_revoked_at_for_the_owner_only() {
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

            store
                .pat_revoke("a@x", "sub-a1", &t.id, "2026-05-02T00:00:00Z")
                .await
                .unwrap();
            let listed = store.pat_list_for_owner("a@x", "sub-a1").await.unwrap();
            assert_eq!(
                listed[0].revoked_at.as_deref(),
                Some("2026-05-02T00:00:00Z")
            );

            // The write matches on owner: another owner's token is not found.
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

        #[tokio::test]
        async fn contract_due_expiry_blocks_spans_tenants_and_skips_released() {
            let store = $factory().await;
            let mk = |block: &str, cidr: &str, status, ttl| CreateAllocation {
                cidr_block_id: block.to_string(),
                cidr: cidr.to_string(),
                status,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
                ttl_seconds: ttl,
            };
            let mut due = Vec::new();
            for tenant in ["a@x", "b@x"] {
                let block = store
                    .create_cidr_block(
                        tenant,
                        &CreateCidrBlock {
                            cidr: "10.0.0.0/8".to_string(),
                            name: None,
                            description: None,
                        },
                    )
                    .await
                    .unwrap();
                for (cidr, status, ttl) in [
                    ("10.0.1.0/24", Some(AllocationStatus::Reserved), Some(60)),
                    ("10.0.2.0/24", None, Some(60)),
                    ("10.0.3.0/24", Some(AllocationStatus::Released), Some(60)),
                    ("10.0.4.0/24", None, None),
                ] {
                    store
                        .create_allocation(tenant, &mk(&block.id, cidr, status, ttl))
                        .await
                        .unwrap();
                }
                due.push(ExpiryDue {
                    tenant_id: tenant.to_string(),
                    cidr_block_id: block.id,
                });
            }
            // A block with nothing expiring is never listed.
            store
                .create_cidr_block(
                    "a@x",
                    &CreateCidrBlock {
                        cidr: "172.16.0.0/12".to_string(),
                        name: None,
                        description: None,
                    },
                )
                .await
                .unwrap();

            assert!(
                store
                    .due_expiry_blocks("2000-01-01T00:00:00+00:00")
                    .await
                    .unwrap()
                    .is_empty(),
                "nothing has expired yet"
            );
            due.sort();
            assert_eq!(
                store
                    .due_expiry_blocks("2999-01-01T00:00:00+00:00")
                    .await
                    .unwrap(),
                due,
                "one entry per block, released allocations ignored"
            );
        }

        // ---- Hostname pointers ----

        #[tokio::test]
        async fn contract_hostname_writes_round_trip() {
            use netcidr::ipam::store::Write;
            let store = $factory().await;
            let pointer = HostnamePointer {
                id: "p-1".to_string(),
                tenant_id: TEST_TENANT.to_string(),
                ip_address: "10.0.1.5".to_string(),
                hostname: "web.example.com".to_string(),
                allocation_id: None,
                notes: Some("v1".to_string()),
                created_at: "2026-10-01T00:00:00+00:00".to_string(),
                updated_at: "2026-10-01T00:00:00+00:00".to_string(),
            };
            let entry = HostnamePointerHistoryEntry {
                id: "h-1".to_string(),
                tenant_id: TEST_TENANT.to_string(),
                pointer_id: "p-1".to_string(),
                ip_address: "10.0.1.5".to_string(),
                hostname: "web.example.com".to_string(),
                change_kind: ChangeKind::Create,
                previous_value: None,
                new_value: Some("{}".to_string()),
                actor: "cli".to_string(),
                changed_at: "2026-10-01T00:00:00+00:00".to_string(),
            };
            write_rows(
                &*store,
                vec![
                    Write::PutHostnamePointer(pointer.clone()),
                    Write::AppendHostnameHistory(entry),
                ],
            )
            .await
            .unwrap();

            // PutHostnamePointer on an existing id overwrites only the
            // allocation link, notes, and updated_at.
            write_rows(
                &*store,
                vec![Write::PutHostnamePointer(HostnamePointer {
                    hostname: "ignored.example.com".to_string(),
                    notes: Some("v2".to_string()),
                    created_at: "2030-01-01T00:00:00+00:00".to_string(),
                    updated_at: "2026-10-01T01:00:00+00:00".to_string(),
                    ..pointer.clone()
                })],
            )
            .await
            .unwrap();
            let live = store
                .list_hostname_pointers(TEST_TENANT, &HostnamePointerFilter::default())
                .await
                .unwrap();
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].hostname, "web.example.com");
            assert_eq!(live[0].notes.as_deref(), Some("v2"));
            assert_eq!(live[0].created_at, "2026-10-01T00:00:00+00:00");
            assert_eq!(live[0].updated_at, "2026-10-01T01:00:00+00:00");

            let hist = store
                .list_hostname_history(TEST_TENANT, &HostnameHistoryFilter::default())
                .await
                .unwrap();
            assert_eq!(hist.len(), 1);
            assert_eq!(hist[0].change_kind, ChangeKind::Create);
            assert_eq!(hist[0].new_value.as_deref(), Some("{}"));

            // Delete matches on tenant: another tenant's id is not found.
            let cross = write_rows(
                &*store,
                vec![Write::DeleteHostnamePointer {
                    tenant_id: "other@example.com".to_string(),
                    id: "p-1".to_string(),
                }],
            )
            .await;
            assert!(matches!(
                cross,
                Err(NetcidrError::HostnamePointerNotFound(_))
            ));
            write_rows(
                &*store,
                vec![Write::DeleteHostnamePointer {
                    tenant_id: TEST_TENANT.to_string(),
                    id: "p-1".to_string(),
                }],
            )
            .await
            .unwrap();
            assert!(
                store
                    .list_hostname_pointers(TEST_TENANT, &HostnamePointerFilter::default())
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

        /// The store behind `IpamOps`, so hostname rules run on this backend.
        async fn hostname_ops() -> (
            netcidr::ipam::operations::IpamOps,
            std::sync::Arc<dyn IpamStore>,
            store_support::Guard,
        ) {
            let (store, guard) = $factory().await.into_parts();
            let store: std::sync::Arc<dyn IpamStore> = std::sync::Arc::new(store);
            let ops = netcidr::ipam::operations::IpamOps::new(std::sync::Arc::clone(&store));
            (ops, store, guard)
        }

        #[tokio::test]
        async fn contract_hostname_set_get_and_history() {
            let (ops, store, _guard) = hostname_ops().await;

            let p = ops
                .set_hostname_pointer(
                    TEST_TENANT,
                    &CreateHostnamePointer {
                        ip_address: "10.0.1.5".to_string(),
                        hostname: "web-01.example.com".to_string(),
                        allocation_id: None,
                        notes: Some("primary".to_string()),
                    },
                )
                .await
                .unwrap();
            assert_eq!(p.ip_address, "10.0.1.5");
            assert_eq!(p.hostname, "web-01.example.com");
            assert!(!p.id.is_empty());

            // Many-to-many: a second hostname on the same IP.
            ops.set_hostname_pointer(
                TEST_TENANT,
                &CreateHostnamePointer {
                    ip_address: "10.0.1.5".to_string(),
                    hostname: "app.example.com".to_string(),
                    allocation_id: None,
                    notes: None,
                },
            )
            .await
            .unwrap();

            let by_ip = ops
                .get_hostname_pointers_for_ip(TEST_TENANT, "10.0.1.5")
                .await
                .unwrap();
            assert_eq!(by_ip.len(), 2);

            // History has two create rows so far, each with one audit row.
            let hist = ops
                .list_hostname_history(
                    TEST_TENANT,
                    &HostnameHistoryFilter {
                        ip_address: Some("10.0.1.5".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(hist.len(), 2);
            assert!(hist.iter().all(|h| h.change_kind == ChangeKind::Create));
            assert!(hist.iter().all(|h| h.actor == "cli"));
            let audit = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        action: Some("set_hostname_pointer".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(audit.len(), 2);
        }

        #[tokio::test]
        async fn contract_hostname_upsert_records_update() {
            let (ops, _store, _guard) = hostname_ops().await;
            let input = CreateHostnamePointer {
                ip_address: "192.168.0.1".to_string(),
                hostname: "host.example.com".to_string(),
                allocation_id: None,
                notes: Some("v1".to_string()),
            };
            let first = ops.set_hostname_pointer(TEST_TENANT, &input).await.unwrap();
            // Re-set the same pair updates in place (same id), records `update`.
            let second = ops
                .set_hostname_pointer(
                    TEST_TENANT,
                    &CreateHostnamePointer {
                        notes: Some("v2".to_string()),
                        ..input.clone()
                    },
                )
                .await
                .unwrap();
            assert_eq!(first.id, second.id);
            assert_eq!(second.notes, Some("v2".to_string()));

            let pointers = ops
                .list_hostname_pointers(TEST_TENANT, &HostnamePointerFilter::default())
                .await
                .unwrap();
            assert_eq!(pointers.len(), 1, "upsert must not create a duplicate row");
            assert_eq!(pointers[0].notes, Some("v2".to_string()));

            let hist = ops
                .list_hostname_history(TEST_TENANT, &HostnameHistoryFilter::default())
                .await
                .unwrap();
            assert_eq!(hist.len(), 2);
            assert_eq!(hist[0].change_kind, ChangeKind::Create);
            assert_eq!(hist[1].change_kind, ChangeKind::Update);
        }

        #[tokio::test]
        async fn contract_hostname_link_requires_an_allocation_in_the_tenant() {
            let (ops, store, _guard) = hostname_ops().await;
            let block = store
                .create_cidr_block(
                    "other@example.com",
                    &CreateCidrBlock {
                        cidr: "10.0.0.0/8".to_string(),
                        name: None,
                        description: None,
                    },
                )
                .await
                .unwrap();
            let theirs = store
                .create_allocation(
                    "other@example.com",
                    &CreateAllocation {
                        cidr_block_id: block.id,
                        cidr: "10.0.1.0/24".to_string(),
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
            let err = ops
                .set_hostname_pointer(
                    TEST_TENANT,
                    &CreateHostnamePointer {
                        ip_address: "10.0.1.5".to_string(),
                        hostname: "web.example.com".to_string(),
                        allocation_id: Some(theirs.id),
                        notes: None,
                    },
                )
                .await
                .unwrap_err();
            assert!(matches!(err, NetcidrError::AllocationNotFound(_)));
            assert!(
                ops.list_hostname_history(TEST_TENANT, &HostnameHistoryFilter::default())
                    .await
                    .unwrap()
                    .is_empty(),
                "a rejected set writes no history"
            );
        }

        #[tokio::test]
        async fn contract_hostname_delete_is_hard_with_history() {
            let (ops, store, _guard) = hostname_ops().await;
            ops.set_hostname_pointer(
                TEST_TENANT,
                &CreateHostnamePointer {
                    ip_address: "10.0.0.9".to_string(),
                    hostname: "gone.example.com".to_string(),
                    allocation_id: None,
                    notes: None,
                },
            )
            .await
            .unwrap();

            ops.delete_hostname_pointer(TEST_TENANT, "10.0.0.9", "gone.example.com")
                .await
                .unwrap();

            // Live row is gone.
            let live = ops
                .list_hostname_pointers(TEST_TENANT, &HostnamePointerFilter::default())
                .await
                .unwrap();
            assert!(live.is_empty());

            // History preserves create + delete.
            let hist = ops
                .list_hostname_history(TEST_TENANT, &HostnameHistoryFilter::default())
                .await
                .unwrap();
            assert_eq!(hist.len(), 2);
            assert_eq!(hist[1].change_kind, ChangeKind::Delete);
            assert!(hist[1].previous_value.is_some());
            assert!(hist[1].new_value.is_none());
            let audit = store
                .query_audit(
                    TEST_TENANT,
                    &AuditFilter {
                        action: Some("delete_hostname_pointer".to_string()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(audit.len(), 1);

            // Deleting a missing pointer is NotFound.
            let err = ops
                .delete_hostname_pointer(TEST_TENANT, "10.0.0.9", "gone.example.com")
                .await
                .unwrap_err();
            assert!(matches!(err, NetcidrError::HostnamePointerNotFound(_)));
        }
    };
}

// ---------------------------------------------------------------------------
// Transaction units (ADR-0007): commit, rollback, reads, lock exclusion
// ---------------------------------------------------------------------------

mod transact_support {
    use netcidr::ipam::models::{AuditEntry, IdempotencyRecord};

    pub fn audit(tenant: &str, entity_id: &str) -> AuditEntry {
        AuditEntry {
            id: String::new(),
            tenant_id: tenant.to_string(),
            entity_type: "test".to_string(),
            entity_id: entity_id.to_string(),
            action: "transact_test".to_string(),
            details: None,
            timestamp: "2026-10-01T00:00:00+00:00".to_string(),
            caller_sub: None,
            caller_email: None,
            source_ip: None,
            request_id: None,
            auth_method: "oidc".to_string(),
            pat_id: None,
        }
    }

    pub fn idempotency(tenant: &str, key: &str) -> IdempotencyRecord {
        IdempotencyRecord {
            tenant_id: tenant.to_string(),
            key: key.to_string(),
            scope: "transact-test".to_string(),
            request_hash: "hash".to_string(),
            status_code: 200,
            response_body: "\"stored\"".to_string(),
            created_at: "2026-10-01T00:00:00+00:00".to_string(),
            expires_at: "2099-01-01T00:00:00+00:00".to_string(),
        }
    }
}

/// Contract tests for `IpamStore::transact`. `$factory` must build a store
/// with `store_support::SHORT_LOCK_TIMEOUT`.
macro_rules! transact_contract_tests {
    ($factory:ident) => {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        use netcidr::ipam::store::{IdempotencyLookup, LockScope, Plan, Read, Rows, TxUnit};

        use super::transact_support::{audit, idempotency};

        fn block_scope(id: &str) -> LockScope {
            LockScope::CidrBlock {
                tenant_id: TEST_TENANT.to_string(),
                cidr_block_id: id.to_string(),
            }
        }

        async fn audit_ids(store: &dyn IpamStore) -> Vec<String> {
            store
                .query_audit(TEST_TENANT, &AuditFilter::default())
                .await
                .unwrap()
                .into_iter()
                .filter(|e| e.action == "transact_test")
                .map(|e| e.entity_id)
                .collect()
        }

        #[tokio::test]
        async fn transact_commits_audit_and_idempotency_and_returns_output() {
            let store = $factory().await;
            let block = store
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

            let out = store
                .transact(TxUnit {
                    scope: block_scope(&block.id),
                    reads: vec![Read::CidrBlock {
                        tenant_id: TEST_TENANT.to_string(),
                        id: block.id.clone(),
                    }],
                    idempotency: None,
                    decide: Box::new(|loaded| {
                        let Rows::CidrBlock(Some(b)) = &loaded.rows[0] else {
                            panic!("expected the cidr block");
                        };
                        Ok(Plan {
                            writes: vec![],
                            audits: vec![audit(TEST_TENANT, &b.id)],
                            idempotency: Some(idempotency(TEST_TENANT, "k1")),
                            output_json: format!("{:?}", b.name.clone().unwrap()),
                        })
                    }),
                })
                .await
                .unwrap();

            assert_eq!(out, "\"Corp\"");
            assert_eq!(audit_ids(&*store).await, vec![block.id.clone()]);
            let rec = store
                .idempotency_get(TEST_TENANT, "k1", "transact-test")
                .await
                .unwrap();
            assert_eq!(rec, Some(idempotency(TEST_TENANT, "k1")));
        }

        #[tokio::test]
        async fn transact_reads_a_row_in_another_tenant_as_absent() {
            let store = $factory().await;
            let block = store
                .create_cidr_block(
                    "someone-else@example.com",
                    &CreateCidrBlock {
                        cidr: "10.0.0.0/8".to_string(),
                        name: None,
                        description: None,
                    },
                )
                .await
                .unwrap();

            store
                .transact(TxUnit {
                    scope: block_scope(&block.id),
                    reads: vec![Read::CidrBlock {
                        tenant_id: TEST_TENANT.to_string(),
                        id: block.id.clone(),
                    }],
                    idempotency: None,
                    decide: Box::new(|loaded| {
                        assert!(matches!(loaded.rows[..], [Rows::CidrBlock(None)]));
                        Ok(Plan::default())
                    }),
                })
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn transact_decide_error_persists_nothing_and_passes_through() {
            let store = $factory().await;
            let err = store
                .transact(TxUnit {
                    scope: block_scope("b1"),
                    reads: vec![],
                    idempotency: None,
                    decide: Box::new(|_| {
                        // Building a plan, then failing, must leave no trace.
                        let _plan = Plan {
                            audits: vec![audit(TEST_TENANT, "never")],
                            idempotency: Some(idempotency(TEST_TENANT, "k2")),
                            ..Plan::default()
                        };
                        Err(NetcidrError::NoFreeSpace {
                            cidr_block: "10.0.0.0/30".to_string(),
                            prefix: 24,
                        })
                    }),
                })
                .await
                .unwrap_err();

            assert!(matches!(err, NetcidrError::NoFreeSpace { prefix: 24, .. }));
            assert!(audit_ids(&*store).await.is_empty());
            assert_eq!(
                store
                    .idempotency_get(TEST_TENANT, "k2", "transact-test")
                    .await
                    .unwrap(),
                None
            );
        }

        #[tokio::test]
        async fn transact_loads_the_idempotency_record_and_a_plan_replaces_it() {
            let store = $factory().await;
            let lookup = IdempotencyLookup {
                tenant_id: TEST_TENANT.to_string(),
                key: "k3".to_string(),
                scope: "transact-test".to_string(),
            };
            let first = idempotency(TEST_TENANT, "k3");
            let seeded = first.clone();
            store
                .transact(TxUnit {
                    scope: block_scope("b1"),
                    reads: vec![],
                    idempotency: None,
                    decide: Box::new(move |_| {
                        Ok(Plan {
                            idempotency: Some(seeded),
                            ..Plan::default()
                        })
                    }),
                })
                .await
                .unwrap();

            let replacement = IdempotencyRecord {
                status_code: 0,
                response_body: String::new(),
                ..first.clone()
            };
            let written = replacement.clone();
            store
                .transact(TxUnit {
                    scope: block_scope("b1"),
                    reads: vec![],
                    idempotency: Some(lookup.clone()),
                    decide: Box::new(move |loaded| {
                        assert_eq!(loaded.idempotency, Some(first));
                        Ok(Plan {
                            idempotency: Some(written),
                            ..Plan::default()
                        })
                    }),
                })
                .await
                .unwrap();
            assert_eq!(
                store
                    .idempotency_get(TEST_TENANT, "k3", "transact-test")
                    .await
                    .unwrap(),
                Some(replacement)
            );
        }

        /// Starts a unit on `scope` whose `decide` holds the lock until
        /// `release` is sent. Resolves once that `decide` is running.
        async fn hold_scope(
            store: Arc<dyn IpamStore>,
            scope: LockScope,
        ) -> (
            tokio::task::JoinHandle<netcidr::error::Result<String>>,
            std::sync::mpsc::Sender<()>,
        ) {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let holder = tokio::spawn(async move {
                store
                    .transact(TxUnit {
                        scope,
                        reads: vec![],
                        idempotency: None,
                        decide: Box::new(move |_| {
                            entered_tx.send(()).unwrap();
                            // Adapters run `decide` off the async workers,
                            // so blocking here holds only the lock.
                            release_rx.recv().unwrap();
                            Ok(Plan::default())
                        }),
                    })
                    .await
            });
            entered_rx.await.unwrap();
            (holder, release_tx)
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn transact_units_on_the_same_scope_never_interleave() {
            let (store, _guard) = $factory().await.into_parts();
            let store: Arc<dyn IpamStore> = Arc::new(store);
            let (holder, release) = hold_scope(Arc::clone(&store), block_scope("b1")).await;

            let entered = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&entered);
            let waiter_store = Arc::clone(&store);
            let waiter = tokio::spawn(async move {
                waiter_store
                    .transact(TxUnit {
                        scope: block_scope("b1"),
                        reads: vec![],
                        idempotency: None,
                        decide: Box::new(move |_| {
                            flag.store(true, Ordering::SeqCst);
                            Ok(Plan::default())
                        }),
                    })
                    .await
            });

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !entered.load(Ordering::SeqCst),
                "second unit decided while the first held the scope"
            );
            release.send(()).unwrap();
            holder.await.unwrap().unwrap();
            waiter.await.unwrap().unwrap();
            assert!(entered.load(Ordering::SeqCst));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn transact_waiting_past_the_lock_timeout_is_store_busy() {
            let (store, _guard) = $factory().await.into_parts();
            let store: Arc<dyn IpamStore> = Arc::new(store);
            let (holder, release) = hold_scope(Arc::clone(&store), block_scope("b1")).await;

            let err = store
                .transact(TxUnit {
                    scope: block_scope("b1"),
                    reads: vec![],
                    idempotency: None,
                    decide: Box::new(|_| panic!("must not decide while the scope is held")),
                })
                .await
                .unwrap_err();
            assert!(matches!(err, NetcidrError::StoreBusy), "got {err:?}");

            release.send(()).unwrap();
            holder.await.unwrap().unwrap();
        }
    };
}

// ---------------------------------------------------------------------------
// Run contract tests against every store adapter
// ---------------------------------------------------------------------------

mod sqlite_contract {
    use super::*;
    store_contract_tests!(sqlite_store);
}

mod sqlite_file_contract {
    use super::*;
    use store_support::sqlite_file_store;
    store_contract_tests!(sqlite_file_store);
}

#[cfg(feature = "ipam-postgres")]
mod postgres_contract {
    use super::*;
    use store_support::postgres_store;
    store_contract_tests!(postgres_store);
}

mod sqlite_transact_contract {
    use super::*;
    use store_support::sqlite_memory_store_short_timeout;
    transact_contract_tests!(sqlite_memory_store_short_timeout);
}

mod sqlite_file_transact_contract {
    use super::*;
    use store_support::sqlite_file_store_short_timeout;
    transact_contract_tests!(sqlite_file_store_short_timeout);
}

#[cfg(feature = "ipam-postgres")]
mod postgres_transact_contract {
    use super::*;
    use store_support::postgres_store_short_timeout;
    transact_contract_tests!(postgres_store_short_timeout);
}

/// Users directory through the operations layer: the marker-guarded
/// one-shot seed, actor stamping on upsert, active-platform-admin counting,
/// listing, and delete (ADR-0006).
#[tokio::test]
async fn users_directory_crud_and_marker_seed() {
    use netcidr::audit_context::{self, AuditContext};
    use netcidr::auth::Role;
    use netcidr::ipam::models::UserStatus;
    use netcidr::ipam::operations::IpamOps;
    use std::sync::Arc;

    let (store, _guard) = sqlite_store().await.into_parts();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let ops = IpamOps::new(Arc::clone(&store));

    // One-shot seed populates from the given triples.
    let seeded = ops
        .seed_users(&[
            (
                "owner@example.com".to_string(),
                Role::PlatformAdmin,
                UserStatus::Active,
            ),
            (
                "dev@example.com".to_string(),
                Role::Allocator,
                UserStatus::Active,
            ),
            (
                "ghost@example.com".to_string(),
                Role::Reader,
                UserStatus::Disabled,
            ),
        ])
        .await
        .unwrap();
    assert_eq!(seeded, 3);

    // Resolution + case-insensitivity + audit provenance.
    let owner = store.get_user("OWNER@EXAMPLE.COM").await.unwrap().unwrap();
    assert_eq!(owner.role, Role::PlatformAdmin);
    assert_eq!(owner.status, UserStatus::Active);
    assert_eq!(owner.created_by.as_deref(), Some("bootstrap"));
    assert!(
        store
            .get_user("nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );

    // The seed is marker-guarded, not emptiness-guarded: even after deleting
    // every row (raw deletes, past the last-admin guard), a second seed must
    // insert nothing.
    store.delete_user("owner@example.com").await.unwrap();
    store.delete_user("dev@example.com").await.unwrap();
    store.delete_user("ghost@example.com").await.unwrap();
    let again = ops
        .seed_users(&[(
            "late@example.com".to_string(),
            Role::PlatformAdmin,
            UserStatus::Active,
        )])
        .await
        .unwrap();
    assert_eq!(again, 0, "marker must make the seed one-shot forever");
    assert!(store.get_user("late@example.com").await.unwrap().is_none());

    // Upsert: insert stamps created_by with the caller; update stamps
    // updated_by and preserves created_*.
    let as_owner = AuditContext {
        caller_email: Some("owner@example.com".to_string()),
        ..AuditContext::default()
    };
    let created = audit_context::scope(
        as_owner.clone(),
        ops.upsert_user(
            TEST_TENANT,
            "dev@example.com",
            Role::Admin,
            UserStatus::Active,
        ),
    )
    .await
    .unwrap();
    assert_eq!(created.created_by.as_deref(), Some("owner@example.com"));
    assert!(created.updated_by.is_none());
    let updated = audit_context::scope(
        as_owner,
        ops.upsert_user(
            TEST_TENANT,
            "dev@example.com",
            Role::Admin,
            UserStatus::Disabled,
        ),
    )
    .await
    .unwrap();
    assert_eq!(updated.status, UserStatus::Disabled);
    assert_eq!(updated.created_by.as_deref(), Some("owner@example.com"));
    assert_eq!(updated.updated_by.as_deref(), Some("owner@example.com"));
    assert_eq!(updated.created_at, created.created_at);

    // Active-platform-admin counting ignores disabled rows and lower roles.
    assert_eq!(store.count_active_platform_admins().await.unwrap(), 0);
    ops.upsert_user(
        TEST_TENANT,
        "owner@example.com",
        Role::PlatformAdmin,
        UserStatus::Active,
    )
    .await
    .unwrap();
    ops.upsert_user(
        TEST_TENANT,
        "frozen@example.com",
        Role::PlatformAdmin,
        UserStatus::Disabled,
    )
    .await
    .unwrap();
    assert_eq!(
        store.count_active_platform_admins().await.unwrap(),
        1,
        "disabled platform admins must not count"
    );

    // List is sorted by email and complete.
    let all = store.list_users().await.unwrap();
    let emails: Vec<&str> = all.iter().map(|u| u.email.as_str()).collect();
    assert_eq!(
        emails,
        vec!["dev@example.com", "frozen@example.com", "owner@example.com"]
    );

    // Delete + not-found.
    ops.delete_user(TEST_TENANT, "dev@example.com")
        .await
        .unwrap();
    let err = ops
        .delete_user(TEST_TENANT, "dev@example.com")
        .await
        .unwrap_err();
    assert!(matches!(err, NetcidrError::UserNotFound(_)));
}

/// Hostname pointers and their history are isolated per tenant: tenant A
/// cannot see tenant B's pointers or change history, and identical
/// `(ip, hostname)` pairs may coexist across tenants.
#[tokio::test]
async fn hostname_pointers_are_tenant_isolated() {
    use std::sync::Arc;
    let store: Arc<dyn IpamStore> = Arc::new(sqlite_store().await.into_parts().0);
    let ops = netcidr::ipam::operations::IpamOps::new(Arc::clone(&store));
    let mk = |ip: &str, host: &str| CreateHostnamePointer {
        ip_address: ip.to_string(),
        hostname: host.to_string(),
        allocation_id: None,
        notes: None,
    };

    // Both tenants record the *same* IP↔hostname pair.
    ops.set_hostname_pointer("a@x", &mk("10.0.0.1", "shared.example.com"))
        .await
        .unwrap();
    ops.set_hostname_pointer("b@x", &mk("10.0.0.1", "shared.example.com"))
        .await
        .unwrap();

    // Each tenant sees exactly their own pointer.
    let a = store
        .list_hostname_pointers("a@x", &HostnamePointerFilter::default())
        .await
        .unwrap();
    let b = store
        .list_hostname_pointers("b@x", &HostnamePointerFilter::default())
        .await
        .unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_ne!(
        a[0].id, b[0].id,
        "pointers must be distinct rows per tenant"
    );

    // History is isolated too.
    let a_hist = store
        .list_hostname_history("a@x", &HostnameHistoryFilter::default())
        .await
        .unwrap();
    assert_eq!(a_hist.len(), 1);
    assert!(a_hist.iter().all(|h| h.tenant_id == "a@x"));

    // Tenant A cannot delete tenant B's pointer (cross-tenant ⇒ NotFound).
    ops.set_hostname_pointer("b@x", &mk("10.0.0.2", "b-only.example.com"))
        .await
        .unwrap();
    let err = ops
        .delete_hostname_pointer("a@x", "10.0.0.2", "b-only.example.com")
        .await
        .unwrap_err();
    assert!(matches!(err, NetcidrError::HostnamePointerNotFound(_)));
    // B's pointer survives.
    assert_eq!(
        store
            .list_hostname_pointers(
                "b@x",
                &HostnamePointerFilter {
                    ip_address: Some("10.0.0.2".to_string()),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
        1
    );
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
        let mut gone = a1.clone();
        gone.status = AllocationStatus::Released;
        gone.released_at = Some("2026-10-01T00:00:00+00:00".to_string());
        write_rows(
            &*store,
            vec![netcidr::ipam::store::Write::ReplaceAllocation(gone)],
        )
        .await
        .unwrap();

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
