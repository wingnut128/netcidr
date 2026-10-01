//! Concurrency tests for IPAM invariants.
//!
//! Each allocation write runs as one transaction under its cidr block's
//! Lock Scope (ADR-0007), so concurrent requests for an overlapping CIDR
//! cannot both succeed. These tests prove the invariant, first within one
//! process and then across processes sharing a database.

use std::sync::Arc;

use netcidr::error::NetcidrError;
use netcidr::ipam::models::*;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;

const TEST_TENANT: &str = "test@example.com";

async fn ops_with_cidr_block(cidr: &str) -> (Arc<IpamOps>, String) {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let ops = Arc::new(IpamOps::new(Arc::new(store)));
    let sn = ops
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
    (ops, sn.id)
}

/// 8 tasks race to allocate the *same* CIDR. Exactly one must succeed; the
/// other 7 must fail with `AllocationConflict`. Without the cidr block's
/// Lock Scope the check-then-insert window lets duplicates slip through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_allocate_specific_same_cidr_yields_exactly_one_winner() {
    let (ops, sn_id) = ops_with_cidr_block("10.0.0.0/8").await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let ops = Arc::clone(&ops);
        let sn_id = sn_id.clone();
        handles.push(tokio::spawn(async move {
            ops.allocate_specific(
                TEST_TENANT,
                &CreateAllocation {
                    cidr_block_id: sn_id,
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
        }));
    }

    let mut wins = 0;
    let mut conflicts = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => wins += 1,
            Err(NetcidrError::AllocationConflict { .. }) => conflicts += 1,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert_eq!(wins, 1, "exactly one task must win");
    assert_eq!(conflicts, 7, "the other seven must see AllocationConflict");
}

/// 16 tasks race to auto-allocate /24 blocks from a small /22 cidr_block
/// (4 blocks total). All 4 winners must hold *non-overlapping* CIDRs and
/// the remaining 12 tasks must see `NoFreeSpace`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_auto_allocate_produces_no_overlaps() {
    let (ops, sn_id) = ops_with_cidr_block("10.0.0.0/22").await;

    let mut handles = Vec::new();
    for _ in 0..16 {
        let ops = Arc::clone(&ops);
        let sn_id = sn_id.clone();
        handles.push(tokio::spawn(async move {
            ops.allocate_auto(
                TEST_TENANT,
                &AutoAllocateRequest {
                    cidr_block_id: sn_id,
                    prefix_length: 24,
                    count: Some(1),
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
        }));
    }

    let mut allocations: Vec<Allocation> = Vec::new();
    let mut no_free_space = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(mut allocs) => allocations.append(&mut allocs),
            Err(NetcidrError::NoFreeSpace { .. }) => no_free_space += 1,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert_eq!(allocations.len(), 4, "/22 fits exactly four /24s");
    assert_eq!(no_free_space, 12);

    // Pairwise non-overlap check by network prefix uniqueness — every
    // /24 block must have a distinct first octet pair.
    let mut cidrs: Vec<String> = allocations.iter().map(|a| a.cidr.clone()).collect();
    cidrs.sort();
    cidrs.dedup();
    assert_eq!(cidrs.len(), 4, "all four /24 CIDRs must be distinct");
}

// ---------------------------------------------------------------------------
// Cross-process races: two independent `IpamOps` over two stores that share
// one database — the shape of two Lambda execution environments or two
// `netcidr serve` processes. Only a lock held inside the database
// transaction can protect an invariant here (#479). Each test repeats its
// race for several rounds to make the interleaving likely rather than lucky.
// ---------------------------------------------------------------------------

mod store_support;

mod cross_process {
    use std::collections::HashSet;
    use std::sync::Arc;

    use netcidr::auth::Role;
    use netcidr::error::NetcidrError;
    use netcidr::ipam::models::*;
    use netcidr::ipam::operations::IpamOps;
    use netcidr::ipam::store::IpamStore;
    use netcidr::pat::PatPepper;
    use netcidr::pat_lifecycle::{CreatePatRequest, PatLifecycle, PatOwner};

    use super::TEST_TENANT;
    use super::store_support::Guard;

    const ROUNDS: usize = 20;

    /// Two "processes" sharing one database.
    pub struct Pair {
        pub stores: [Arc<dyn IpamStore>; 2],
        pub ops: [Arc<IpamOps>; 2],
        _guard: Guard,
    }

    impl Pair {
        pub fn new(a: Arc<dyn IpamStore>, b: Arc<dyn IpamStore>, guard: Guard) -> Self {
            let ops = [
                Arc::new(IpamOps::new(Arc::clone(&a))),
                Arc::new(IpamOps::new(Arc::clone(&b))),
            ];
            Self {
                stores: [a, b],
                ops,
                _guard: guard,
            }
        }
    }

    fn alloc_request(block_id: &str, cidr: &str) -> CreateAllocation {
        CreateAllocation {
            cidr_block_id: block_id.to_string(),
            cidr: cidr.to_string(),
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
        }
    }

    fn auto_request(block_id: &str) -> AutoAllocateRequest {
        AutoAllocateRequest {
            cidr_block_id: block_id.to_string(),
            prefix_length: 24,
            count: Some(1),
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
        }
    }

    async fn block(ops: &IpamOps, cidr: &str) -> String {
        ops.create_cidr_block(
            TEST_TENANT,
            &CreateCidrBlock {
                cidr: cidr.to_string(),
                name: None,
                description: None,
            },
        )
        .await
        .unwrap()
        .id
    }

    /// Per round, 8 tasks split across both processes request the same /24.
    /// Exactly one may win.
    pub async fn allocate_specific_has_one_winner(pair: Pair) {
        let block_id = block(&pair.ops[0], "10.0.0.0/8").await;
        for round in 0..ROUNDS {
            let cidr = format!("10.{round}.0.0/24");
            let mut handles = Vec::new();
            for task in 0..8 {
                let ops = Arc::clone(&pair.ops[task % 2]);
                let req = alloc_request(&block_id, &cidr);
                handles.push(tokio::spawn(async move {
                    ops.allocate_specific(TEST_TENANT, &req).await
                }));
            }
            let mut wins = 0;
            for h in handles {
                match h.await.unwrap() {
                    Ok(_) => wins += 1,
                    Err(NetcidrError::AllocationConflict { .. }) => {}
                    Err(e) => panic!("round {round}: unexpected error: {e:?}"),
                }
            }
            assert_eq!(wins, 1, "round {round}: {cidr} allocated {wins} times");
        }
    }

    /// Per round, 16 tasks split across both processes auto-allocate /24s
    /// from a fresh /22 (room for four). The winners must be four distinct
    /// CIDRs.
    pub async fn allocate_auto_never_overlaps(pair: Pair) {
        for round in 0..ROUNDS {
            let block_id = block(&pair.ops[0], &format!("10.{}.0.0/22", round * 4)).await;
            let mut handles = Vec::new();
            for task in 0..16 {
                let ops = Arc::clone(&pair.ops[task % 2]);
                let req = auto_request(&block_id);
                handles.push(tokio::spawn(async move {
                    ops.allocate_auto(TEST_TENANT, &req).await
                }));
            }
            let mut cidrs = Vec::new();
            for h in handles {
                match h.await.unwrap() {
                    Ok(allocs) => cidrs.extend(allocs.into_iter().map(|a| a.cidr)),
                    Err(NetcidrError::NoFreeSpace { .. }) => {}
                    Err(e) => panic!("round {round}: unexpected error: {e:?}"),
                }
            }
            let distinct: HashSet<_> = cidrs.iter().collect();
            assert_eq!(
                cidrs.len(),
                distinct.len(),
                "round {round}: duplicate allocations {cidrs:?}"
            );
            assert_eq!(cidrs.len(), 4, "round {round}: /22 fits four /24s");
        }
    }

    /// Per round there are exactly two active platform admins; each process
    /// deletes a different one at the same time. At most one delete may
    /// succeed, so a platform admin always remains.
    pub async fn last_platform_admin_survives(pair: Pair) {
        let ops = &pair.ops;
        let mut survivor = "admin-0@example.com".to_string();
        ops[0]
            .upsert_user(
                TEST_TENANT,
                &survivor,
                Role::PlatformAdmin,
                UserStatus::Active,
            )
            .await
            .unwrap();
        for round in 1..=ROUNDS {
            let newcomer = format!("admin-{round}@example.com");
            ops[0]
                .upsert_user(
                    TEST_TENANT,
                    &newcomer,
                    Role::PlatformAdmin,
                    UserStatus::Active,
                )
                .await
                .unwrap();
            let (a, b) = (Arc::clone(&ops[0]), Arc::clone(&ops[1]));
            let (old, new) = (survivor.clone(), newcomer.clone());
            let ha = tokio::spawn(async move { a.delete_user(TEST_TENANT, &old).await });
            let hb = tokio::spawn(async move { b.delete_user(TEST_TENANT, &new).await });
            let (ra, rb) = (ha.await.unwrap(), hb.await.unwrap());
            for r in [&ra, &rb] {
                if let Err(e) = r
                    && !matches!(e, NetcidrError::LastPlatformAdmin)
                {
                    panic!("round {round}: unexpected error: {e:?}");
                }
            }
            let remaining = pair.stores[0].count_active_platform_admins().await.unwrap();
            assert_eq!(
                remaining, 1,
                "round {round}: {remaining} active platform admins remain"
            );
            survivor = if ra.is_ok() { newcomer } else { survivor };
        }
    }

    /// Both processes run the one-shot users seed at the same moment, as two
    /// cold starts would. It must apply exactly once, and neither may fail.
    pub async fn concurrent_seeds_apply_once(pair: Pair) {
        let seeds: Vec<(String, Role, UserStatus)> = (0..10)
            .map(|i| {
                (
                    format!("user-{i}@example.com"),
                    Role::Reader,
                    UserStatus::Active,
                )
            })
            .collect();
        let (a, b) = (Arc::clone(&pair.ops[0]), Arc::clone(&pair.ops[1]));
        let (sa, sb) = (seeds.clone(), seeds.clone());
        let ha = tokio::spawn(async move { a.seed_users(&sa).await });
        let hb = tokio::spawn(async move { b.seed_users(&sb).await });
        let (ra, rb) = (ha.await.unwrap().unwrap(), hb.await.unwrap().unwrap());
        assert_eq!(ra + rb, 10, "seeded {ra} + {rb} users; expected 10 once");
        assert_eq!(pair.stores[0].list_users().await.unwrap().len(), 10);
    }

    /// Per round, 8 mints for one PAT Owner split across both processes,
    /// with a per-owner limit of 2. At most 2 may be active afterwards.
    pub async fn pat_limit_holds(pair: Pair) {
        const LIMIT: u32 = 2;
        let pepper = Arc::new(PatPepper::from_bytes(&[0xA5u8; 32]).unwrap());
        let lifecycles = [
            Arc::new(PatLifecycle::new(
                Arc::clone(&pair.stores[0]),
                Arc::clone(&pepper),
                LIMIT,
            )),
            Arc::new(PatLifecycle::new(
                Arc::clone(&pair.stores[1]),
                Arc::clone(&pepper),
                LIMIT,
            )),
        ];
        for round in 0..ROUNDS {
            let owner = PatOwner {
                tenant_id: TEST_TENANT.to_string(),
                subject: format!("sub-{round}"),
                email: TEST_TENANT.to_string(),
            };
            let mut handles = Vec::new();
            for task in 0..8 {
                let lc = Arc::clone(&lifecycles[task % 2]);
                let owner = owner.clone();
                handles.push(tokio::spawn(async move {
                    lc.mint_for_owner(
                        &owner,
                        Role::Admin,
                        CreatePatRequest {
                            name: format!("tok-{task}"),
                            expires_in_days: Some(30),
                            role: None,
                        },
                    )
                    .await
                }));
            }
            for h in handles {
                match h.await.unwrap() {
                    Ok(_) | Err(NetcidrError::PatLimitExceeded { .. }) => {}
                    Err(e) => panic!("round {round}: unexpected error: {e:?}"),
                }
            }
            let now = chrono::Utc::now().to_rfc3339();
            let active = pair.stores[0]
                .pat_count_active_for_owner(TEST_TENANT, &owner.subject, &now)
                .await
                .unwrap();
            assert!(
                active <= LIMIT,
                "round {round}: {active} active PATs exceed the limit of {LIMIT}"
            );
        }
    }

    /// Per round, each process creates a different but overlapping cidr
    /// block at the same time. Exactly one may succeed.
    pub async fn overlapping_blocks_have_one_winner(pair: Pair) {
        for round in 0..ROUNDS {
            let (a, b) = (Arc::clone(&pair.ops[0]), Arc::clone(&pair.ops[1]));
            let wide = format!("10.{round}.0.0/16");
            let narrow = format!("10.{round}.1.0/24");
            let ha = tokio::spawn(async move {
                a.create_cidr_block(
                    TEST_TENANT,
                    &CreateCidrBlock {
                        cidr: wide,
                        name: None,
                        description: None,
                    },
                )
                .await
            });
            let hb = tokio::spawn(async move {
                b.create_cidr_block(
                    TEST_TENANT,
                    &CreateCidrBlock {
                        cidr: narrow,
                        name: None,
                        description: None,
                    },
                )
                .await
            });
            let mut wins = 0;
            for r in [ha.await.unwrap(), hb.await.unwrap()] {
                match r {
                    Ok(_) => wins += 1,
                    Err(NetcidrError::AllocationConflict { .. }) => {}
                    Err(e) => panic!("round {round}: unexpected error: {e:?}"),
                }
            }
            assert_eq!(wins, 1, "round {round}: {wins} overlapping blocks created");
        }
    }

    /// Per round, one process deletes an empty block while the other
    /// allocates into it. Both must never succeed: either the delete wins
    /// and the allocation finds no block, or the allocation wins and the
    /// delete sees an active allocation.
    pub async fn delete_and_allocate_never_both_succeed(pair: Pair) {
        for round in 0..ROUNDS {
            let block_id = block(&pair.ops[0], &format!("10.{round}.0.0/16")).await;
            let (a, b) = (Arc::clone(&pair.ops[0]), Arc::clone(&pair.ops[1]));
            let (del_id, req) = (
                block_id.clone(),
                alloc_request(&block_id, &format!("10.{round}.1.0/24")),
            );
            let hd = tokio::spawn(async move { a.delete_cidr_block(TEST_TENANT, &del_id).await });
            let ha = tokio::spawn(async move { b.allocate_specific(TEST_TENANT, &req).await });
            let (deleted, allocated) = (hd.await.unwrap(), ha.await.unwrap());
            match (&deleted, &allocated) {
                (Ok(()), Err(NetcidrError::CidrBlockNotFound(_)))
                | (Err(NetcidrError::CidrBlockHasActiveAllocations(_)), Ok(_)) => {}
                other => panic!("round {round}: inconsistent outcome {other:?}"),
            }
        }
    }

    /// Per round, 8 tasks split across both processes set the same
    /// `(ip, hostname)` pair. None may fail on the unique constraint: one
    /// creates the pointer and the rest update it, each with one history
    /// entry.
    pub async fn hostname_sets_of_one_pair_create_once(pair: Pair) {
        for round in 0..ROUNDS {
            let hostname = format!("host-{round}.example.com");
            let mut handles = Vec::new();
            for task in 0..8 {
                let ops = Arc::clone(&pair.ops[task % 2]);
                let input = CreateHostnamePointer {
                    ip_address: "10.0.0.1".to_string(),
                    hostname: hostname.clone(),
                    allocation_id: None,
                    notes: Some(format!("task-{task}")),
                };
                handles.push(tokio::spawn(async move {
                    ops.set_hostname_pointer(TEST_TENANT, &input).await
                }));
            }
            let mut ids = HashSet::new();
            for h in handles {
                match h.await.unwrap() {
                    Ok(p) => {
                        ids.insert(p.id);
                    }
                    Err(e) => panic!("round {round}: unexpected error: {e:?}"),
                }
            }
            assert_eq!(ids.len(), 1, "round {round}: pointer ids {ids:?}");
            let history = pair.stores[0]
                .list_hostname_history(
                    TEST_TENANT,
                    &HostnameHistoryFilter {
                        hostname: Some(hostname),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let creates = history
                .iter()
                .filter(|h| h.change_kind == ChangeKind::Create)
                .count();
            assert_eq!(history.len(), 8, "round {round}: one entry per set");
            assert_eq!(creates, 1, "round {round}: {creates} create entries");
        }
    }

    macro_rules! cross_process_tests {
        ($pair:expr) => {
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn allocate_specific_has_one_winner() {
                super::allocate_specific_has_one_winner($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn allocate_auto_never_overlaps() {
                super::allocate_auto_never_overlaps($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn overlapping_blocks_have_one_winner() {
                super::overlapping_blocks_have_one_winner($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn delete_and_allocate_never_both_succeed() {
                super::delete_and_allocate_never_both_succeed($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn last_platform_admin_survives() {
                super::last_platform_admin_survives($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn concurrent_seeds_apply_once() {
                super::concurrent_seeds_apply_once($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn pat_limit_holds() {
                super::pat_limit_holds($pair.await).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn hostname_sets_of_one_pair_create_once() {
                super::hostname_sets_of_one_pair_create_once($pair.await).await;
            }
        };
    }

    mod sqlite_file {
        use super::super::store_support::{open_sqlite_file, sqlite_file_path};
        use super::*;

        async fn pair() -> Pair {
            let (path, dir) = sqlite_file_path();
            let a: Arc<dyn IpamStore> = Arc::new(open_sqlite_file(&path).await);
            let b: Arc<dyn IpamStore> = Arc::new(open_sqlite_file(&path).await);
            Pair::new(a, b, Guard::TempDir(dir))
        }

        cross_process_tests!(pair());
    }

    #[cfg(feature = "ipam-postgres")]
    mod postgres {
        use super::super::store_support::pg::{open_postgres, test_database};
        use super::*;

        async fn pair() -> Pair {
            let db = test_database().await;
            let a: Arc<dyn IpamStore> = Arc::new(open_postgres(&db.url()).await);
            let b: Arc<dyn IpamStore> = Arc::new(open_postgres(&db.url()).await);
            Pair::new(a, b, Guard::Postgres(db))
        }

        cross_process_tests!(pair());
    }
}
