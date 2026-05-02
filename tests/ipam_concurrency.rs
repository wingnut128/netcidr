//! Concurrency tests for IPAM allocations.
//!
//! Per-supernet locking in `IpamOps` serializes the
//! "check overlap → insert" sequence so concurrent requests for an
//! overlapping CIDR cannot both succeed. These tests prove the invariant.

use std::sync::Arc;

use netcidr::error::NetcidrError;
use netcidr::ipam::models::*;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;

const TEST_TENANT: &str = "test@example.com";

async fn ops_with_supernet(cidr: &str) -> (Arc<IpamOps>, String) {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let ops = Arc::new(IpamOps::new(Arc::new(store)));
    let sn = ops
        .create_supernet(
            TEST_TENANT,
            &CreateSupernet {
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
/// other 7 must fail with `AllocationConflict`. Without per-supernet
/// locking the check-then-insert window allows duplicates to slip through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_allocate_specific_same_cidr_yields_exactly_one_winner() {
    let (ops, sn_id) = ops_with_supernet("10.0.0.0/8").await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let ops = Arc::clone(&ops);
        let sn_id = sn_id.clone();
        handles.push(tokio::spawn(async move {
            ops.allocate_specific(
                TEST_TENANT,
                &CreateAllocation {
                    supernet_id: sn_id,
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

/// 16 tasks race to auto-allocate /24 blocks from a small /22 supernet
/// (4 blocks total). All 4 winners must hold *non-overlapping* CIDRs and
/// the remaining 12 tasks must see `NoFreeSpace`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_auto_allocate_produces_no_overlaps() {
    let (ops, sn_id) = ops_with_supernet("10.0.0.0/22").await;

    let mut handles = Vec::new();
    for _ in 0..16 {
        let ops = Arc::clone(&ops);
        let sn_id = sn_id.clone();
        handles.push(tokio::spawn(async move {
            ops.allocate_auto(
                TEST_TENANT,
                &AutoAllocateRequest {
                    supernet_id: sn_id,
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
