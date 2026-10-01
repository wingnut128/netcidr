//! Allocation Mutations under the cidr-block Lock Scope (ADR-0007).
//!
//! Every rule that used to be split between `IpamOps` and the store
//! adapters lives here: containment and overlap, ids and timestamps,
//! derived network metadata, TTL expiry, and status transitions. The
//! adapters only persist the rows these decisions produce.

use chrono::Duration;

use super::{
    IpRange, find_free_blocks, parse_range, range_contains, ranges_overlap,
    validate_same_ip_version,
};
use crate::error::{NetcidrError, Result};
use crate::ipam::models::{
    Allocation, AllocationStatus, AutoAllocateRequest, CidrBlock, CreateAllocation,
    UpdateAllocation,
};
use crate::ipam::mutation::{
    AuditFact, Change, DecideCtx, Decision, Handle, Mutation, ReadSet, Snapshot,
};
use crate::ipam::parse_cidr_metadata;
use crate::ipam::store::{LockScope, Write};

/// Allocations that occupy address space.
pub(super) const LIVE: [AllocationStatus; 2] =
    [AllocationStatus::Active, AllocationStatus::Reserved];

/// Upper bound on one auto-allocate. Each allocation is a row; an unbounded
/// count would let a caller drive unbounded work inside one transaction.
pub(super) const MAX_AUTO_ALLOCATE_COUNT: u32 = 1000;

fn block_scope(tenant_id: &str, cidr_block_id: &str) -> LockScope {
    LockScope::CidrBlock {
        tenant_id: tenant_id.to_string(),
        cidr_block_id: cidr_block_id.to_string(),
    }
}

fn require_block<'a>(block: &'a Option<CidrBlock>, id: &str) -> Result<&'a CidrBlock> {
    block
        .as_ref()
        .ok_or_else(|| NetcidrError::CidrBlockNotFound(id.to_string()))
}

fn require_allocation(alloc: &Option<Allocation>, id: &str) -> Result<Allocation> {
    alloc
        .clone()
        .ok_or_else(|| NetcidrError::AllocationNotFound(id.to_string()))
}

/// Fail if `candidate` overlaps any live allocation. Rows whose CIDR no
/// longer parses are skipped, as before.
fn ensure_no_overlap(live: &[Allocation], candidate: &IpRange, candidate_cidr: &str) -> Result<()> {
    for alloc in live {
        if let Ok(range) = parse_range(&alloc.cidr)
            && ranges_overlap(candidate, &range)
        {
            return Err(NetcidrError::AllocationConflict {
                existing: alloc.cidr.clone(),
                candidate: candidate_cidr.to_string(),
            });
        }
    }
    Ok(())
}

/// A brand-new allocation row: the id, timestamps, derived network fields,
/// and TTL expiry are all decided here.
fn new_allocation(tenant_id: &str, input: &CreateAllocation, cx: &DecideCtx) -> Result<Allocation> {
    let (network, broadcast, prefix, total, _ip_version) = parse_cidr_metadata(&input.cidr)?;
    let now = cx.now();
    let timestamp = now.to_rfc3339();
    Ok(Allocation {
        id: cx.new_id(),
        tenant_id: tenant_id.to_string(),
        cidr_block_id: input.cidr_block_id.clone(),
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
        tags: input.tags.clone().unwrap_or_default(),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        released_at: None,
        expires_at: input
            .ttl_seconds
            .map(|ttl| (now + Duration::seconds(ttl as i64)).to_rfc3339()),
    })
}

fn insert(alloc: &Allocation) -> Change {
    Change::new(
        Write::InsertAllocation(alloc.clone()),
        AuditFact {
            action: "allocate",
            entity_type: "allocation",
            entity_id: alloc.id.clone(),
            details: Some(alloc.cidr.clone()),
        },
    )
}

/// Mark `alloc` released at `cx.now()`.
fn released(mut alloc: Allocation, cx: &DecideCtx) -> Allocation {
    let now = cx.now().to_rfc3339();
    alloc.status = AllocationStatus::Released;
    alloc.released_at = Some(now.clone());
    alloc.updated_at = now;
    alloc
}

// ---------------------------------------------------------------------------
// Allocate a specific CIDR
// ---------------------------------------------------------------------------

pub(super) struct AllocateSpecific {
    pub tenant_id: String,
    pub input: CreateAllocation,
}

pub(super) struct AllocateSpecificReads {
    block: Handle<Option<CidrBlock>>,
    parent: Option<Handle<Option<Allocation>>>,
    live: Handle<Vec<Allocation>>,
}

impl Mutation for AllocateSpecific {
    type Output = Allocation;
    type Reads = AllocateSpecificReads;

    fn scope(&self) -> LockScope {
        block_scope(&self.tenant_id, &self.input.cidr_block_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        AllocateSpecificReads {
            block: set.cidr_block(&self.tenant_id, &self.input.cidr_block_id),
            parent: self
                .input
                .parent_allocation_id
                .as_ref()
                .map(|id| set.allocation(&self.tenant_id, id)),
            live: set.allocations_in_block(&self.tenant_id, &self.input.cidr_block_id, &LIVE),
        }
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<Allocation>> {
        let input = &self.input;
        let block = require_block(snapshot.get(reads.block)?, &input.cidr_block_id)?;
        let block_range = parse_range(&block.cidr)?;
        let candidate = parse_range(&input.cidr)?;

        // Reject cross-family allocations (e.g. an IPv4 CIDR in an IPv6 block).
        validate_same_ip_version(&block_range, &candidate, &input.cidr)?;
        if !range_contains(&block_range, &candidate) {
            return Err(NetcidrError::AllocationConflict {
                existing: block.cidr.clone(),
                candidate: format!("{} is outside cidr_block", input.cidr),
            });
        }
        if let (Some(parent_id), Some(parent)) = (&input.parent_allocation_id, reads.parent) {
            let parent = require_allocation(snapshot.get(parent)?, parent_id)?;
            if !range_contains(&parse_range(&parent.cidr)?, &candidate) {
                return Err(NetcidrError::AllocationConflict {
                    existing: parent.cidr.clone(),
                    candidate: format!("{} does not fit within parent allocation", input.cidr),
                });
            }
        }
        ensure_no_overlap(snapshot.get(reads.live)?, &candidate, &input.cidr)?;

        // A released allocation with the same CIDR is history, not a slot to
        // reuse: always create a fresh record.
        let alloc = new_allocation(&self.tenant_id, input, cx)?;
        let change = insert(&alloc);
        Ok(Decision::new(alloc, change))
    }
}

// ---------------------------------------------------------------------------
// Auto-allocate the next free blocks
// ---------------------------------------------------------------------------

pub(super) struct AllocateAuto {
    pub tenant_id: String,
    pub request: AutoAllocateRequest,
}

pub(super) struct AllocateAutoReads {
    block: Handle<Option<CidrBlock>>,
    live: Handle<Vec<Allocation>>,
}

impl Mutation for AllocateAuto {
    type Output = Vec<Allocation>;
    type Reads = AllocateAutoReads;

    fn scope(&self) -> LockScope {
        block_scope(&self.tenant_id, &self.request.cidr_block_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        AllocateAutoReads {
            block: set.cidr_block(&self.tenant_id, &self.request.cidr_block_id),
            live: set.allocations_in_block(&self.tenant_id, &self.request.cidr_block_id, &LIVE),
        }
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<Vec<Allocation>>> {
        let request = &self.request;
        let block = require_block(snapshot.get(reads.block)?, &request.cidr_block_id)?;
        let block_range = parse_range(&block.cidr)?;

        let count = request.count.unwrap_or(1);
        if count > MAX_AUTO_ALLOCATE_COUNT {
            return Err(NetcidrError::InvalidInput(format!(
                "requested count {count} exceeds maximum of {MAX_AUTO_ALLOCATE_COUNT}"
            )));
        }
        let max_prefix: u8 = if block_range.is_v4 { 32 } else { 128 };
        if request.prefix_length > max_prefix {
            return Err(NetcidrError::InvalidInput(format!(
                "prefix length {} exceeds maximum {} for IPv{}",
                request.prefix_length,
                max_prefix,
                if block_range.is_v4 { 4 } else { 6 }
            )));
        }

        let occupied: Vec<IpRange> = snapshot
            .get(reads.live)?
            .iter()
            .filter_map(|a| parse_range(&a.cidr).ok())
            .collect();
        let cidrs = find_free_blocks(&block_range, &occupied, request.prefix_length, count)?;
        if cidrs.is_empty() {
            return Err(NetcidrError::NoFreeSpace {
                cidr_block: block.cidr.clone(),
                prefix: request.prefix_length,
            });
        }

        // Every allocation is one Change in the same unit, so the request
        // commits all of them or none.
        let mut allocations = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let input = CreateAllocation {
                cidr_block_id: request.cidr_block_id.clone(),
                cidr,
                status: request.status.clone(),
                resource_id: request.resource_id.clone(),
                resource_type: request.resource_type.clone(),
                name: request.name.clone(),
                description: request.description.clone(),
                environment: request.environment.clone(),
                owner: request.owner.clone(),
                parent_allocation_id: request.parent_allocation_id.clone(),
                tags: request.tags.clone(),
                ttl_seconds: request.ttl_seconds,
            };
            allocations.push(new_allocation(&self.tenant_id, &input, cx)?);
        }
        let changes: Vec<Change> = allocations.iter().map(insert).collect();
        Ok(changes
            .into_iter()
            .fold(Decision::unchanged(allocations), Decision::and))
    }
}

// ---------------------------------------------------------------------------
// Update and release
// ---------------------------------------------------------------------------

/// Update an allocation's descriptive fields and/or status.
/// `cidr_block_id` is the allocation's block, read before locking; an
/// allocation never changes blocks, so the lock it names is the right one.
pub(super) struct UpdateAllocationMutation {
    pub tenant_id: String,
    pub id: String,
    pub cidr_block_id: String,
    pub input: UpdateAllocation,
}

pub(super) struct UpdateReads {
    alloc: Handle<Option<Allocation>>,
    live: Handle<Vec<Allocation>>,
}

impl Mutation for UpdateAllocationMutation {
    type Output = Allocation;
    type Reads = UpdateReads;

    fn scope(&self) -> LockScope {
        block_scope(&self.tenant_id, &self.cidr_block_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        UpdateReads {
            alloc: set.allocation(&self.tenant_id, &self.id),
            live: set.allocations_in_block(&self.tenant_id, &self.cidr_block_id, &LIVE),
        }
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<Allocation>> {
        let mut alloc = require_allocation(snapshot.get(reads.alloc)?, &self.id)?;
        let input = self.input;
        let reactivating = matches!(
            input.status,
            Some(AllocationStatus::Active | AllocationStatus::Reserved)
        );

        // Reactivating a released allocation must not overlap what was
        // allocated while it was released.
        if reactivating && alloc.status == AllocationStatus::Released {
            ensure_no_overlap(
                snapshot.get(reads.live)?,
                &parse_range(&alloc.cidr)?,
                &alloc.cidr,
            )?;
        }

        macro_rules! apply {
            ($($field:ident),*) => {
                $(if let Some(value) = input.$field { alloc.$field = Some(value); })*
            };
        }
        apply!(
            name,
            description,
            resource_id,
            resource_type,
            environment,
            owner
        );
        if let Some(status) = input.status {
            alloc.status = status;
        }
        if reactivating {
            alloc.released_at = None;
        }
        alloc.updated_at = cx.now().to_rfc3339();

        let change = Change::new(
            Write::ReplaceAllocation(alloc.clone()),
            AuditFact {
                action: "update",
                entity_type: "allocation",
                entity_id: alloc.id.clone(),
                details: None,
            },
        );
        Ok(Decision::new(alloc, change))
    }
}

/// Release an allocation. Releasing one that is already released changes
/// nothing and records no audit row.
pub(super) struct ReleaseAllocationMutation {
    pub tenant_id: String,
    pub id: String,
    pub cidr_block_id: String,
}

impl Mutation for ReleaseAllocationMutation {
    type Output = Allocation;
    type Reads = Handle<Option<Allocation>>;

    fn scope(&self) -> LockScope {
        block_scope(&self.tenant_id, &self.cidr_block_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.allocation(&self.tenant_id, &self.id)
    }

    fn decide(
        self,
        alloc: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<Allocation>> {
        let alloc = require_allocation(snapshot.get(alloc)?, &self.id)?;
        if alloc.status == AllocationStatus::Released {
            return Ok(Decision::unchanged(alloc));
        }
        let alloc = released(alloc, cx);
        let change = Change::new(
            Write::ReplaceAllocation(alloc.clone()),
            AuditFact {
                action: "release",
                entity_type: "allocation",
                entity_id: alloc.id.clone(),
                details: Some(alloc.cidr.clone()),
            },
        );
        Ok(Decision::new(alloc, change))
    }
}

/// Release every live allocation in one cidr block whose `expires_at` has
/// passed. Returns how many were released.
pub(super) struct ExpireInBlock {
    pub tenant_id: String,
    pub cidr_block_id: String,
}

impl Mutation for ExpireInBlock {
    type Output = usize;
    type Reads = Handle<Vec<Allocation>>;

    fn scope(&self) -> LockScope {
        block_scope(&self.tenant_id, &self.cidr_block_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.allocations_in_block(&self.tenant_id, &self.cidr_block_id, &LIVE)
    }

    fn decide(
        self,
        live: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<usize>> {
        // RFC 3339 timestamps in UTC compare correctly as strings.
        let now = cx.now().to_rfc3339();
        let changes: Vec<Change> = snapshot
            .get(live)?
            .iter()
            .filter(|a| a.expires_at.as_deref().is_some_and(|e| e <= now.as_str()))
            .map(|a| {
                let alloc = released(a.clone(), cx);
                Change::new(
                    Write::ReplaceAllocation(alloc.clone()),
                    AuditFact {
                        action: "expire",
                        entity_type: "allocation",
                        entity_id: alloc.id.clone(),
                        details: Some(alloc.cidr.clone()),
                    },
                )
            })
            .collect();
        let count = changes.len();
        Ok(changes
            .into_iter()
            .fold(Decision::unchanged(count), Decision::and))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::audit_context::AuditContext;
    use crate::ipam::models::Tag;
    use crate::ipam::mutation::IdSource;
    use crate::ipam::store::Rows;

    const T: &str = "t@example.com";

    #[derive(Default)]
    struct SeqIds(AtomicUsize);
    impl IdSource for SeqIds {
        fn new_id(&self) -> String {
            format!("id-{}", self.0.fetch_add(1, Ordering::Relaxed))
        }
    }

    fn noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
    }

    fn cx() -> DecideCtx {
        DecideCtx::new(noon(), AuditContext::default(), Arc::new(SeqIds::default()))
    }

    fn block(cidr: &str) -> CidrBlock {
        CidrBlock {
            id: "b1".to_string(),
            tenant_id: T.to_string(),
            cidr: cidr.to_string(),
            network_address: String::new(),
            broadcast_address: String::new(),
            prefix_length: 0,
            total_hosts: 0,
            name: None,
            description: None,
            ip_version: 4,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn alloc(id: &str, cidr: &str, status: AllocationStatus) -> Allocation {
        Allocation {
            id: id.to_string(),
            tenant_id: T.to_string(),
            cidr_block_id: "b1".to_string(),
            cidr: cidr.to_string(),
            network_address: String::new(),
            broadcast_address: String::new(),
            prefix_length: 24,
            total_hosts: 256,
            status,
            resource_id: None,
            resource_type: None,
            name: Some("old".to_string()),
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: vec![],
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            updated_at: "2026-01-01T00:00:00+00:00".to_string(),
            released_at: None,
            expires_at: None,
        }
    }

    fn create(cidr: &str) -> CreateAllocation {
        CreateAllocation {
            cidr_block_id: "b1".to_string(),
            cidr: cidr.to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: Some("web".to_string()),
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: Some(vec![Tag {
                key: "env".to_string(),
                value: "prod".to_string(),
            }]),
            ttl_seconds: Some(3600),
        }
    }

    /// Declare a Mutation's reads and decide it against `rows`.
    fn decide<M: Mutation>(m: M, rows: Vec<Rows>) -> Result<Decision<M::Output>> {
        let mut set = ReadSet::default();
        let reads = m.reads(&mut set);
        m.decide(reads, &Snapshot::new(rows), &cx())
    }

    fn specific(cidr: &str) -> AllocateSpecific {
        AllocateSpecific {
            tenant_id: T.to_string(),
            input: create(cidr),
        }
    }

    #[test]
    fn allocate_specific_builds_the_row_from_the_decision_context() {
        let d = decide(
            specific("10.0.1.0/24"),
            vec![
                Rows::CidrBlock(Some(block("10.0.0.0/8"))),
                Rows::Allocations(vec![]),
            ],
        )
        .unwrap();
        let a = d.output();
        assert_eq!(a.id, "id-0");
        assert_eq!(a.status, AllocationStatus::Active);
        assert_eq!(a.network_address, "10.0.1.0");
        assert_eq!(a.broadcast_address, "10.0.1.255");
        assert_eq!(a.total_hosts, 256);
        assert_eq!(a.created_at, noon().to_rfc3339());
        assert_eq!(a.updated_at, noon().to_rfc3339());
        assert_eq!(
            a.expires_at,
            Some((noon() + Duration::seconds(3600)).to_rfc3339())
        );
        assert_eq!(a.tags.len(), 1);
        assert_eq!(d.changes().len(), 1);
    }

    #[test]
    fn allocate_specific_rejects_a_missing_block() {
        let err = decide(
            specific("10.0.1.0/24"),
            vec![Rows::CidrBlock(None), Rows::Allocations(vec![])],
        )
        .unwrap_err();
        assert!(matches!(err, NetcidrError::CidrBlockNotFound(_)));
    }

    #[test]
    fn allocate_specific_rejects_outside_block_and_overlap() {
        let outside = decide(
            specific("192.168.0.0/24"),
            vec![
                Rows::CidrBlock(Some(block("10.0.0.0/8"))),
                Rows::Allocations(vec![]),
            ],
        );
        assert!(matches!(
            outside,
            Err(NetcidrError::AllocationConflict { .. })
        ));

        let overlap = decide(
            specific("10.0.1.0/25"),
            vec![
                Rows::CidrBlock(Some(block("10.0.0.0/8"))),
                Rows::Allocations(vec![alloc("a", "10.0.1.0/24", AllocationStatus::Active)]),
            ],
        );
        assert!(matches!(
            overlap,
            Err(NetcidrError::AllocationConflict { .. })
        ));
    }

    fn auto(count: u32) -> AllocateAuto {
        AllocateAuto {
            tenant_id: T.to_string(),
            request: AutoAllocateRequest {
                cidr_block_id: "b1".to_string(),
                prefix_length: 24,
                count: Some(count),
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
        }
    }

    #[test]
    fn allocate_auto_decides_every_block_in_one_decision() {
        let d = decide(
            auto(3),
            vec![
                Rows::CidrBlock(Some(block("10.0.0.0/22"))),
                Rows::Allocations(vec![alloc("a", "10.0.1.0/24", AllocationStatus::Reserved)]),
            ],
        )
        .unwrap();
        let cidrs: Vec<&str> = d.output().iter().map(|a| a.cidr.as_str()).collect();
        assert_eq!(cidrs, ["10.0.0.0/24", "10.0.2.0/24", "10.0.3.0/24"]);
        assert_eq!(d.changes().len(), 3);
    }

    #[test]
    fn allocate_auto_rejects_excess_count_and_a_full_block() {
        let too_many = decide(
            auto(MAX_AUTO_ALLOCATE_COUNT + 1),
            vec![
                Rows::CidrBlock(Some(block("10.0.0.0/8"))),
                Rows::Allocations(vec![]),
            ],
        );
        assert!(matches!(too_many, Err(NetcidrError::InvalidInput(_))));

        let full = decide(
            auto(1),
            vec![
                Rows::CidrBlock(Some(block("10.0.0.0/24"))),
                Rows::Allocations(vec![alloc("a", "10.0.0.0/24", AllocationStatus::Active)]),
            ],
        );
        assert!(matches!(full, Err(NetcidrError::NoFreeSpace { .. })));
    }

    fn update(status: Option<AllocationStatus>) -> UpdateAllocationMutation {
        UpdateAllocationMutation {
            tenant_id: T.to_string(),
            id: "a".to_string(),
            cidr_block_id: "b1".to_string(),
            input: UpdateAllocation {
                name: None,
                description: Some("new".to_string()),
                resource_id: None,
                resource_type: None,
                environment: None,
                owner: None,
                status,
            },
        }
    }

    #[test]
    fn update_keeps_unspecified_fields_and_stamps_updated_at() {
        let d = decide(
            update(None),
            vec![
                Rows::Allocation(Some(alloc("a", "10.0.1.0/24", AllocationStatus::Active))),
                Rows::Allocations(vec![]),
            ],
        )
        .unwrap();
        assert_eq!(d.output().name.as_deref(), Some("old"));
        assert_eq!(d.output().description.as_deref(), Some("new"));
        assert_eq!(d.output().updated_at, noon().to_rfc3339());
    }

    #[test]
    fn reactivation_checks_overlap_and_clears_released_at() {
        let mut released = alloc("a", "10.0.1.0/24", AllocationStatus::Released);
        released.released_at = Some("2026-09-01T00:00:00+00:00".to_string());

        let blocked = decide(
            update(Some(AllocationStatus::Active)),
            vec![
                Rows::Allocation(Some(released.clone())),
                Rows::Allocations(vec![alloc("b", "10.0.1.0/24", AllocationStatus::Active)]),
            ],
        );
        assert!(matches!(
            blocked,
            Err(NetcidrError::AllocationConflict { .. })
        ));

        let d = decide(
            update(Some(AllocationStatus::Reserved)),
            vec![Rows::Allocation(Some(released)), Rows::Allocations(vec![])],
        )
        .unwrap();
        assert_eq!(d.output().status, AllocationStatus::Reserved);
        assert_eq!(d.output().released_at, None);
    }

    fn release() -> ReleaseAllocationMutation {
        ReleaseAllocationMutation {
            tenant_id: T.to_string(),
            id: "a".to_string(),
            cidr_block_id: "b1".to_string(),
        }
    }

    #[test]
    fn release_stamps_released_at_and_is_a_no_op_when_already_released() {
        let d = decide(
            release(),
            vec![Rows::Allocation(Some(alloc(
                "a",
                "10.0.1.0/24",
                AllocationStatus::Active,
            )))],
        )
        .unwrap();
        assert_eq!(d.output().status, AllocationStatus::Released);
        assert_eq!(d.output().released_at, Some(noon().to_rfc3339()));
        assert_eq!(d.changes().len(), 1);

        let again = decide(release(), vec![Rows::Allocation(Some(d.output().clone()))]).unwrap();
        assert!(again.changes().is_empty());

        let missing = decide(release(), vec![Rows::Allocation(None)]);
        assert!(matches!(missing, Err(NetcidrError::AllocationNotFound(_))));
    }

    #[test]
    fn expiry_releases_only_allocations_past_their_expiry() {
        let mut due = alloc("due", "10.0.1.0/24", AllocationStatus::Reserved);
        due.expires_at = Some((noon() - Duration::seconds(1)).to_rfc3339());
        let mut later = alloc("later", "10.0.2.0/24", AllocationStatus::Reserved);
        later.expires_at = Some((noon() + Duration::hours(1)).to_rfc3339());
        let forever = alloc("forever", "10.0.3.0/24", AllocationStatus::Active);

        let d = decide(
            ExpireInBlock {
                tenant_id: T.to_string(),
                cidr_block_id: "b1".to_string(),
            },
            vec![Rows::Allocations(vec![due, later, forever])],
        )
        .unwrap();
        assert_eq!(*d.output(), 1);
        assert_eq!(d.changes().len(), 1);
    }
}
