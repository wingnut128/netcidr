//! CIDR-block Mutations (ADR-0007).
//!
//! Creating a block takes the tenant's Lock Scope, because its rule — no two
//! blocks in a tenant overlap — spans every block the tenant has. Deleting a
//! block takes that block's own scope, because its rule — no active
//! allocations — is about the block's allocations, which are written under
//! the same scope. `load` restores a dump into an empty tenant as one unit.

use std::collections::HashMap;

use super::allocation::{LIVE, new_allocation};
use super::{parse_range, ranges_overlap};
use crate::error::{NetcidrError, Result};
use crate::ipam::models::{Allocation, CidrBlock, CreateAllocation, CreateCidrBlock, IpamDump};
use crate::ipam::mutation::{
    AuditFact, Change, DecideCtx, Decision, Handle, Mutation, ReadSet, Snapshot,
};
use crate::ipam::store::{LockScope, Write};

fn tenant_scope(tenant_id: &str) -> LockScope {
    LockScope::Tenant {
        tenant_id: tenant_id.to_string(),
    }
}

/// A brand-new cidr block row, with its id and timestamps from the decision
/// context.
fn new_cidr_block(tenant_id: &str, input: &CreateCidrBlock, cx: &DecideCtx) -> Result<CidrBlock> {
    CidrBlock::from_input(tenant_id, input, cx.new_id(), cx.now())
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

pub(super) struct CreateCidrBlockMutation {
    pub tenant_id: String,
    pub input: CreateCidrBlock,
}

impl Mutation for CreateCidrBlockMutation {
    type Output = CidrBlock;
    type Reads = Handle<Vec<CidrBlock>>;

    fn scope(&self) -> LockScope {
        tenant_scope(&self.tenant_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.cidr_blocks(&self.tenant_id)
    }

    fn decide(
        self,
        existing: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<CidrBlock>> {
        let candidate = parse_range(&self.input.cidr)?;
        for block in snapshot.get(existing)? {
            if ranges_overlap(&candidate, &parse_range(&block.cidr)?) {
                return Err(NetcidrError::AllocationConflict {
                    existing: block.cidr.clone(),
                    candidate: self.input.cidr.clone(),
                });
            }
        }
        let block = new_cidr_block(&self.tenant_id, &self.input, cx)?;
        let change = Change::new(
            Write::InsertCidrBlock(block.clone()),
            AuditFact {
                action: "create_cidr_block",
                entity_type: "cidr_block",
                entity_id: block.id.clone(),
                details: Some(block.cidr.clone()),
            },
        );
        Ok(Decision::new(block, change))
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/// Delete a cidr block with no active or reserved allocations, removing its
/// released allocations with it.
pub(super) struct DeleteCidrBlockMutation {
    pub tenant_id: String,
    pub id: String,
}

pub(super) struct DeleteReads {
    block: Handle<Option<CidrBlock>>,
    live: Handle<Vec<Allocation>>,
}

impl Mutation for DeleteCidrBlockMutation {
    type Output = ();
    type Reads = DeleteReads;

    fn scope(&self) -> LockScope {
        LockScope::CidrBlock {
            tenant_id: self.tenant_id.clone(),
            cidr_block_id: self.id.clone(),
        }
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        DeleteReads {
            block: set.cidr_block(&self.tenant_id, &self.id),
            live: set.allocations_in_block(&self.tenant_id, &self.id, &LIVE),
        }
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        _cx: &DecideCtx,
    ) -> Result<Decision<()>> {
        let block = snapshot
            .get(reads.block)?
            .as_ref()
            .ok_or_else(|| NetcidrError::CidrBlockNotFound(self.id.clone()))?;
        if !snapshot.get(reads.live)?.is_empty() {
            return Err(NetcidrError::CidrBlockHasActiveAllocations(self.id.clone()));
        }
        let change = Change::new(
            Write::DeleteCidrBlock {
                tenant_id: self.tenant_id.clone(),
                id: self.id.clone(),
            },
            AuditFact {
                action: "delete_cidr_block",
                entity_type: "cidr_block",
                entity_id: self.id.clone(),
                details: Some(block.cidr.clone()),
            },
        );
        Ok(Decision::new((), change))
    }
}

// ---------------------------------------------------------------------------
// Load (restore a dump)
// ---------------------------------------------------------------------------

/// Restore a dump into an empty tenant, all-or-nothing. Records get fresh
/// ids and timestamps; allocation status, descriptive fields, and tags are
/// kept; parent links and expiry are not restored. Every restored row is
/// audited as `load`.
pub(super) struct LoadDump {
    pub tenant_id: String,
    pub dump: IpamDump,
}

impl Mutation for LoadDump {
    type Output = (usize, usize);
    type Reads = Handle<Vec<CidrBlock>>;

    fn scope(&self) -> LockScope {
        tenant_scope(&self.tenant_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.cidr_blocks(&self.tenant_id)
    }

    fn decide(
        self,
        existing: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<(usize, usize)>> {
        if !snapshot.get(existing)?.is_empty() {
            return Err(NetcidrError::InvalidInput(
                "cannot import into a non-empty store — existing CIDR blocks found".to_string(),
            ));
        }

        let restored = |entity_type: &'static str, id: &str, cidr: &str| AuditFact {
            action: "load",
            entity_type,
            entity_id: id.to_string(),
            details: Some(cidr.to_string()),
        };

        let mut changes = Vec::new();
        let mut new_block_ids: HashMap<&str, String> = HashMap::new();
        for old in &self.dump.cidr_blocks {
            let block = new_cidr_block(
                &self.tenant_id,
                &CreateCidrBlock {
                    cidr: old.cidr.clone(),
                    name: old.name.clone(),
                    description: old.description.clone(),
                },
                cx,
            )?;
            new_block_ids.insert(old.id.as_str(), block.id.clone());
            changes.push(Change::new(
                Write::InsertCidrBlock(block.clone()),
                restored("cidr_block", &block.id, &block.cidr),
            ));
        }

        for old in &self.dump.allocations {
            let block_id = new_block_ids
                .get(old.cidr_block_id.as_str())
                .ok_or_else(|| {
                    NetcidrError::InvalidInput(format!(
                        "allocation {} references unknown cidr_block {}",
                        old.cidr, old.cidr_block_id
                    ))
                })?;
            let alloc = new_allocation(
                &self.tenant_id,
                &CreateAllocation {
                    cidr_block_id: block_id.clone(),
                    cidr: old.cidr.clone(),
                    status: Some(old.status.clone()),
                    resource_id: old.resource_id.clone(),
                    resource_type: old.resource_type.clone(),
                    name: old.name.clone(),
                    description: old.description.clone(),
                    environment: old.environment.clone(),
                    owner: old.owner.clone(),
                    parent_allocation_id: None,
                    tags: Some(old.tags.clone()),
                    ttl_seconds: None,
                },
                cx,
            )?;
            changes.push(Change::new(
                Write::InsertAllocation(alloc.clone()),
                restored("allocation", &alloc.id, &alloc.cidr),
            ));
        }

        let counts = (self.dump.cidr_blocks.len(), self.dump.allocations.len());
        Ok(changes
            .into_iter()
            .fold(Decision::unchanged(counts), Decision::and))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::audit_context::AuditContext;
    use crate::ipam::models::{AllocationStatus, Tag};
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

    fn decide<M: Mutation>(m: M, rows: Vec<Rows>) -> Result<Decision<M::Output>> {
        let cx = DecideCtx::new(noon(), AuditContext::default(), Arc::new(SeqIds::default()));
        let mut set = ReadSet::default();
        let reads = m.reads(&mut set);
        m.decide(reads, &Snapshot::new(rows), &cx)
    }

    fn block(id: &str, cidr: &str) -> CidrBlock {
        CidrBlock::from_input(
            T,
            &CreateCidrBlock {
                cidr: cidr.to_string(),
                name: None,
                description: None,
            },
            id.to_string(),
            noon(),
        )
        .unwrap()
    }

    fn alloc(block_id: &str, cidr: &str, status: AllocationStatus) -> Allocation {
        Allocation::from_input(
            T,
            &CreateAllocation {
                cidr_block_id: block_id.to_string(),
                cidr: cidr.to_string(),
                status: Some(status),
                resource_id: None,
                resource_type: None,
                name: Some("n".to_string()),
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
            format!("old-{cidr}"),
            noon(),
        )
        .unwrap()
    }

    fn create(cidr: &str) -> CreateCidrBlockMutation {
        CreateCidrBlockMutation {
            tenant_id: T.to_string(),
            input: CreateCidrBlock {
                cidr: cidr.to_string(),
                name: Some("Corp".to_string()),
                description: None,
            },
        }
    }

    #[test]
    fn create_builds_the_row_and_rejects_overlap_with_any_tenant_block() {
        let d = decide(create("10.0.0.0/8"), vec![Rows::CidrBlocks(vec![])]).unwrap();
        assert_eq!(d.output().id, "id-0");
        assert_eq!(d.output().broadcast_address, "10.255.255.255");
        assert_eq!(d.output().created_at, noon().to_rfc3339());
        assert_eq!(d.changes().len(), 1);

        let overlap = decide(
            create("10.1.0.0/16"),
            vec![Rows::CidrBlocks(vec![
                block("a", "192.168.0.0/16"),
                block("b", "10.0.0.0/8"),
            ])],
        );
        assert!(matches!(
            overlap,
            Err(NetcidrError::AllocationConflict { .. })
        ));
    }

    fn delete() -> DeleteCidrBlockMutation {
        DeleteCidrBlockMutation {
            tenant_id: T.to_string(),
            id: "b".to_string(),
        }
    }

    #[test]
    fn delete_requires_the_block_and_no_live_allocations() {
        let missing = decide(
            delete(),
            vec![Rows::CidrBlock(None), Rows::Allocations(vec![])],
        );
        assert!(matches!(missing, Err(NetcidrError::CidrBlockNotFound(_))));

        let busy = decide(
            delete(),
            vec![
                Rows::CidrBlock(Some(block("b", "10.0.0.0/8"))),
                Rows::Allocations(vec![alloc("b", "10.0.0.0/24", AllocationStatus::Reserved)]),
            ],
        );
        assert!(matches!(
            busy,
            Err(NetcidrError::CidrBlockHasActiveAllocations(_))
        ));

        let ok = decide(
            delete(),
            vec![
                Rows::CidrBlock(Some(block("b", "10.0.0.0/8"))),
                Rows::Allocations(vec![]),
            ],
        )
        .unwrap();
        assert_eq!(ok.changes().len(), 1);
    }

    fn load(dump: IpamDump) -> LoadDump {
        LoadDump {
            tenant_id: T.to_string(),
            dump,
        }
    }

    fn dump(blocks: Vec<CidrBlock>, allocations: Vec<Allocation>) -> IpamDump {
        IpamDump {
            version: 1,
            exported_at: String::new(),
            cidr_blocks: blocks,
            allocations,
        }
    }

    #[test]
    fn load_restores_everything_with_fresh_ids_in_one_decision() {
        let mut released = alloc("old-b", "10.0.1.0/24", AllocationStatus::Released);
        released.parent_allocation_id = Some("old-parent".to_string());
        let d = decide(
            load(dump(
                vec![block("old-b", "10.0.0.0/8")],
                vec![
                    alloc("old-b", "10.0.0.0/24", AllocationStatus::Active),
                    released,
                ],
            )),
            vec![Rows::CidrBlocks(vec![])],
        )
        .unwrap();
        assert_eq!(*d.output(), (1, 2));
        assert_eq!(d.changes().len(), 3);
    }

    #[test]
    fn load_rejects_a_non_empty_tenant_and_dangling_block_references() {
        let non_empty = decide(
            load(dump(vec![block("x", "10.0.0.0/8")], vec![])),
            vec![Rows::CidrBlocks(vec![block("existing", "172.16.0.0/12")])],
        );
        assert!(matches!(non_empty, Err(NetcidrError::InvalidInput(_))));

        let dangling = decide(
            load(dump(
                vec![],
                vec![alloc("nowhere", "10.0.0.0/24", AllocationStatus::Active)],
            )),
            vec![Rows::CidrBlocks(vec![])],
        );
        assert!(matches!(dangling, Err(NetcidrError::InvalidInput(_))));
    }
}
