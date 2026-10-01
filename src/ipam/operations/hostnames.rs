//! Hostname-pointer Mutations under the tenant's Lock Scope (ADR-0007).
//!
//! A tenant has at most one live pointer per `(ip, hostname)`, and a pointer
//! may only link an allocation in the same tenant. Setting reads the
//! existing pointer under the scope, so two concurrent sets of one pair
//! become a create and an update rather than a unique-constraint failure.
//! Every write appends its history entry in the same Change.

use crate::error::{NetcidrError, Result};
use crate::ipam::models::{
    Allocation, ChangeKind, CreateHostnamePointer, HostnamePointer, HostnamePointerHistoryEntry,
};
use crate::ipam::mutation::{
    AuditFact, Change, DecideCtx, Decision, Handle, Mutation, ReadSet, Snapshot,
};
use crate::ipam::store::{LockScope, Write};

fn tenant_scope(tenant_id: &str) -> LockScope {
    LockScope::Tenant {
        tenant_id: tenant_id.to_string(),
    }
}

/// The history entry recording `kind` on `subject`. `before`/`after` are the
/// pointer's snapshots on either side of the change.
fn history(
    kind: ChangeKind,
    subject: &HostnamePointer,
    before: Option<&HostnamePointer>,
    after: Option<&HostnamePointer>,
    cx: &DecideCtx,
) -> Result<HostnamePointerHistoryEntry> {
    Ok(HostnamePointerHistoryEntry {
        id: cx.new_id(),
        tenant_id: subject.tenant_id.clone(),
        pointer_id: subject.id.clone(),
        ip_address: subject.ip_address.clone(),
        hostname: subject.hostname.clone(),
        change_kind: kind,
        previous_value: before.map(serde_json::to_string).transpose()?,
        new_value: after.map(serde_json::to_string).transpose()?,
        actor: cx.actor(),
        changed_at: cx.now().to_rfc3339(),
    })
}

fn pair(pointer: &HostnamePointer) -> String {
    format!("{} -> {}", pointer.ip_address, pointer.hostname)
}

// ---------------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------------

/// Create the pointer for `(ip, hostname)`, or update its allocation link
/// and notes if it already exists. `input` must already be normalized.
pub(super) struct SetHostnamePointer {
    pub tenant_id: String,
    pub input: CreateHostnamePointer,
}

pub(super) struct SetReads {
    existing: Handle<Option<HostnamePointer>>,
    allocation: Option<Handle<Option<Allocation>>>,
}

impl Mutation for SetHostnamePointer {
    type Output = HostnamePointer;
    type Reads = SetReads;

    fn scope(&self) -> LockScope {
        tenant_scope(&self.tenant_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        SetReads {
            existing: set.hostname_pointer(
                &self.tenant_id,
                &self.input.ip_address,
                &self.input.hostname,
            ),
            allocation: self
                .input
                .allocation_id
                .as_deref()
                .map(|id| set.allocation(&self.tenant_id, id)),
        }
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<HostnamePointer>> {
        if let (Some(handle), Some(id)) = (reads.allocation, &self.input.allocation_id)
            && snapshot.get(handle)?.is_none()
        {
            return Err(NetcidrError::AllocationNotFound(id.clone()));
        }

        let now = cx.now().to_rfc3339();
        let previous = snapshot.get(reads.existing)?.as_ref();
        let (pointer, kind) = match previous {
            Some(current) => (
                HostnamePointer {
                    allocation_id: self.input.allocation_id,
                    notes: self.input.notes,
                    updated_at: now,
                    ..current.clone()
                },
                ChangeKind::Update,
            ),
            None => (
                HostnamePointer {
                    id: cx.new_id(),
                    tenant_id: self.tenant_id,
                    ip_address: self.input.ip_address,
                    hostname: self.input.hostname,
                    allocation_id: self.input.allocation_id,
                    notes: self.input.notes,
                    created_at: now.clone(),
                    updated_at: now,
                },
                ChangeKind::Create,
            ),
        };
        let entry = history(kind, &pointer, previous, Some(&pointer), cx)?;
        let change = Change::new(
            Write::PutHostnamePointer(pointer.clone()),
            AuditFact {
                action: "set_hostname_pointer",
                entity_type: "hostname_pointer",
                entity_id: pointer.id.clone(),
                details: Some(pair(&pointer)),
            },
        )
        .also(Write::AppendHostnameHistory(entry));
        Ok(Decision::new(pointer, change))
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/// Remove the live pointer for `(ip, hostname)`; its history is kept.
/// `ip_address` and `hostname` must already be normalized.
pub(super) struct DeleteHostnamePointer {
    pub tenant_id: String,
    pub ip_address: String,
    pub hostname: String,
}

impl Mutation for DeleteHostnamePointer {
    type Output = ();
    type Reads = Handle<Option<HostnamePointer>>;

    fn scope(&self) -> LockScope {
        tenant_scope(&self.tenant_id)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.hostname_pointer(&self.tenant_id, &self.ip_address, &self.hostname)
    }

    fn decide(
        self,
        existing: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<()>> {
        let current = snapshot.get(existing)?.as_ref().ok_or_else(|| {
            NetcidrError::HostnamePointerNotFound(format!(
                "{} -> {}",
                self.ip_address, self.hostname
            ))
        })?;
        let entry = history(ChangeKind::Delete, current, Some(current), None, cx)?;
        let change = Change::new(
            Write::DeleteHostnamePointer {
                tenant_id: current.tenant_id.clone(),
                id: current.id.clone(),
            },
            AuditFact {
                action: "delete_hostname_pointer",
                entity_type: "hostname_pointer",
                entity_id: current.id.clone(),
                details: Some(pair(current)),
            },
        )
        .also(Write::AppendHostnameHistory(entry));
        Ok(Decision::new((), change))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::audit_context::AuditContext;
    use crate::ipam::mutation::IdSource;
    use crate::ipam::store::Rows;

    const TENANT: &str = "t@example.com";

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
        let caller = AuditContext {
            caller_email: Some("ops@x".to_string()),
            ..AuditContext::default()
        };
        let cx = DecideCtx::new(noon(), caller, Arc::new(SeqIds::default()));
        let mut set = ReadSet::default();
        let reads = m.reads(&mut set);
        m.decide(reads, &Snapshot::new(rows), &cx)
    }

    fn set(allocation_id: Option<&str>, notes: Option<&str>) -> SetHostnamePointer {
        SetHostnamePointer {
            tenant_id: TENANT.to_string(),
            input: CreateHostnamePointer {
                ip_address: "10.0.1.5".to_string(),
                hostname: "web.example.com".to_string(),
                allocation_id: allocation_id.map(str::to_string),
                notes: notes.map(str::to_string),
            },
        }
    }

    fn existing() -> HostnamePointer {
        HostnamePointer {
            id: "p-1".to_string(),
            tenant_id: TENANT.to_string(),
            ip_address: "10.0.1.5".to_string(),
            hostname: "web.example.com".to_string(),
            allocation_id: None,
            notes: Some("v1".to_string()),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        }
    }

    /// The pointer and history entry a single-Change decision writes.
    fn written(change: &Change) -> (Option<&HostnamePointer>, &HostnamePointerHistoryEntry) {
        let mut writes = change.writes();
        let pointer = match writes.next() {
            Some(Write::PutHostnamePointer(p)) => Some(p),
            Some(Write::DeleteHostnamePointer { .. }) => None,
            other => panic!("unexpected primary write {other:?}"),
        };
        let Some(Write::AppendHostnameHistory(entry)) = writes.next() else {
            panic!("missing history entry");
        };
        assert!(writes.next().is_none());
        (pointer, entry)
    }

    #[test]
    fn set_creates_a_new_pointer_with_a_create_history_entry() {
        let d = decide(set(None, Some("n")), vec![Rows::HostnamePointer(None)]).unwrap();
        let p = d.output();
        assert_eq!(p.id, "id-0");
        assert_eq!(p.created_at, noon().to_rfc3339());
        assert_eq!(p.updated_at, noon().to_rfc3339());

        let [change] = d.changes() else {
            panic!("one change")
        };
        assert_eq!(change.audit().action, "set_hostname_pointer");
        assert_eq!(change.audit().entity_id, "id-0");
        assert_eq!(
            change.audit().details.as_deref(),
            Some("10.0.1.5 -> web.example.com")
        );
        let (pointer, entry) = written(change);
        assert_eq!(pointer.unwrap().id, "id-0");
        assert_eq!(entry.id, "id-1");
        assert_eq!(entry.pointer_id, "id-0");
        assert_eq!(entry.change_kind, ChangeKind::Create);
        assert_eq!(entry.previous_value, None);
        assert_eq!(
            entry.new_value.as_deref(),
            Some(serde_json::to_string(p).unwrap().as_str())
        );
        assert_eq!(entry.actor, "ops@x");
        assert_eq!(entry.changed_at, noon().to_rfc3339());
    }

    #[test]
    fn set_updates_an_existing_pointer_in_place() {
        let d = decide(
            set(None, Some("v2")),
            vec![Rows::HostnamePointer(Some(existing()))],
        )
        .unwrap();
        let p = d.output();
        assert_eq!(p.id, "p-1");
        assert_eq!(p.notes.as_deref(), Some("v2"));
        assert_eq!(p.created_at, "2026-01-01T00:00:00+00:00");
        assert_eq!(p.updated_at, noon().to_rfc3339());

        let (_, entry) = written(&d.changes()[0]);
        assert_eq!(entry.change_kind, ChangeKind::Update);
        assert_eq!(
            entry.previous_value.as_deref(),
            Some(serde_json::to_string(&existing()).unwrap().as_str())
        );
        assert!(entry.new_value.as_deref().unwrap().contains("\"v2\""));
    }

    #[test]
    fn set_rejects_an_allocation_missing_from_the_tenant() {
        let err = decide(
            set(Some("alloc-9"), None),
            vec![Rows::HostnamePointer(None), Rows::Allocation(None)],
        )
        .unwrap_err();
        assert!(matches!(err, NetcidrError::AllocationNotFound(id) if id == "alloc-9"));
    }

    #[test]
    fn delete_removes_the_pointer_and_keeps_its_last_value_in_history() {
        let d = decide(
            DeleteHostnamePointer {
                tenant_id: TENANT.to_string(),
                ip_address: "10.0.1.5".to_string(),
                hostname: "web.example.com".to_string(),
            },
            vec![Rows::HostnamePointer(Some(existing()))],
        )
        .unwrap();
        let [change] = d.changes() else {
            panic!("one change")
        };
        assert_eq!(change.audit().action, "delete_hostname_pointer");
        assert_eq!(change.audit().entity_id, "p-1");
        let (pointer, entry) = written(change);
        assert!(pointer.is_none());
        assert_eq!(entry.change_kind, ChangeKind::Delete);
        assert_eq!(entry.pointer_id, "p-1");
        assert!(entry.previous_value.is_some());
        assert_eq!(entry.new_value, None);
    }

    #[test]
    fn deleting_a_missing_pointer_is_not_found() {
        let err = decide(
            DeleteHostnamePointer {
                tenant_id: TENANT.to_string(),
                ip_address: "10.0.1.5".to_string(),
                hostname: "web.example.com".to_string(),
            },
            vec![Rows::HostnamePointer(None)],
        )
        .unwrap_err();
        assert!(
            matches!(err, NetcidrError::HostnamePointerNotFound(m) if m == "10.0.1.5 -> web.example.com")
        );
    }
}
