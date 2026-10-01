//! User-directory Mutations under the user-directory Lock Scope (ADR-0006,
//! ADR-0007).
//!
//! The directory is global, so every write takes the same scope. That is
//! what makes the platform-admin guards hold across processes: two
//! concurrent demotions or deletes see each other's effect on the count of
//! active platform admins instead of both passing a stale check.

use std::collections::HashSet;

use crate::audit_context::AuditContext;
use crate::auth::Role;
use crate::error::{NetcidrError, Result};
use crate::ipam::models::{UserRecord, UserStatus};
use crate::ipam::mutation::{
    AuditFact, Change, DecideCtx, Decision, Handle, Mutation, ReadSet, Snapshot,
};
use crate::ipam::store::{LockScope, Write};

/// The bootstrap marker that makes the env-list seed one-shot.
pub(super) const USERS_ENV_SEED: &str = "users_env_seed";

/// Who made a change: the caller's email, else their subject, else `"cli"`.
fn actor(caller: &AuditContext) -> String {
    caller
        .caller_email
        .clone()
        .or_else(|| caller.caller_sub.clone())
        .unwrap_or_else(|| "cli".to_string())
}

/// Safety rails for changing or deleting an existing user (ADR-0006).
/// `proposed` is the new `(role, status)`, or `None` for a delete.
///
/// 1. **Self-protection**: an authenticated platform admin cannot delete,
///    disable, or demote their own row. The CLI has no caller email, so it
///    is bound only by rule 2 — the documented lockout-recovery path.
/// 2. **Last platform admin**: nothing may leave zero active platform
///    admins.
fn guard_platform_admins(
    current: &UserRecord,
    proposed: Option<(Role, UserStatus)>,
    caller: &AuditContext,
    active_platform_admins: u64,
) -> Result<()> {
    let is_active_platform_admin =
        current.role == Role::PlatformAdmin && current.status == UserStatus::Active;
    let survives = proposed == Some((Role::PlatformAdmin, UserStatus::Active));
    if !is_active_platform_admin || survives {
        return Ok(());
    }
    if caller
        .caller_email
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case(&current.email))
    {
        return Err(NetcidrError::InvalidInput(
            "cannot remove, disable, or demote your own platform admin role".to_string(),
        ));
    }
    if active_platform_admins <= 1 {
        return Err(NetcidrError::LastPlatformAdmin);
    }
    Ok(())
}

fn directory_reads(set: &mut ReadSet, email: &str) -> DirectoryReads {
    DirectoryReads {
        user: set.user(email),
        active_platform_admins: set.active_platform_admin_count(),
    }
}

pub(super) struct DirectoryReads {
    user: Handle<Option<UserRecord>>,
    active_platform_admins: Handle<u64>,
}

// ---------------------------------------------------------------------------
// Upsert
// ---------------------------------------------------------------------------

/// Create a user or change an existing one's role and status. `email` must
/// already be lowercased.
pub(super) struct UpsertUser {
    pub email: String,
    pub role: Role,
    pub status: UserStatus,
}

impl Mutation for UpsertUser {
    type Output = UserRecord;
    type Reads = DirectoryReads;

    fn scope(&self) -> LockScope {
        LockScope::UserDirectory
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        directory_reads(set, &self.email)
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<UserRecord>> {
        let now = cx.now().to_rfc3339();
        let actor = actor(cx.caller());
        let user = match snapshot.get(reads.user)? {
            // A new row can only add capability, never strand the directory.
            None => UserRecord {
                email: self.email.clone(),
                role: self.role,
                status: self.status,
                created_at: now.clone(),
                updated_at: now,
                created_by: Some(actor),
                updated_by: None,
            },
            Some(current) => {
                guard_platform_admins(
                    current,
                    Some((self.role, self.status)),
                    cx.caller(),
                    *snapshot.get(reads.active_platform_admins)?,
                )?;
                UserRecord {
                    role: self.role,
                    status: self.status,
                    updated_at: now,
                    updated_by: Some(actor),
                    ..current.clone()
                }
            }
        };
        let change = Change::new(
            Write::PutUser(user.clone()),
            AuditFact {
                action: "upsert_user",
                entity_type: "user",
                entity_id: user.email.clone(),
                details: Some(format!(
                    "role={},status={}",
                    self.role.as_str(),
                    self.status.as_str()
                )),
            },
        );
        Ok(Decision::new(user, change))
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/// Hard-delete a user. `email` must already be lowercased.
pub(super) struct DeleteUser {
    pub email: String,
}

impl Mutation for DeleteUser {
    type Output = ();
    type Reads = DirectoryReads;

    fn scope(&self) -> LockScope {
        LockScope::UserDirectory
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        directory_reads(set, &self.email)
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<()>> {
        let current = snapshot
            .get(reads.user)?
            .as_ref()
            .ok_or_else(|| NetcidrError::UserNotFound(self.email.clone()))?;
        guard_platform_admins(
            current,
            None,
            cx.caller(),
            *snapshot.get(reads.active_platform_admins)?,
        )?;
        let change = Change::new(
            Write::DeleteUser {
                email: self.email.clone(),
            },
            AuditFact {
                action: "delete_user",
                entity_type: "user",
                entity_id: self.email.clone(),
                details: None,
            },
        );
        Ok(Decision::new((), change))
    }
}

// ---------------------------------------------------------------------------
// One-shot seed from the env lists
// ---------------------------------------------------------------------------

/// Seed the directory from `(email, role, status)` triples exactly once per
/// database. Existing users are never overwritten, and when an email
/// appears more than once the first entry wins. Returns how many users were
/// added; 0 forever after the marker is written.
pub(super) struct SeedUsers {
    pub seeds: Vec<(String, Role, UserStatus)>,
}

pub(super) struct SeedReads {
    marker: Handle<bool>,
    users: Handle<Vec<UserRecord>>,
}

impl Mutation for SeedUsers {
    type Output = u64;
    type Reads = SeedReads;

    fn scope(&self) -> LockScope {
        LockScope::UserDirectory
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        SeedReads {
            marker: set.bootstrap_marker(USERS_ENV_SEED),
            users: set.users(),
        }
    }

    fn decide(
        self,
        reads: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<u64>> {
        if *snapshot.get(reads.marker)? {
            return Ok(Decision::unchanged(0));
        }
        let now = cx.now().to_rfc3339();
        let mut taken: HashSet<String> = snapshot
            .get(reads.users)?
            .iter()
            .map(|u| u.email.clone())
            .collect();

        let mut changes = Vec::new();
        for (email, role, status) in self.seeds {
            let email = email.to_ascii_lowercase();
            if !taken.insert(email.clone()) {
                continue;
            }
            let user = UserRecord {
                email: email.clone(),
                role,
                status,
                created_at: now.clone(),
                updated_at: now.clone(),
                created_by: Some("bootstrap".to_string()),
                updated_by: None,
            };
            changes.push(Change::new(
                Write::PutUser(user),
                AuditFact {
                    action: "seed_user",
                    entity_type: "user",
                    entity_id: email,
                    details: Some(format!("role={},status={}", role.as_str(), status.as_str())),
                },
            ));
        }
        let seeded = changes.len() as u64;
        changes.push(Change::new(
            Write::SetBootstrapMarker {
                key: USERS_ENV_SEED.to_string(),
                applied_at: now,
            },
            AuditFact {
                action: "seed_users",
                entity_type: "bootstrap_marker",
                entity_id: USERS_ENV_SEED.to_string(),
                details: Some(format!("seeded={seeded}")),
            },
        ));
        Ok(changes
            .into_iter()
            .fold(Decision::unchanged(seeded), Decision::and))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::ipam::mutation::UuidIds;
    use crate::ipam::store::Rows;

    fn noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
    }

    fn decide_as<M: Mutation>(
        caller: Option<&str>,
        m: M,
        rows: Vec<Rows>,
    ) -> Result<Decision<M::Output>> {
        let ctx = AuditContext {
            caller_email: caller.map(str::to_string),
            ..AuditContext::default()
        };
        let cx = DecideCtx::new(noon(), ctx, Arc::new(UuidIds));
        let mut set = ReadSet::default();
        let reads = m.reads(&mut set);
        m.decide(reads, &Snapshot::new(rows), &cx)
    }

    fn user(email: &str, role: Role, status: UserStatus) -> UserRecord {
        UserRecord {
            email: email.to_string(),
            role,
            status,
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            updated_at: "2026-01-01T00:00:00+00:00".to_string(),
            created_by: Some("bootstrap".to_string()),
            updated_by: None,
        }
    }

    fn admin(email: &str) -> UserRecord {
        user(email, Role::PlatformAdmin, UserStatus::Active)
    }

    fn upsert(email: &str, role: Role, status: UserStatus) -> UpsertUser {
        UpsertUser {
            email: email.to_string(),
            role,
            status,
        }
    }

    #[test]
    fn upsert_inserts_with_the_caller_as_creator() {
        let d = decide_as(
            Some("boss@x"),
            upsert("new@x", Role::Reader, UserStatus::Active),
            vec![Rows::User(None), Rows::Count(1)],
        )
        .unwrap();
        assert_eq!(d.output().created_by.as_deref(), Some("boss@x"));
        assert_eq!(d.output().updated_by, None);
        assert_eq!(d.output().created_at, noon().to_rfc3339());
    }

    #[test]
    fn upsert_update_keeps_creation_fields_and_stamps_the_updater() {
        let d = decide_as(
            None,
            upsert("dev@x", Role::Allocator, UserStatus::Disabled),
            vec![
                Rows::User(Some(user("dev@x", Role::Reader, UserStatus::Active))),
                Rows::Count(1),
            ],
        )
        .unwrap();
        assert_eq!(d.output().created_at, "2026-01-01T00:00:00+00:00");
        assert_eq!(d.output().created_by.as_deref(), Some("bootstrap"));
        assert_eq!(d.output().updated_by.as_deref(), Some("cli"));
        assert_eq!(d.output().updated_at, noon().to_rfc3339());
    }

    #[test]
    fn the_last_active_platform_admin_cannot_be_demoted_disabled_or_deleted() {
        for (role, status) in [
            (Role::Admin, UserStatus::Active),
            (Role::PlatformAdmin, UserStatus::Disabled),
        ] {
            let err = decide_as(
                None,
                upsert("only@x", role, status),
                vec![Rows::User(Some(admin("only@x"))), Rows::Count(1)],
            )
            .unwrap_err();
            assert!(matches!(err, NetcidrError::LastPlatformAdmin));
        }
        let err = decide_as(
            None,
            DeleteUser {
                email: "only@x".to_string(),
            },
            vec![Rows::User(Some(admin("only@x"))), Rows::Count(1)],
        )
        .unwrap_err();
        assert!(matches!(err, NetcidrError::LastPlatformAdmin));
    }

    #[test]
    fn a_platform_admin_cannot_demote_themselves_even_with_others_left() {
        let err = decide_as(
            Some("ME@x"),
            DeleteUser {
                email: "me@x".to_string(),
            },
            vec![Rows::User(Some(admin("me@x"))), Rows::Count(3)],
        )
        .unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn other_changes_pass_the_guards() {
        // Another admin remains.
        assert!(
            decide_as(
                Some("me@x"),
                DeleteUser {
                    email: "other@x".to_string()
                },
                vec![Rows::User(Some(admin("other@x"))), Rows::Count(2)],
            )
            .is_ok()
        );
        // Keeping a platform admin active is never a demotion.
        assert!(
            decide_as(
                Some("me@x"),
                upsert("me@x", Role::PlatformAdmin, UserStatus::Active),
                vec![Rows::User(Some(admin("me@x"))), Rows::Count(1)],
            )
            .is_ok()
        );
        // Missing user → NotFound, guards never consulted.
        let missing = decide_as(
            None,
            DeleteUser {
                email: "ghost@x".to_string(),
            },
            vec![Rows::User(None), Rows::Count(0)],
        );
        assert!(matches!(missing, Err(NetcidrError::UserNotFound(_))));
    }

    fn seed(seeds: &[(&str, Role)]) -> SeedUsers {
        SeedUsers {
            seeds: seeds
                .iter()
                .map(|(e, r)| (e.to_string(), *r, UserStatus::Active))
                .collect(),
        }
    }

    #[test]
    fn seed_skips_existing_and_repeated_emails_and_writes_the_marker() {
        let d = decide_as(
            None,
            seed(&[
                ("Boss@X", Role::PlatformAdmin),
                ("boss@x", Role::Reader),
                ("old@x", Role::Reader),
                ("dev@x", Role::Allocator),
            ]),
            vec![
                Rows::Flag(false),
                Rows::Users(vec![user("old@x", Role::Admin, UserStatus::Active)]),
            ],
        )
        .unwrap();
        assert_eq!(*d.output(), 2, "boss@x once, dev@x; old@x untouched");
        assert_eq!(d.changes().len(), 3, "two users plus the marker");
    }

    #[test]
    fn seed_is_a_no_op_once_the_marker_exists() {
        let d = decide_as(
            None,
            seed(&[("late@x", Role::PlatformAdmin)]),
            vec![Rows::Flag(true), Rows::Users(vec![])],
        )
        .unwrap();
        assert_eq!(*d.output(), 0);
        assert!(d.changes().is_empty());
    }
}
