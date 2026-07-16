//! Ops-layer tests for the users directory (ADR-0006): upsert/delete with
//! the platform-admin safety rails, and the audit trail they leave.
//!
//! The two guards under test:
//! 1. Last-active-platform-admin — deleting, disabling, or demoting the
//!    only active platform admin returns `LastPlatformAdmin` (409 at the
//!    API layer).
//! 2. Self-protection — an authenticated platform admin cannot delete,
//!    disable, or demote their own row. The CLI actor carries no caller
//!    email, so it is exempt (the documented lockout-recovery path).

use std::sync::Arc;

use netcidr::audit_context::{AuditContext, scope};
use netcidr::auth::Role;
use netcidr::error::NetcidrError;
use netcidr::ipam::models::UserStatus;
use netcidr::ipam::operations::IpamOps;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use netcidr::tenant::Tenant;

async fn ops() -> IpamOps {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    IpamOps::new(store)
}

fn ctx_for(email: &str) -> AuditContext {
    AuditContext {
        caller_sub: Some(format!("sub-{email}")),
        caller_email: Some(email.to_string()),
        source_ip: None,
        request_id: None,
        auth_method: Some("oidc".to_string()),
        pat_id: None,
    }
}

const TENANT: &str = Tenant::LOCAL;

#[tokio::test]
async fn upsert_and_delete_round_trip_with_audit_actor() {
    let ops = ops().await;

    let created = scope(ctx_for("owner@x.test"), async {
        ops.upsert_user(TENANT, "New@X.test", Role::Reader, UserStatus::Active)
            .await
    })
    .await
    .unwrap();
    assert_eq!(created.email, "new@x.test", "email must be lowercased");
    assert_eq!(created.created_by.as_deref(), Some("owner@x.test"));

    // Update flips status and stamps updated_by.
    let updated = scope(ctx_for("owner@x.test"), async {
        ops.upsert_user(TENANT, "new@x.test", Role::Reader, UserStatus::Disabled)
            .await
    })
    .await
    .unwrap();
    assert_eq!(updated.status, UserStatus::Disabled);
    assert_eq!(updated.updated_by.as_deref(), Some("owner@x.test"));

    ops.delete_user(TENANT, "new@x.test").await.unwrap();
    let err = ops.delete_user(TENANT, "new@x.test").await.unwrap_err();
    assert!(matches!(err, NetcidrError::UserNotFound(_)));
}

#[tokio::test]
async fn last_platform_admin_cannot_be_deleted_disabled_or_demoted() {
    let ops = ops().await;
    ops.upsert_user(
        TENANT,
        "solo@x.test",
        Role::PlatformAdmin,
        UserStatus::Active,
    )
    .await
    .unwrap();

    // Delete refused.
    let err = ops.delete_user(TENANT, "solo@x.test").await.unwrap_err();
    assert!(matches!(err, NetcidrError::LastPlatformAdmin), "{err:?}");

    // Disable refused.
    let err = ops
        .upsert_user(
            TENANT,
            "solo@x.test",
            Role::PlatformAdmin,
            UserStatus::Disabled,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, NetcidrError::LastPlatformAdmin), "{err:?}");

    // Demote refused.
    let err = ops
        .upsert_user(TENANT, "solo@x.test", Role::Admin, UserStatus::Active)
        .await
        .unwrap_err();
    assert!(matches!(err, NetcidrError::LastPlatformAdmin), "{err:?}");

    // A no-op upsert of the same role+status is fine.
    ops.upsert_user(
        TENANT,
        "solo@x.test",
        Role::PlatformAdmin,
        UserStatus::Active,
    )
    .await
    .unwrap();

    // With a second active platform admin, the first becomes mutable.
    ops.upsert_user(
        TENANT,
        "second@x.test",
        Role::PlatformAdmin,
        UserStatus::Active,
    )
    .await
    .unwrap();
    ops.upsert_user(TENANT, "solo@x.test", Role::Admin, UserStatus::Active)
        .await
        .unwrap();
}

#[tokio::test]
async fn disabled_platform_admin_does_not_satisfy_the_last_admin_count() {
    let ops = ops().await;
    ops.upsert_user(
        TENANT,
        "active@x.test",
        Role::PlatformAdmin,
        UserStatus::Active,
    )
    .await
    .unwrap();
    ops.upsert_user(
        TENANT,
        "frozen@x.test",
        Role::PlatformAdmin,
        UserStatus::Disabled,
    )
    .await
    .unwrap();

    // frozen@x is a platform admin but disabled — deleting active@x would
    // still leave zero ACTIVE platform admins, so it must be refused.
    let err = ops.delete_user(TENANT, "active@x.test").await.unwrap_err();
    assert!(matches!(err, NetcidrError::LastPlatformAdmin), "{err:?}");
}

#[tokio::test]
async fn platform_admin_cannot_remove_disable_or_demote_self() {
    let ops = ops().await;
    ops.upsert_user(TENANT, "a@x.test", Role::PlatformAdmin, UserStatus::Active)
        .await
        .unwrap();
    ops.upsert_user(TENANT, "b@x.test", Role::PlatformAdmin, UserStatus::Active)
        .await
        .unwrap();

    // Two active platform admins exist, so only the self-guard can fire.
    let err = scope(ctx_for("a@x.test"), async {
        ops.delete_user(TENANT, "a@x.test").await
    })
    .await
    .unwrap_err();
    assert!(
        matches!(err, NetcidrError::InvalidInput(ref m) if m.contains("your own")),
        "{err:?}"
    );
    let err = scope(ctx_for("a@x.test"), async {
        ops.upsert_user(TENANT, "A@X.test", Role::Admin, UserStatus::Active)
            .await
    })
    .await
    .unwrap_err();
    assert!(
        matches!(err, NetcidrError::InvalidInput(ref m) if m.contains("your own")),
        "{err:?}"
    );

    // ...but a@x may remove b@x (peer removal is allowed).
    scope(ctx_for("a@x.test"), async {
        ops.delete_user(TENANT, "b@x.test").await
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cli_actor_bypasses_self_guard_but_not_last_admin_guard() {
    let ops = ops().await;
    ops.upsert_user(TENANT, "a@x.test", Role::PlatformAdmin, UserStatus::Active)
        .await
        .unwrap();
    ops.upsert_user(TENANT, "b@x.test", Role::PlatformAdmin, UserStatus::Active)
        .await
        .unwrap();

    // No audit context (CLI shape): removing a platform admin is allowed
    // while another active one remains…
    ops.delete_user(TENANT, "b@x.test").await.unwrap();
    // …but the last one is still protected.
    let err = ops.delete_user(TENANT, "a@x.test").await.unwrap_err();
    assert!(matches!(err, NetcidrError::LastPlatformAdmin), "{err:?}");
}

#[tokio::test]
async fn non_admin_users_are_freely_mutable() {
    let ops = ops().await;
    ops.upsert_user(
        TENANT,
        "root@x.test",
        Role::PlatformAdmin,
        UserStatus::Active,
    )
    .await
    .unwrap();
    // Tenant-space Admins carry no platform power and get no guard.
    ops.upsert_user(
        TENANT,
        "tenant-admin@x.test",
        Role::Admin,
        UserStatus::Active,
    )
    .await
    .unwrap();
    scope(ctx_for("tenant-admin@x.test"), async {
        ops.delete_user(TENANT, "tenant-admin@x.test").await
    })
    .await
    .expect("a tenant admin's own row is not platform-guarded");
}
