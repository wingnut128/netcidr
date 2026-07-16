//! Upgrade rehearsal for the users-directory release (ADR-0006).
//!
//! Simulates the deployed Lambda's database crossing the release boundary:
//! a DB created by the *previous* release (schema at migration 12, with
//! `role_assignments` rows) is booted by the *new* code — migration 013
//! runs, then the one-shot env seed tops up allowlist-only users. Asserts
//! every promise in the lockout risk register:
//!
//! 1. Existing `admin` rows promote to `platform_admin`.
//! 2. Allowlist-only emails (no role row before) get active reader rows.
//! 3. The bootstrap marker is written; a second boot seeds nothing.
//! 4. `role_assignments` is left untouched (binary-rollback safety).
//! 5. A role-listed email absent from the allowlist seeds disabled.

use std::sync::Arc;

use netcidr::auth::Role;
use netcidr::config::ServerConfig;
use netcidr::ipam::bootstrap::seed_users;
use netcidr::ipam::models::UserStatus;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;

/// Build a SQLite DB exactly as the previous release left it: migrations
/// 1..=12 applied (schema_version rows included, so the new binary only
/// applies 013) and `role_assignments` populated.
fn previous_release_db(path: &str) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    for &(version, sql) in netcidr::ipam::sqlite::migrations::MIGRATIONS {
        if version >= 13 {
            break;
        }
        conn.execute_batch(sql).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?1, '2026-06-01T00:00:00Z')",
            rusqlite::params![version],
        )
        .unwrap();
    }
    conn.execute_batch(
        r#"INSERT INTO role_assignments (email, role, created_at, updated_at, created_by)
           VALUES ('mlapane@gmail.com',     'admin',  '2026-05-29T00:00:00Z', '2026-05-29T00:00:00Z', 'bootstrap'),
                  ('mike@cloudreaper.dev',  'admin',  '2026-05-29T00:00:00Z', '2026-05-29T00:00:00Z', 'bootstrap')"#,
    )
    .unwrap();
    conn
}

/// The prod-shaped env: both admins allowlisted, plus one allowlist-only
/// viewer with no role row, plus one role-listed email NOT in the
/// allowlist (must seed disabled).
fn prod_shaped_config() -> ServerConfig {
    ServerConfig {
        oidc_allowed_emails: vec![
            "mlapane@gmail.com".to_string(),
            "mike@cloudreaper.dev".to_string(),
            "viewer@example.com".to_string(),
        ],
        admin_emails: vec![
            "mlapane@gmail.com".to_string(),
            "mike@cloudreaper.dev".to_string(),
        ],
        oidc_allocator_emails: vec!["robot@example.com".to_string()],
        ..ServerConfig::default()
    }
}

#[tokio::test]
async fn deployed_db_upgrades_without_lockout() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("upgrade.db");
    let db_path = db_path.to_str().unwrap();
    drop(previous_release_db(db_path));

    // ── First boot of the new release ──────────────────────────────────
    let store = SqliteStore::new(db_path).unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap(); // applies only migration 013
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let config = prod_shaped_config();
    seed_users(&store, &config).await;

    // 1. Admins promoted, active, provenance preserved.
    for admin in ["mlapane@gmail.com", "mike@cloudreaper.dev"] {
        let u = store.get_user(admin).await.unwrap().unwrap();
        assert_eq!(u.role, Role::PlatformAdmin, "{admin} must promote");
        assert_eq!(u.status, UserStatus::Active);
        assert_eq!(
            u.created_at, "2026-05-29T00:00:00Z",
            "migration copy, not seed"
        );
    }

    // 2. Allowlist-only email topped up as an active reader.
    let viewer = store.get_user("viewer@example.com").await.unwrap().unwrap();
    assert_eq!(viewer.role, Role::Reader);
    assert_eq!(viewer.status, UserStatus::Active);
    assert_eq!(viewer.created_by.as_deref(), Some("bootstrap"));

    // 5. Role-listed but not allowlisted → disabled (no silent widening).
    let robot = store.get_user("robot@example.com").await.unwrap().unwrap();
    assert_eq!(robot.role, Role::Allocator);
    assert_eq!(robot.status, UserStatus::Disabled);

    assert_eq!(store.count_active_platform_admins().await.unwrap(), 2);

    // ── Second boot (warm restart / new Lambda instance) ───────────────
    // Delete the viewer first: seed-if-empty semantics would resurrect
    // them; the marker must not.
    store.delete_user("viewer@example.com").await.unwrap();
    seed_users(&store, &config).await;
    assert!(
        store
            .get_user("viewer@example.com")
            .await
            .unwrap()
            .is_none(),
        "marker must make the env seed one-shot; deletions are permanent"
    );

    // 4. role_assignments untouched for binary rollback.
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let legacy: i64 = conn
        .query_row("SELECT COUNT(*) FROM role_assignments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        legacy, 2,
        "frozen role_assignments must survive the upgrade"
    );
    let legacy_role: String = conn
        .query_row(
            "SELECT role FROM role_assignments WHERE email = 'mlapane@gmail.com'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        legacy_role, "admin",
        "legacy rows keep their pre-split role"
    );
}
