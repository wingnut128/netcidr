//! First-boot seeding of the users directory from the env lists (ADR-0006).
//!
//! Shared by `netcidr serve` (`main.rs`) and the Lambda binary so the two
//! startup paths cannot drift. The seed is one-shot: it runs exactly once
//! per database, guarded by the `bootstrap_markers` table (see
//! [`IpamStore::seed_users_once`]) — after that the DB is the source of
//! truth and the env lists are ignored.

use std::sync::Arc;

use crate::auth::Role;
use crate::config::ServerConfig;
use crate::ipam::models::UserStatus;
use crate::ipam::store::IpamStore;

/// Build the `(email, role, status)` seed triples from the env/config lists.
///
/// - `NETCIDR_ADMIN_EMAILS` → `platform_admin` (the founding-owner tier:
///   pre-split Admins held user-management power, and a fresh install must
///   boot with at least one platform admin or user management would be
///   unreachable from the API).
/// - `NETCIDR_ALLOCATOR_EMAILS` → `allocator`, `NETCIDR_READER_EMAILS` →
///   `reader`.
/// - Every `NETCIDR_OIDC_ALLOWED_EMAILS` entry not already seeded →
///   `reader` (they had default-Reader access before the directory
///   existed).
///
/// Ordering is first-write-wins per email (the store seed uses
/// `ON CONFLICT DO NOTHING`), so a stronger role wins when an email
/// appears in multiple lists.
///
/// Status: when the env allowlist is **non-empty**, a role-listed email
/// that is *not* in it is seeded `disabled` — that email has no access
/// today (allowlist and role lists were checked independently), and
/// seeding it active would silently widen access. Everything else seeds
/// `active`.
pub fn user_seed_triples(config: &ServerConfig) -> Vec<(String, Role, UserStatus)> {
    let allowlist: Vec<String> = config
        .oidc_allowed_emails()
        .into_iter()
        .map(|e| e.to_ascii_lowercase())
        .collect();
    let status_for = |email: &str| -> UserStatus {
        if allowlist.is_empty() || allowlist.iter().any(|a| a == email) {
            UserStatus::Active
        } else {
            UserStatus::Disabled
        }
    };

    let mut seeds: Vec<(String, Role, UserStatus)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut push = |email: String, role: Role, seeds: &mut Vec<(String, Role, UserStatus)>| {
        let needle = email.to_ascii_lowercase();
        if seen.iter().any(|s| s == &needle) {
            return;
        }
        let status = status_for(&needle);
        seen.push(needle.clone());
        seeds.push((needle, role, status));
    };

    for e in config.admin_emails() {
        push(e, Role::PlatformAdmin, &mut seeds);
    }
    for e in config.allocator_emails() {
        push(e, Role::Allocator, &mut seeds);
    }
    for e in config.reader_emails() {
        push(e, Role::Reader, &mut seeds);
    }
    for e in &allowlist {
        push(e.clone(), Role::Reader, &mut seeds);
    }
    seeds
}

/// Run the one-shot users-directory seed. Logs the outcome; a seed failure
/// is a warning, not a startup abort — the operator can still recover via
/// the CLI, and refusing to serve would turn a transient DB hiccup into an
/// outage.
pub async fn seed_users(store: &Arc<dyn IpamStore>, config: &ServerConfig) {
    let seeds = user_seed_triples(config);
    match store.seed_users_once(&seeds).await {
        Ok(n) if n > 0 => tracing::info!("seeded {n} user(s) from env lists"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "users directory bootstrap seed failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(
        allowed: &[&str],
        admins: &[&str],
        allocators: &[&str],
        readers: &[&str],
    ) -> ServerConfig {
        ServerConfig {
            oidc_allowed_emails: allowed.iter().map(|s| s.to_string()).collect(),
            admin_emails: admins.iter().map(|s| s.to_string()).collect(),
            oidc_allocator_emails: allocators.iter().map(|s| s.to_string()).collect(),
            oidc_reader_emails: readers.iter().map(|s| s.to_string()).collect(),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn admins_seed_platform_admin_and_allowlist_only_seeds_reader() {
        let cfg = config(&["Boss@X", "viewer@x"], &["boss@x"], &[], &[]);
        let seeds = user_seed_triples(&cfg);
        assert_eq!(
            seeds,
            vec![
                ("boss@x".into(), Role::PlatformAdmin, UserStatus::Active),
                ("viewer@x".into(), Role::Reader, UserStatus::Active),
            ]
        );
    }

    #[test]
    fn role_listed_email_missing_from_allowlist_seeds_disabled() {
        // ops@x has a role but is NOT allowlisted — it has no access today,
        // so it must not gain any via the seed.
        let cfg = config(&["boss@x"], &["boss@x"], &["ops@x"], &[]);
        let seeds = user_seed_triples(&cfg);
        assert_eq!(
            seeds,
            vec![
                ("boss@x".into(), Role::PlatformAdmin, UserStatus::Active),
                ("ops@x".into(), Role::Allocator, UserStatus::Disabled),
            ]
        );
    }

    #[test]
    fn empty_allowlist_seeds_everyone_active_and_strongest_role_wins() {
        // Open mode: no allowlist. An email in several role lists takes the
        // strongest (first-pushed) role.
        let cfg = config(&[], &["dual@x"], &["dual@x"], &["viewer@x"]);
        let seeds = user_seed_triples(&cfg);
        assert_eq!(
            seeds,
            vec![
                ("dual@x".into(), Role::PlatformAdmin, UserStatus::Active),
                ("viewer@x".into(), Role::Reader, UserStatus::Active),
            ]
        );
    }
}
