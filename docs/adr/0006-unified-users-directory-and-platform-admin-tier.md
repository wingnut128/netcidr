# Unified users directory in the DB; Platform Admin tier above Admin

**Status:** Accepted
**Date:** 2026-07-16
**Issue:** [#300](https://github.com/wingnut128/netcidr/issues/300) (ENG-120)
**Related:** [[ADR-0002 — RBAC role config and per-handler extractors]](./0002-rbac-role-config-and-per-handler-extractors.md), [[ADR-0003 — Role membership in DB with env bootstrap]](./0003-role-membership-in-db-with-env-bootstrap.md), [[ADR-0001 — Tenancy via explicit parameter]](./0001-tenancy-via-explicit-parameter.md)

## Context

ADR-0003 moved *roles* into the DB but explicitly left the *allowlist*
(`NETCIDR_OIDC_ALLOWED_EMAILS`) env-sourced — changing who may sign in
required a `netcidr-deploy` edit and a Lambda redeploy. It also listed a
"founding admin" tier as a follow-up: `Role::Admin` conflated platform
powers (managing `/admin/users`) with tenant-data admin powers, so any
admin could grant or revoke anyone.

Two conceptually-one records also lived in two places: an allowlist entry
("may this email sign in?") and a role grant ("what may they do?") could
drift — allowlisted but role-less, or role-listed but unable to sign in.

## Decision

1. **Unified `users` table** (migration 013, SQLite + Postgres):
   `email PK, role, status ('active'|'disabled'), created_at, updated_at,
   created_by, updated_by`. One row is the whole story for a user:
   *allowlisted* = an active row exists; the role lives on the same row.
   Replaces both the env allowlist and `role_assignments`.

2. **`Role::PlatformAdmin` above `Admin`** in the existing enum (Ord
   intact, serde `snake_case` — byte-identical wire format for the old
   variants). Platform Admins own the user directory (`/admin/users` is
   `RequirePlatformAdmin`); `Admin` becomes the tenant-space data admin
   (CIDR-block create/delete, audit — unchanged surface). Roles remain
   **global** per ADR-0003 §3; per-tenant roles stay out of scope.

3. **Allowlist semantics** (single `resolve_access` fetch per request):
   - `status = 'disabled'` → denied, always — sessions *and* PATs; an
     explicit deny beats the open-mode default.
   - **Open mode** iff the env allowlist resolves empty (unchanged
     dev/loopback behavior; no per-request COUNT): any verified principal
     is allowed, role = row's role if present else Reader.
   - **Closed mode**: allowed iff an active row exists.
   - Store read errors fail closed. Store-less deployments (bearer-only /
     non-IPAM) keep the in-memory env-list behavior verbatim.

4. **Bootstrap = one-shot marker, not seed-if-empty.** Migration 013
   copies `role_assignments` in, so the table is non-empty on upgraded
   deployments — but allowlist-only emails (no role row) still need rows.
   `seed_users_once` is guarded by `bootstrap_markers['users_env_seed']`
   and runs exactly once per database: `ADMIN_EMAILS → platform_admin`,
   allocator/reader lists at their tiers, remaining allowlist entries →
   active `reader`. A role-listed email absent from a non-empty allowlist
   seeds **disabled** (it had no access before; seeding it active would
   silently widen access). After the marker, env vars are ignored forever.

5. **Existing `admin` rows promote to `platform_admin`** in the
   migration. Pre-split Admins held user-management power; demoting them
   would strand a deployed system with zero platform admins and no API
   path to create one. Operators can create narrower tenant-Admins
   afterwards.

6. **PATs are capped at `admin`.** The PAT role CHECK still excludes
   `platform_admin`; mint requests clamp. User-directory management is
   only reachable through an interactive OIDC session, the bearer-mode
   carve-out, or the CLI — never a long-lived token. Consequently
   `min(owner_role, pat_role) ≤ admin` always.

7. **Bearer carve-out extends to PlatformAdmin.** `email = None`
   resolves to the top tier for the same reasons as ADR-0002: bearer mode
   is the single-operator model, and dropping it to Admin would silently
   strip user management from bearer deployments on upgrade.

8. **Guards** (shared by upsert and delete): the last **active**
   platform admin cannot be deleted, disabled, or demoted
   (`LastPlatformAdmin` → 409); an authenticated platform admin cannot
   delete/disable/demote **their own** row. The CLI actor (`"cli"`)
   bypasses only the self-guard — CLI-on-the-DB-host is the documented
   lockout-recovery path. Plain Admins are freely revocable (they hold no
   platform power, so no lockout is possible).

9. **Surface convergence**: `GET/POST(upsert)/DELETE /admin/users` with
   `UserRecord`/`UserList`/`UpsertUserRequest`; **`GET /admin/allowlist`
   is removed** (the dashboard was its only consumer). CLI:
   `netcidr admin user add|disable|enable|remove|list` (`grant`/`revoke`
   aliases kept). Dashboard: the Allowlist page is deleted; Users is the
   single directory page, gated by the new `/me.is_platform_admin`.
   Disable is the soft remove (data intact, re-enable restores access —
   matching the 2026-05-02 spec); hard delete also leaves tenant data
   untouched (tenant_id is just the email string).

## Consequences

- Access changes are immediate, survive restarts, and need no redeploy;
  disabling a user kills their sessions and PATs on the next request.
- `role_assignments` is **kept frozen** (not dropped) so a binary
  rollback still finds its table; new code never touches it. Dropping it
  is deferred to a later release (follow-up migration).
- One indexed PK read per authenticated request (same budget as
  ADR-0003; the allowlist check now shares the role lookup's fetch).
- The env vars must remain set in `netcidr-deploy` through the upgrade
  release so the one-shot top-up can seed allowlist-only users; after
  that they are inert and can be cleaned up.

## Out of scope (follow-ups)

Per-tenant roles and multi-user workspaces (future
`workspace_memberships(email, workspace_id, role)` join table — nothing
in this schema blocks it); `DROP TABLE role_assignments`; a TTL cache
for user lookups; bulk import.
