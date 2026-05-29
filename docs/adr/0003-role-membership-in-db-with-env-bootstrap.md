# Role membership lives in the DB; env vars are a first-start bootstrap seed

**Status:** Accepted
**Date:** 2026-05-29
**Issue:** [#215](https://github.com/wingnut128/netcidr/issues/215) (ENG-88), part of [#102](https://github.com/wingnut128/netcidr/issues/102)
**Related:** [[ADR-0002 — RBAC role config and per-handler extractors]](./0002-rbac-role-config-and-per-handler-extractors.md), [[ADR-0001 — Tenancy via explicit parameter]](./0001-tenancy-via-explicit-parameter.md)

## Context

ADR-0002 resolved a caller's role from three env-var email lists
(`NETCIDR_ADMIN_EMAILS` / `NETCIDR_ALLOCATOR_EMAILS` / `NETCIDR_READER_EMAILS`)
held in memory on `AuthConfig`. Changing who has access meant editing
`netcidr-deploy` and redeploying the Lambda — high friction for day-to-day
access management, and it required infra access for a routine RBAC change.

## Decision

Move role membership into a global `role_assignments(email, role, …)` table
(migration 011), managed at runtime via `/admin/users` (REST), `netcidr admin
user grant/revoke/list` (CLI), and a dashboard Users page. Env vars become a
**bootstrap seed only**.

1. **Bootstrap = seed-if-empty.** On startup, if `role_assignments` is empty,
   it is seeded from the env lists; once it has any rows, the env lists are
   ignored. The DB is the source of truth thereafter. This keeps first-deploy
   working from env while making the DB authoritative.

2. **Resolution reads the DB per request.** `AuthConfig::role_for_email`
   became `async`; when an IPAM store is attached it resolves via
   `store.get_role_for_email` (a single indexed PK lookup). This is correct
   across multiple Lambda execution environments — a startup in-memory cache
   would let a grant on one instance go unseen by warm instances until a cold
   start. A no-store fallback to the in-memory env lists is preserved for
   bearer-only / non-IPAM deployments, so their behavior is unchanged. The
   bearer-mode `email = None → Admin` carve-out from ADR-0002 is retained.

3. **Scope = global.** An email maps to one role system-wide, matching the
   prior env-list semantics. Data isolation remains tenant-scoped (ADR-0001);
   roles govern *what actions* an identity may take, not *which data*. The
   table is intentionally **not** tenant-scoped.

4. **Grant policy = any admin grants any role, with guards.** Any admin may
   grant or revoke any role (including Admin). Two safety rails prevent
   lockout: the **last remaining admin** cannot be revoked
   (`NetcidrError::LastAdmin` → 409), and an authenticated caller cannot
   revoke **their own** admin role (the CLI actor is `"cli"` and never matches
   an email, so CLI is bound only by the last-admin guard).

5. **Audit.** Every grant/revoke writes an `audit_log` row with
   `entity_type = "role_assignment"`, so changes appear in the per-user
   Activity view (ENG-89 / #212), scoped to the acting admin's tenant.

## Consequences

- Role changes are immediate and survive restarts, with no redeploy.
- One extra indexed DB read on the authenticated request path; acceptable at
  current volume. A short TTL cache is a possible future optimization (out of
  scope).
- The **allowlist** (`/admin/allowlist`, `NETCIDR_OIDC_ALLOWED_EMAILS`) is a
  separate concern and remains env-sourced; this ADR covers *roles* only.

## Out of scope (follow-ups)

Per-tenant roles; a "founding admin" tier; a TTL cache for role lookups; bulk
import; DB-backed mutable allowlist.
