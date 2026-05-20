# RBAC: roles come from per-user email config; extractors are per-handler

**Status:** Accepted
**Date:** 2026-05-20
**Issue:** [#102](https://github.com/wingnut128/netcidr/issues/102)
**Related:** [[ADR-0001 — Tenancy via explicit parameter]](./0001-tenancy-via-explicit-parameter.md)

## Decision

Role-based authorization for the IPAM HTTP API is gated at the handler
boundary by three explicit Axum extractors — `RequireReader`,
`RequireAllocator`, `RequireAdmin` — defined in `src/authorization.rs`.
Every IPAM handler signature names exactly one of them. The principal's
role is derived once at authentication time from per-user email lists in
`AuthConfig` (`admin_emails`, `allocator_emails`, `reader_emails`, with
admin > allocator > reader > Default precedence) and stamped onto the
`AuthenticatedPrincipal` extension by `AuthConfig::finalize_principal`.

For PR1 the resolution defaults to `Role::Admin` when the principal's
email is in none of the lists, so existing deployments retain full
access until operators explicitly downgrade users. A follow-on PR will
flip the default to `Role::Reader` once every IPAM route has shipped
with an explicit gate and the production allowlist has been migrated.

## Why per-handler, not per-router-group

The router-group alternative is to split `create_ipam_router` into
three sub-routers (`/ipam/read*`, `/ipam/write*`, `/ipam/admin*`), each
with its own role-checking middleware. It collapses ~19 handler signature
edits to three middleware layers.

Rejected because:

- **Adding a new endpoint is silently default-permissive.** Forgetting
  to mount a handler under the right sub-router opens it to every role.
  The compiler offers nothing. With per-handler extractors, the
  extractor parameter is part of the function signature — leaving it
  off makes the handler unreachable from the router (which expects the
  extractor's input type to be `()`), or the route mounts and the
  reviewer sees a handler with no role parameter in the diff. Either
  way the omission is visible.
- **Routes don't slice cleanly by verb.** `POST /ipam/cidr-blocks` is
  Admin, `POST /ipam/cidr-blocks/{id}/allocate-specific` is Allocator,
  `POST /ipam/allocations/{id}/release` is Allocator — verb prefixes
  would mislead. A read like `GET /ipam/audit` is Admin-only. Grouping
  forces awkward sub-route names.
- **The repetition cost is small.** 19 handlers × one extractor
  parameter is not the friction it might seem; the handlers already
  carry four to six positional extractors, so one more doesn't add
  meaningful noise.

## Why per-user email config, not per-PAT

The per-PAT alternative stores a `role` column on
`personal_access_tokens` and lets the mint flow accept a `--role` flag,
so a user with full admin rights can mint a `reader` PAT for a CI
script. That is the long-term-correct model but requires:

- A schema migration on the PAT table (both backends).
- Mint-flow changes (`POST /me/tokens` body, CLI flag, dashboard UI).
- A resolution rule for how PAT role interacts with the owner's role.

PR1 keeps the scope tight by deriving role from the user's email
only. Per-PAT role downgrade is the explicit subject of PR3 (with the
resolution rule `effective_role = min(user_role, pat_role)` — PATs can
narrow privileges but never widen them).

## Why default-Admin for PR1, not default-Reader

The strictly-correct security default is `Reader` — least privilege,
deny unless explicitly granted. Shipping that in the same PR that
introduces the role types means every existing deployment loses access
on upgrade until operators add the new env vars. For a single-operator
deploy (the common case) that means setting both
`NETCIDR_ADMIN_EMAILS` and the new `NETCIDR_ALLOCATOR_EMAILS` /
`NETCIDR_READER_EMAILS` in the same maintenance window, with no
warning.

PR1 ships the seam with `Default::default() = Admin` so the upgrade is
a no-op. PR2 (separately reviewable, ~one-line code change plus
deploy-config migration) flips the default. Splitting the change makes
the *policy* flip independently rollback-able from the *mechanism*
introduction.

## Why a fixed-safe 403 body

Denial responses carry `{"error":"Forbidden"}` and nothing else. The
required and actual roles are logged server-side (at WARN, with the
actor's email) but not echoed to the client. Two reasons:

- **Avoid leaking the access matrix.** An attacker probing endpoints
  who learns "you need Admin for this" gets a free lateral-movement
  hint. The role required for each endpoint is not a secret per se,
  but giving it away in 403 responses normalises that posture and
  makes auto-recon scripts more efficient.
- **Audit clarity at the boundary.** The single fixed string means
  one log search pattern catches every denial. Per-endpoint customised
  messages drift over time.

The cost is a slightly worse caller debugging experience. That is
acceptable for a security boundary — debugging RBAC issues is an
operator-side activity (the operator has access to the logs that
contain the actor + required + actual values).

## Missing-principal → 500, not 401

If the role extractor runs without an `AuthenticatedPrincipal` in
request extensions, the request returns 500 `"internal server error"`.
That state implies `require_auth` did not run upstream — i.e. the
router was wired without the auth middleware layer. The mistake is on
the server side; the caller cannot fix it by retrying with a token, so
401 (which suggests they can) would mislead. The extractor logs at
`tracing::error` to make the wiring bug obvious in operator logs.

## Revisiting

Revisit if any of the following becomes true:

1. **A real authorization bypass ships** despite the extractor — e.g.
   a handler that takes `RequireReader` but accepts mutations because
   it ignores the principal and trusts the body. The extractor proves
   only that *some* tier was checked; it does not enforce the action's
   semantic class. Tighter "verbs vs roles" coupling (or per-action
   capability tokens) may be needed.
2. **Routes proliferate enough** (≥40 IPAM handlers) that the
   per-handler repetition becomes meaningful noise. At that scale the
   router-group alternative or a procedural macro may pay rent.
3. **Per-PAT roles ship (PR3)** and the resolution rule turns out to
   need per-request context (e.g. role narrowed by tenant) that
   `finalize_principal` cannot express. That would push role
   resolution out of `AuthConfig` into a per-request capability
   evaluator.
4. **An external policy engine** (OPA, Cedar) is introduced. Then
   `Require*` extractors become thin adapters that delegate to it; the
   per-user email config gets retired in favour of policy bundles.

Marginal ergonomic improvements (e.g. "the macro defining the three
extractors is too clever") are not reasons to revisit on their own.
