# Tenancy is threaded as an explicit parameter, not a task-local

**Status:** Accepted
**Date:** 2026-05-12
**Source:** [`docs/superpowers/specs/2026-05-02-multi-tenant-isolation-design.md`](../superpowers/specs/2026-05-02-multi-tenant-isolation-design.md)

Every `IpamOps` and `IpamStore` method that touches tenant-scoped data takes
`tenant_id: &str` as an explicit parameter. There is no task-local or other
ambient channel for tenant identity inside `IpamOps`. HTTP handlers extract a
`Tenant` value from request extensions (via `src/tenant.rs::Tenant` and the
`require_auth` middleware) and pass `tenant.as_str()` at the call site; the
CLI and local MCP backend pass `Tenant::LOCAL`.

## Why

The worst class of bug in this system is a silent cross-tenant data leak —
a query that ships without `WHERE tenant_id = ?` and returns another
tenant's rows. The type system is the strongest defense: every method
signature requires the parameter, and any new query that doesn't filter on
it is a code-review red flag rather than a silent failure. Task-local
tenancy would make the bug invisible at the call site.

## Considered and rejected: task-local tenant context

Modeled after `src/audit_context.rs`, which is a task-local. Surface
appeal: collapses 85+ positional `tenant_id` arguments in `operations.rs`
and removes the duplicated `"local"` constant at frontend boundaries.

Rejected because:

- **Silent failure mode.** A task-local that isn't set returns
  `Default::default()`; a missing `tenant_id` parameter is a compile error.
  The default of `audit_context` (all `None`) is harmless because audit
  fields are observational; the default of a `tenant_context` would be a
  cross-tenant leak.
- **Code review surface.** With explicit parameters, `git diff` of a new
  query shows the tenant filter or shows its absence. With a task-local,
  the filter is woven into store implementations and easy to forget.
- **Ergonomics gain is small.** The 85 mentions in `operations.rs` are
  mostly internal threading between operation helpers — not friction that
  comes home to roost. The seam-level duplicated `"local"` constant is
  fixed by a single `Tenant::LOCAL`, not by hiding state.

## Consequences

- The ~85 `tenant_id: &str` thread-throughs in `src/ipam/operations.rs` are
  intentional. Architecture reviews that propose collapsing them into a
  task-local should be rejected with a pointer to this ADR.
- New frontends (gRPC, GraphQL, MCP variants) must extract or supply the
  tenant explicitly at every call site. Use `Tenant::LOCAL` for
  single-tenant frontends; extract per-request for multi-tenant ones.
- Internal helper functions inside `operations.rs` that don't touch the
  store but compose over tenant-scoped values still carry the parameter,
  for consistency and to avoid creating a half-explicit half-implicit
  surface.

## Revisiting

Revisit only if one of the following becomes true:

1. A real cross-tenant leak ships *despite* the type-checked parameter
   (e.g., a `WHERE` clause is omitted in a backend implementation), proving
   the parameter alone isn't enough and we need to add (not replace it
   with) further defenses.
2. A new frontend or call shape makes explicit threading genuinely
   awkward in a way `Tenant::LOCAL` can't address.
3. The operations module splits into many sub-modules where the parameter
   creates real ceremony.

Marginal ergonomic improvement on its own is not a reason to revisit.
