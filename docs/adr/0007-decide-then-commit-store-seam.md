# IPAM writes are decide-then-commit units under one lock scope

**Status:** Accepted
**Date:** 2026-10-01
**Issue:** [#479](https://github.com/wingnut128/netcidr/issues/479) (sub-issues #480–#487)
**Related:** [[ADR-0001 — Tenancy via explicit parameter]](./0001-tenancy-via-explicit-parameter.md), [[ADR-0006 — Unified users directory]](./0006-unified-users-directory-and-platform-admin-tier.md)

## Context

IPAM invariants were enforced by check-then-write sequences of separate
`IpamStore` calls. The only lock was an in-process mutex per cidr block, but
the Lambda deployment runs many processes against one Postgres, so two warm
instances could both pass the overlap check and both insert. CIDR-block
creation, the last-platform-admin guard, and the per-owner PAT limit had the
same shape with no lock at all. Audit rows and idempotency records were
written by separate calls after the change.

The store's ~45 methods also carried domain rules (tenant-ownership checks,
id/timestamp/derived metadata, hostname history snapshots, the delete
precondition, status transitions) duplicated in both the SQLite and Postgres
adapters.

## Decision

1. **The store runs units; IpamOps decides.** `IpamStore` shrinks to
   `migrate`, `read` (plain, unlocked reads such as lists and PAT lookups),
   and `transact`. A transaction unit names one **Lock Scope**, the reads it
   needs, and a synchronous, pure `decide` function. The adapter runs:
   begin → lock → reads → `decide` → writes + audit rows + idempotency record
   → commit. If `decide` fails, nothing persists.
2. **Mutations, Decisions, Changes.** Each IpamOps write is a **Mutation**
   whose `decide` returns a **Decision** made of **Changes**. A Change cannot
   be constructed without its audit fact, so an unaudited write does not
   compile. One executor handles idempotency replay and recording, and
   builds the decide context (`now`, id generator, caller) from an injected
   clock and id source. The `*_idempotent` wrappers go away.
3. **Exactly one Lock Scope per unit:** a cidr block (allocations, tags,
   cidr-block delete), a tenant (cidr-block create, `load`), the user
   directory (user upsert/delete/seed), or a PAT owner (mint/revoke). One
   lock per unit makes deadlock impossible by construction. Operations
   spanning scopes run one unit per scope, as `batch_allocate` and
   `reap_expired` already do.
   A scope is chosen by what its rule reads. Create checks overlap across
   every block in the tenant, so it takes the tenant. Delete checks that the
   block has no live allocations, which are written under the block's scope,
   so it takes the block: under the tenant scope an allocation could commit
   between the check and the delete. A delete can only free space, so it
   needs nothing from the tenant scope.
4. **Adapters persist and lock; they hold no rules.**
   - SQLite runs the whole unit synchronously in one `spawn_blocking` under
     `BEGIN IMMEDIATE`, with `busy_timeout` 5s on every pooled connection.
     The lock scope is not consulted: SQLite serializes all writers, which
     is coarse but correct for its single-node role.
   - Postgres takes `pg_advisory_xact_lock(hashtextextended(scope, 0))` after
     `SET LOCAL lock_timeout = '5s'`. Advisory locks work for every scope,
     including ones with no row to lock; a hash collision only
     over-serializes.
5. **Lock timeouts surface as `NetcidrError::StoreBusy`**, presented as a
   retryable 503.
6. **Background writes stay outside units.** `pat_touch_last_used` and the
   idempotency/PAT reapers remain plain, unaudited store methods.
   `reap_expired` changes allocation state, so it is a unit and is audited.

## Considered and rejected: a transaction handle

`store.begin(scope)` returning a `Box<dyn IpamTx>` with typed row methods (or
generic `get`/`put` over record enums) keeps IpamOps as straight-line async
code and is the most familiar shape. Rejected because:

- **rusqlite transactions are synchronous and not `Send`.** A handle that
  lives across `.await` must ferry the pooled connection into
  `spawn_blocking` per statement, issue `BEGIN`/`COMMIT` by hand, and run a
  blocking `ROLLBACK` from `Drop` when a request future is cancelled
  mid-transaction. Decide-then-commit keeps the whole SQLite transaction in
  one synchronous stack frame, so cancellation cannot strand it.
- **"Lock, then audit, then commit" stays a convention.** With a handle,
  forgetting the audit row or opening a second transaction while holding the
  first is expressible. With units, the audit fact is part of the Change and
  `decide` cannot do I/O.
- **The interface stays wide.** A typed-row handle is ~40 methods; the unit
  seam is three.

The cost accepted: every read a unit needs is declared before the lock.
Operations that must discover their lock key (release and update read the
allocation's cidr block id) read it once unlocked, then re-read under the
lock; this is sound because an allocation never changes blocks.

## Consequences

- Invariants hold across any number of processes, and each change commits
  together with its audit row and idempotency record.
- `allocate_auto` with `count > 1` is all-or-nothing.
- PAT mint/revoke, hostname, and tag writes now write audit rows.
- Domain rules are pure `decide` functions, unit-testable without a
  database; the store contract suite runs against both adapters.
- The in-process `cidr_block_locks` mutex is deleted.
- Tenancy stays an explicit field on every tenant-scoped lock, read, and
  write (ADR-0001).

## Revisiting

Allow several locks per unit (acquired in sorted order) only when an
operation genuinely needs two scopes atomically. Do not reintroduce a
transaction handle without a solution to the SQLite cancellation problem
above.
