# Glossary

## Domain Terms

### Personal Access Token

A long-lived opaque bearer secret with the `ncdr_pat_` prefix. It is bound to
one OIDC owner and authenticates requests as that owner for tenant-scoped IPAM
operations.

### PAT Lifecycle

The complete behavior for minting, listing, revoking, and verifying personal
access tokens. The lifecycle owns owner identity, create validation, expiry
calculation, active-token verification, allowlist re-checks, one-time plaintext
return, and `last_used_at` updates.

### PAT Owner

The OIDC identity that owns a personal access token. It carries the owner
subject, email, and tenant id used for scoped listing and revocation.

### One-Time Plaintext

The plaintext token returned only once when a PAT is minted. Stored state keeps
only the public prefix and peppered hash.

### Error Presenter

The single module (`src/error_presenter.rs`) that translates a `NetcidrError`
into a `PresentedError`. Every caller-facing surface — IPAM HTTP API,
`/me/tokens` HTTP API, MCP tool results — calls `present()` so error
classification, message scrubbing, and the "log this at error" decision
are made in one place.

### Presented Error

The wire-format-neutral view of an error: `{ status: u16, client_msg: String,
log_level: LogLevel }`. HTTP frontends serialize it to `{"error": ...}` with
the given status; the MCP frontend serializes it to a scrubbed string. The
`client_msg` is always safe to expose; raw database, transport, and
unrecognized errors are flattened to `"internal server error"`. `PatNotFound`
is canonicalised to `"token not found"` so the caller-supplied id is never
echoed back.

### Mutation

A single IPAM write operation expressed as a pure decision over data read
under its Lock Scope — for example allocating a specific CIDR or deleting a
user. A Mutation decides; it never touches storage itself.
_Avoid_: command, transaction script

### Decision

What a Mutation concludes: its result for the caller plus the Changes to
apply. A Decision is applied completely or not at all.

### Change

One write together with the audit fact that records it. A write without an
audit fact is not a Change.
_Avoid_: write op, patch

### Lock Scope

The one thing a Mutation holds exclusively while it decides and commits: a
cidr block, a tenant, the user directory, or a PAT Owner. Two Mutations with
the same Lock Scope never interleave.
_Avoid_: lock key, mutex
