# Context

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
