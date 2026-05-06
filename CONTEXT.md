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
