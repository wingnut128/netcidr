# Personal Access Tokens for netcidr

**Status:** Design draft, awaiting approval
**Date:** 2026-05-02
**Sub-project of:** Personal Access Tokens + remote MCP endpoint (sub-project 2 of 3)
**Depends on:** Multi-tenant isolation (sub-project 1, shipped in v0.24.0)

## Goal

Let an authenticated OIDC user mint long-lived **personal access tokens** (PATs) bound to their identity. A PAT in `Authorization: Bearer …` authenticates the request as if the OIDC owner had logged in, inheriting their `tenant_id`. Tokens are mintable, listable, and revocable from the dashboard, REST API, and CLI.

## Why

- Programmatic clients (CI, scripts, the upcoming `/mcp` endpoint, MCP clients running outside the browser) can't run an OIDC browser flow.
- The current single static `NETCIDR_BEARER_TOKEN` env var is a single shared secret with no attribution and no revocation. It stays for single-operator deploys but isn't a multi-user solution.
- Multi-tenant isolation (v0.24.0) made every IPAM operation tenant-scoped. PATs ride that machinery — a PAT yields a `tenant_id` exactly the way an OIDC login does.

## Non-goals

- **Per-token scopes.** v1 PATs grant the same access the OIDC owner has — no read-only / read-write split, no per-resource scopes. Deferred until usage demands it.
- **Org / shared-team tokens.** A PAT belongs to exactly one OIDC identity. Service-account-style tokens are out of scope.
- **OAuth flows.** No authorization-code grant, no refresh tokens, no client registration. PATs are minted by an authenticated human in their own session.
- **Replacing the static `NETCIDR_BEARER_TOKEN` env.** Both auth modes coexist. Bearer-env stays for solo/CI deploys; OIDC + PATs is the multi-user path.
- **Migrating existing data.** PATs are net-new; nothing to backfill.

## Design

### Token format

Opaque random — no embedded claims, no JWT. Wire format:

```
ncdr_pat_<43 base64url chars>          # 32 random bytes, b64url-no-pad
```

The `ncdr_pat_` prefix lets the auth middleware route a `Authorization: Bearer …` header to the PAT verifier without trial-and-error against OIDC. It also lets secret scanners (GitHub push protection, etc.) recognise leaked tokens.

#### Why opaque, not JWT

PATs are **deliberately not JWTs**. The token *is* the secret — there is no signing key, no `alg` header, no claims to tamper with. Forging a PAT means guessing a 256-bit random value (2^256 search space) — computationally infeasible.

| Concern | JWT-style PAT | Opaque PAT (this design) |
|---|---|---|
| Algorithm-confusion attacks (`alg: none`, `RS256→HS256`) | Real risk if validator is buggy | Impossible — no `alg` field |
| Signing-key leak compromises every token | Yes | N/A — no signing key |
| Revocation | Requires stateful denylist anyway | Trivial — flip `revoked_at` |
| Stateless verify | Yes | No (one indexed DB lookup per request) |
| Leaked-token detection via prefix scanners | Possible | Yes — `ncdr_pat_…` is a public matchable prefix |
| Signature tampering via header manipulation | Possible if validator is buggy | Impossible |

GitHub, GitLab, npm, Vercel all use opaque PATs for the same reason: **stateful tokens are cheaper to verify securely than stateless ones.** The single DB hit is negligible against the safety it buys (instant revocation, no algorithm-confusion surface, no key-rotation choreography).

OIDC ID tokens (`Authorization: Bearer ey…`) remain JWT-validated against Google's JWKS — RS256 only, audience-pinned, expiry-checked. PATs and JWTs coexist; the prefix routes to the right verifier.

#### Wire-format pre-validation

Before any DB lookup or hash computation, the verifier rejects malformed tokens with a regex check:

```rust
static PAT_SHAPE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^ncdr_pat_[A-Za-z0-9_-]{43}$").unwrap());
```

A token failing the shape check returns `401 unauthorized` immediately — no hash, no query. This blocks junk-traffic amplification and tightens the timing surface (a bogus token and a non-existent valid-shaped token take comparable time to reject; both are dominated by the DB roundtrip, which only runs for shape-valid inputs).

All `401` responses use the same generic body regardless of the underlying reason (expired, revoked, no such token, shape-invalid). The dashboard surfaces specific reasons only for the *caller's own* tokens via `GET /me/tokens` — never via a verifier 401.

### Storage at rest

`personal_access_tokens` table:

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID |
| `tenant_id` | TEXT NOT NULL | Same shape as elsewhere — owning OIDC email |
| `owner_sub` | TEXT NOT NULL | OIDC `sub` of the human who minted it |
| `owner_email` | TEXT NOT NULL | OIDC email at mint time (denormalized for audit) |
| `name` | TEXT NOT NULL | User-supplied label, e.g. "laptop CLI" |
| `prefix` | TEXT NOT NULL | First 12 chars of token (`ncdr_pat_xxxx`) — shown in lists, indexed |
| `token_hash` | BLOB NOT NULL | `sha256(secret \|\| pepper)` — 32 bytes |
| `created_at` | TEXT NOT NULL | RFC3339 |
| `expires_at` | TEXT NULL | RFC3339; NULL means default-90-days from `created_at` (enforced at mint, not nullable on the wire) |
| `last_used_at` | TEXT NULL | Updated lazily — every successful auth bumps it |
| `revoked_at` | TEXT NULL | Soft-delete; revoked tokens stay for audit |

Indexes: `(tenant_id)`, `(token_hash)` UNIQUE, `(prefix)`.

**Pepper:** `NETCIDR_PAT_PEPPER` env var, 32 bytes b64url. Required when OIDC is enabled. Mixed into the hash so a DB dump alone can't be brute-forced. Rotation = re-mint all tokens (deferred).

**Hashing:** `sha256(token || pepper)`. Argon2 would be over-engineered for unguessable 256-bit random tokens — they're not human passwords.

### Default and max expiration

- Default: **90 days** from `created_at`.
- User may specify any duration up to **365 days** at mint time.
- Background reaper hard-deletes `expires_at < now() - 30 days` rows so the table doesn't grow unbounded.
- Verifier returns the same generic `401 unauthorized` for expired, revoked, never-existed, and shape-invalid tokens. Users debug "why did my CI break?" via `GET /me/tokens` from the dashboard, which shows their own tokens' status.

### REST API

All paths gated by OIDC middleware (a PAT can't mint another PAT — closes a privilege-escalation path).

- `POST /me/tokens` — body `{ name, expires_at? }`. Response: `{ id, name, prefix, token, expires_at, created_at }`. **`token` field is the only place the plaintext appears, ever.**
- `GET /me/tokens` — list caller's own tokens (no plaintext, no hash; just `id, name, prefix, created_at, expires_at, last_used_at, revoked_at`).
- `DELETE /me/tokens/{id}` — soft-revoke. Idempotent. 404 if the id isn't the caller's.

Cross-tenant lookup follows the multi-tenant rules: `DELETE /me/tokens/{other-user's-id}` → 404.

### Auth middleware

`require_auth` (`src/auth.rs`) gains a third branch in front of the existing OIDC path:

```
let header = req.headers().get(AUTHORIZATION);
match header {
    Some(h) if h.starts_with("Bearer ncdr_pat_") => verify_pat(...).await,
    Some(h) if h.starts_with("Bearer ")          => verify_bearer_or_oidc(...).await,
    None                                          => 401,
}
```

`verify_pat`:
1. Shape-check against `^ncdr_pat_[A-Za-z0-9_-]{43}$`; bail to generic 401 if it fails.
2. Hash incoming secret with pepper, lookup by `(token_hash, revoked_at IS NULL, expires_at > now())`. Single SQL predicate so any miss path is timing-equivalent.
3. If owner email isn't in `NETCIDR_OIDC_ALLOWED_EMAILS`, return 401 (allowlist enforcement applies live — removing someone from the allowlist locks out their PATs immediately, no DB cleanup needed).
4. Build the `Principal` from the PAT row's `owner_sub` / `owner_email`, set `tenant_id = owner_email`, attach `auth_method = pat` + `pat_id` to the audit context.
5. Async-fire-and-forget update `last_used_at = now()` (no blocking write on the request path; failure is logged, not propagated).

Every failure mode in steps 1–3 returns the same generic `401 unauthorized` body — no leakage of which check failed.

The `/me/tokens/*` endpoints sit outside the IPAM router and check `auth_method == "oidc"` to deny PATs from minting more PATs.

### Audit context extensions

`AuditContext` (`src/audit_context.rs`) gains:

```rust
pub auth_method: Option<AuthMethod>,  // "oidc" | "pat" | "bearer"
pub pat_id: Option<String>,           // populated only when auth_method == Pat
```

`audit_log` table grows two columns: `auth_method TEXT NOT NULL DEFAULT 'oidc'`, `pat_id TEXT NULL`. Migration `007_pat_audit_columns.sql` adds them; existing rows take the default.

### CLI

```
netcidr token list
netcidr token create --name "laptop" [--expires-in 30d]
netcidr token revoke <id>
```

Talks to a remote `netcidr serve` instance via the same `--api-url` / `NETCIDR_API_URL` plumbing the future `mcp-serve --remote` already uses. Auth: caller must already have a bearer token in `NETCIDR_API_TOKEN` (could be an existing PAT, or the static bearer in single-operator deploys). For first-token bootstrap, OIDC mode requires using the dashboard.

### Dashboard

New page `/me/tokens` (linked from existing user menu). Lists existing tokens, "New token" modal returns the plaintext exactly once (with copy-to-clipboard + warning to save it), revoke button per row. No editing — names are fixed at mint.

## Testing

### Unit / contract tests

- `personal_access_tokens` store CRUD: create, list, get-by-hash (hit/miss), soft-revoke, reap-expired.
- Same-pepper hash determinism; wrong-pepper miss.
- Cross-tenant: tenant A's `DELETE /me/tokens/<B's-id>` returns 404 (not 403, not 200).

### Auth middleware tests

- Valid PAT → request authenticated, `tenant_id == owner_email`, `auth_method == Pat`.
- Expired PAT → 401 with body `{"error":"token expired"}`.
- Revoked PAT → 401 invalid.
- Allowlist removed mid-flight → 401 forbidden.
- PAT used against `POST /me/tokens` → 403 (only OIDC sessions can mint).
- Audit row written for an IPAM op via PAT carries `auth_method = "pat"` and `pat_id` set.

### Integration test

`tests/pat_integration.rs`:
1. Mint OIDC session for `a@x`.
2. `POST /me/tokens` → capture plaintext.
3. New client with only the PAT → `POST /ipam/supernets` succeeds, row owned by tenant `a@x`.
4. `DELETE /me/tokens/<id>` → next call with that PAT returns 401.
5. Mint PAT, then remove `a@x` from `NETCIDR_OIDC_ALLOWED_EMAILS` (restart test server) → PAT now 401.

### CLI tests

`tests/cli_token.rs`: stand up an in-process API server with a seed PAT, exercise `netcidr token list/create/revoke` against it.

## Migration / deploy

- Migration `007` (both backends): adds `personal_access_tokens` table + audit columns. Non-destructive — additive only.
- Operator action: set `NETCIDR_PAT_PEPPER` (32 bytes b64url) on the deployed Lambda before rolling out. Workflow startup refuses to launch with OIDC enabled and an empty pepper.
- No data migration needed.

## Risks

- **Pepper loss.** If the pepper is rotated or lost, every PAT becomes a permanent miss. Mitigation: document pepper as a one-time-set secret; rotation requires bulk re-mint (deferred feature). Production deploys must back up the pepper alongside DB credentials.
- **`last_used_at` write amplification.** Every authed request writes the row. Mitigation: fire-and-forget async; an even cheaper path (write only when `now - last_used_at > 5min`) is a fast follow if it shows up in metrics.
- **Token in URLs.** Users will be tempted to put PATs in query strings. Mitigation: middleware rejects PATs presented anywhere but the `Authorization` header (no `?token=`, no cookie). Documented prominently.
- **Privilege escalation via PAT-mints-PAT.** Closed: `/me/tokens/*` endpoints check `auth_method == oidc`.
- **Replay after allowlist removal.** Open by design: allowlist is checked on every request, so removal locks out PATs immediately. No race, because PAT auth re-reads the allowlist live (it's an env-var array, no caching).

## Out of scope (deferred)

- Per-token scopes (read-only / specific resources).
- Pepper rotation tooling.
- Service-account / org-shared tokens.
- Token usage analytics beyond `last_used_at`.

These each become their own spec when needed.

## Open questions

(none currently — defaults from brainstorm approved)
