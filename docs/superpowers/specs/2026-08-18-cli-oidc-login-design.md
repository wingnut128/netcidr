# `netcidr login` — OIDC authorization-code flow for the CLI

**Status:** Design draft, awaiting approval
**Date:** 2026-08-18
**Supersedes:** the "OAuth flows" non-goal in [2026-05-02-pat-design.md](2026-05-02-pat-design.md)

## Goal

Give the CLI a first-class `netcidr login` that runs a Google OAuth
authorization-code flow with PKCE, caches the resulting credential, and
silently refreshes it. This makes the OIDC-gated `/me/tokens` endpoints
reachable from the terminal, so a user can bootstrap their first PAT
without a browser devtools detour.

## Why

`/me/tokens` requires `auth_method == Oidc` (`src/me_api.rs:112`) — a PAT
cannot mint another PAT, which closes a privilege-escalation path and is
not up for renegotiation. But the CLI has no way to *obtain* an OIDC
credential: `token_cli.rs` reads `NETCIDR_API_TOKEN` and forwards it
verbatim. The only working bootstrap today is signing into the dashboard
and minting a PAT there.

That leaves two bad outcomes in practice:

- Users paste a PAT or the static bearer into `NETCIDR_API_TOKEN` and get
  a `403 OIDC authentication required to manage personal access tokens`,
  which reads as a scope problem and is not one.
- Deployments with no dashboard build (`--no-default-features`, headless
  API-only installs) have *no* PAT bootstrap path at all.

## Non-goals

- **Device-code flow.** Deferred. `--no-browser` prints the URL for
  paste-into-a-local-browser use, but the loopback redirect still needs
  port forwarding over SSH. A genuine headless story is a follow-up.
- **Replacing `NETCIDR_API_TOKEN`.** Explicit env/flag credentials keep
  winning over a cached login. CI is unaffected.
- **Non-Google identity providers.** The server validates Google ID
  tokens specifically (`GOOGLE_ISSUERS`, Google JWKS). Generic OIDC
  discovery is out of scope.
- **Revoking at the provider.** `netcidr logout` clears local state only.
- **`netcidr whoami`.** `/me` already answers this. Add it when wanted.
- **Changing PAT semantics.** No new scopes, no new lifetimes.

## Design

### Why the audience has to change

`validate_google_id_token` pins the audience to exactly one value
(`src/auth.rs:872`):

```rust
validation.set_audience(&[expected_audience]);   // NETCIDR_OIDC_AUDIENCE
```

Google stamps `aud` with whichever OAuth client performed the sign-in.
The dashboard uses a **Web** client; a CLI running its own flow needs a
**Desktop app** client, which yields a different `aud`. There is no way
to have the CLI produce a token this check accepts without widening it.

So `NETCIDR_OIDC_AUDIENCE` becomes a comma-separated list. A single
value still parses unchanged, so the change is back-compatible and every
existing deployment keeps working untouched.

### How the CLI learns the client

netcidr is self-hosted: each operator has their own Google project and
their own client IDs. Nothing can be baked into the binary. The server
therefore advertises its CLI client on the existing unauthenticated
`/features` endpoint:

```json
{
  "ipam": true,
  "swagger": false,
  "auth": {
    "mode": "oidc",
    "cli_client_id": "1234-abc.apps.googleusercontent.com",
    "cli_client_secret": "GOCSPX-..."
  }
}
```

The `auth` block is emitted only when `auth_mode == oidc` **and** both
values are configured; otherwise it is absent and `netcidr login` fails
with a message naming the missing env var.

Serving the client secret publicly is deliberate, not an oversight. A
Google "Desktop app" client secret is explicitly non-confidential
(RFC 8252 section 8.5 — installed apps cannot keep secrets). PKCE is
what actually secures the exchange; the secret is a client *identifier*
in this flow. This is the same posture `gcloud` takes with its own
embedded client credentials.

### Components

Three modules, split along I/O boundaries so each is testable alone:

| Module | Purpose | Depends on |
|---|---|---|
| `src/credentials.rs` (lib) | Credential file load/save, `0600` enforcement, keyed by `api_url`, plus the `resolve_credential` precedence chain | serde, `dirs` |
| `src/oauth.rs` (lib) | PKCE generation, auth-URL construction, code-to-token exchange, refresh | reqwest, sha2, base64, rand |
| `src/login_cli.rs` (bin) | Orchestration: fetch `/features`, run the loopback listener, open the browser, persist, print | both above |

`login_cli.rs` sits beside `token_cli.rs` and mirrors its shape.
`credentials.rs` and `oauth.rs` live in the lib so `mcp-serve --remote`
can reach the resolver too.

**No new dependencies.** `dirs`, `sha2`, `base64`, `rand`, `reqwest`,
and `jsonwebtoken` are all already in `Cargo.toml`.

### Credential store

`~/.config/netcidr/credentials.json` (via `dirs::config_dir()`, so XDG
is honored), mode `0600`:

```json
{
  "version": 1,
  "accounts": {
    "https://ipam.corp.example": {
      "email":         "user@example.com",
      "refresh_token": "1//0g...",
      "id_token":      "eyJ...",
      "expires_at":    "2026-08-18T21:04:11Z",
      "client_id":     "1234-abc.apps.googleusercontent.com"
    }
  }
}
```

Keyed by `api_url` so a user can stay signed into several deployments.
`version` is present so the format can migrate without guesswork.
Timestamps are RFC3339 TEXT, matching the convention used elsewhere in
the project.

### Login flow

```
netcidr login --api-url https://server

1. GET /features                     -> mode=oidc, cli_client_id, cli_client_secret
2. bind TcpListener 127.0.0.1:0      -> actual port
                                        (Desktop clients permit any loopback port)
3. gen state (32B random) + PKCE verifier -> S256 challenge
4. open browser -> accounts.google.com/o/oauth2/v2/auth
        scope=openid email profile
        access_type=offline & prompt=consent    (required for a refresh_token)
        code_challenge=<S256>, code_challenge_method=S256, state=<state>
5. serve exactly one request on the listener
        constant-time state compare; extract ?code=
        respond "you can close this tab"; shut down
6. POST oauth2.googleapis.com/token
        code + code_verifier + client_id + client_secret + redirect_uri
        -> id_token, refresh_token, expires_in
7. validate id_token locally         -> confirm aud, extract verified email
8. write credentials.json 0600       -> "Signed in as <email>"
```

Step 7 is load-bearing. Validating at login means a misconfigured
audience list fails immediately with an actionable message, instead of
surfacing as an opaque 401 on the next `netcidr token` call. It requires
exposing the currently-private validation helper in `auth.rs` as a
narrow `pub fn`.

Browser launch is `open` (macOS), `xdg-open` (Linux), `rundll32`
(Windows), with the URL printed as a fallback whenever the spawn fails
or `--no-browser` is passed.

### Refresh

Handled inside `resolve_credential`. If `expires_at` is within 60
seconds, POST `grant_type=refresh_token`, rewrite the file, and
continue. An `invalid_grant` response — user revoked access at Google,
or the refresh token aged out — drops that account entry and errors with
`session expired - run 'netcidr login'`.

### Credential precedence

One resolver, used by every command that talks to a remote netcidr:

```
resolve_credential(api_url) -> Result<String>

  1. --token <flag>            explicit
  2. $NETCIDR_API_TOKEN        explicit   (CI / PATs)
  3. cached login for api_url  implicit   (refreshed if stale)
  4. -> Err: "not authenticated - run 'netcidr login'"
```

Explicit always beats implicit. A developer with a PAT exported in their
shell profile does not silently switch identity after logging in, and CI
that sets the env var behaves identically to before this change.

Consumers: `netcidr token list|create|revoke`, `mcp-serve --remote`, and
any future remote command.

### CLI surface

```
netcidr login  [--api-url URL] [--no-browser] [--timeout SECS]   # default 180
netcidr logout [--api-url URL | --all]
```

When `--api-url` is omitted, both commands fall back to `$NETCIDR_API_URL`
and then error, exactly as `token_cli::resolve_api_url` already does.
`netcidr logout` with neither `--api-url` nor `--all` therefore resolves
the same single account the other commands would use; it never clears
everything implicitly. `--all` is the only way to wipe the file.

Account keys are normalized before lookup or write — trailing slashes
trimmed, matching the existing `trim_end_matches('/')` in
`token_cli.rs:47` — so `https://server` and `https://server/` are one
account, not two.

### Server changes

1. `validate_google_id_token` takes `&[String]`; `AuthConfig` carries a
   `Vec<String>` of audiences. `NETCIDR_OIDC_AUDIENCE` is parsed
   comma-separated, trimmed, empties dropped.
2. `FeaturesResponse` gains an optional `auth` block, fed by new config
   `oidc_cli_client_id` / `oidc_cli_client_secret` (env
   `NETCIDR_OIDC_CLI_CLIENT_ID` / `NETCIDR_OIDC_CLI_CLIENT_SECRET`).

Both are additive. A deployment that adopts neither is unaffected.

## Error handling

A new `NetcidrError::Auth(String)` variant — none of the existing
variants fit, and folding these into `InvalidInput` would produce
misleading messages. Every failure names its fix:

| Failure | Message |
|---|---|
| `/features` has no `auth` block | `server at <url> has no CLI OAuth client configured (set NETCIDR_OIDC_CLI_CLIENT_ID)` |
| `auth_mode != oidc` | `server at <url> is not in OIDC mode - use NETCIDR_API_TOKEN instead` |
| `state` mismatch | `authorization response failed state validation - aborting` |
| Google returns `access_denied` | `sign-in was declined` |
| No `refresh_token` in exchange | `Google returned no refresh token - check the client is of type "Desktop app"` |
| ID token fails local validation | `signed in, but this server will not accept the token (audience <aud> not in its allowlist)` |
| Listener timeout | `timed out after <n>s waiting for the browser callback` |
| `invalid_grant` on refresh | `session expired - run 'netcidr login'` |
| Credential file mode too open | `refusing to read <path>: mode 0644, expected 0600` |

## Security

- `api_url` is external input and goes through `validation.rs` per the
  project's input-scrubbing rule: scheme must be `http`/`https`, no
  control characters, no embedded credentials.
- PKCE `S256` only. `plain` is never offered.
- `state` is 32 random bytes, compared with the existing
  `constant_time_eq` helper.
- The listener binds `127.0.0.1` explicitly, never `0.0.0.0`, and serves
  exactly one request before shutting down.
- The credential file is written `0600`; reads refuse a looser mode. The
  check is `cfg`-gated to unix.
- No `unsafe`, per project policy.
- Tokens are never logged at any level. The OTLP redaction allowlist
  already strips `*token*`, but the login path does not emit them at
  all.
- `logout` clears local state only; the refresh token remains valid at
  Google until revoked there. Documented explicitly so nobody assumes
  otherwise.

## Testing

**Unit**

- PKCE challenge against the RFC 7636 Appendix B test vector.
- Credential file round-trip through a temp dir.
- A `0644` credential file is rejected.
- The four-step precedence chain, as a table test.
- Expiry/skew boundary around the 60-second refresh window.
- Multi-audience validation accepts either configured audience and
  rejects a third.

**Integration**

- An axum test server standing in for Google's token endpoint: happy-path
  exchange, refresh, and `invalid_grant`.
- The loopback handler driven by a plain GET at the callback URL, with
  valid and tampered `state`.
- No test contacts the real Google endpoints. The JWKS-dependent path is
  already covered by existing fixtures in the `auth.rs` test module.

**Regression**

- Existing tests pass unchanged with a single-valued
  `NETCIDR_OIDC_AUDIENCE`, proving the comma-separated parse is
  back-compatible.

## Operator migration

Three additive steps; skipping them all changes nothing:

1. Create a second OAuth client in the same Google project, type
   **Desktop app**.
2. Append its client ID to `NETCIDR_OIDC_AUDIENCE` (now
   comma-separated).
3. Set `NETCIDR_OIDC_CLI_CLIENT_ID` and
   `NETCIDR_OIDC_CLI_CLIENT_SECRET`.

A deployment that does none of this keeps working exactly as today;
`netcidr login` reports that the server has no CLI client configured.

## Documentation

- `README.md`: rewrite the PAT bootstrap section, which currently
  presents the dashboard as the only path, and document the new env
  vars in the configuration table.
- `CHANGELOG.md`: entry under `[Unreleased]`.
- Fix the stale comment at `src/token_cli.rs:7` claiming
  `HttpIpamClient` never carries an `Authorization` header — it does
  (`src/mcp_client.rs:33`).

## Risks

- **Google changes installed-app behavior.** The flow depends on
  arbitrary loopback ports being accepted for Desktop clients. This is
  documented behavior and RFC 8252's recommendation, but it is an
  external dependency. Mitigation: the failure is loud and immediate at
  login, never silent.
- **`prompt=consent` on every login.** Required to reliably receive a
  refresh token; the cost is an extra consent screen each time a user
  runs `netcidr login`. Acceptable for a command run rarely.
- **Widening the audience list is a trust decision.** Any token minted
  by any listed client is accepted. Operators must list only clients
  they control. Called out in the README.
