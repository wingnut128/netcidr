# `netcidr login` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `netcidr login` / `netcidr logout`, running a Google OAuth authorization-code flow with PKCE, so the OIDC-gated `/me/tokens` endpoints are reachable from the terminal.

**Architecture:** Two additive server changes (audience becomes a list; `/features` advertises the CLI OAuth client) plus three new modules — `credentials.rs` (0600 credential file + precedence resolver), `oauth.rs` (PKCE, code exchange, refresh), and `login_cli.rs` (loopback listener + orchestration). Explicit `NETCIDR_API_TOKEN` keeps winning over a cached login, so CI is untouched.

**Tech Stack:** Rust, axum 0.8, reqwest 0.13, jsonwebtoken 10.4, clap 4, `dirs` 6, sha2, base64, rand, percent-encoding, form_urlencoded. Tests use tokio-test, tempfile, tower, rsa.

**Spec:** [docs/superpowers/specs/2026-08-18-cli-oidc-login-design.md](../specs/2026-08-18-cli-oidc-login-design.md)

## Global Constraints

- **No `unsafe` anywhere.** No exceptions.
- **Two new direct dependencies only:** `percent-encoding = "2"` and
  `form_urlencoded = "1"`. Both are already compiled as transitive deps of
  axum, so this adds no new crates to the build — it only makes them
  directly importable. Add no others.
- All external input goes through `src/validation.rs` before use.
- Never log, trace, or print an ID token, refresh token, or client secret.
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- Work on branch `feat/cli-oidc-login`. Never commit to `main`.
- Run `just check` before the final commit of each task; zero failures required.
- Timestamps are RFC3339 strings, matching project convention.
- `just fmt` before every commit — a pre-commit hook enforces formatting.

## Deviation from the spec (deliberate, carried through this plan)

Spec step 7 says the CLI validates the new ID token **locally**. This plan
instead has the CLI call **`GET /me`** on the target server with the fresh
token. Rationale: it tests the audience list the server *actually* has
rather than the CLI's copy of it, it reuses an endpoint that already
returns the verified email, and it avoids making `auth.rs` internals
(`OidcClaims`, `validate_google_id_token`) public. Same failure surfaced at
the same moment, less exposed API. Everything else follows the spec as
written.

---

### Task 1: Multi-audience ID token validation

**Files:**
- Modify: `src/auth.rs:143-160` (AuthConfig field), `src/auth.rs:256-258` (`oidc` constructor), `src/auth.rs:430-432` (`oidc_audience` accessor), `src/auth.rs:492` and `src/auth.rs:560-562` (call sites), `src/auth.rs:858-884` (`validate_google_id_token`)
- Test: `src/auth.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `AuthConfig::oidc_audiences(&self) -> &[String]`. `AuthConfig::oidc(Option<String>)` keeps its existing signature and now splits the string on commas internally, so every existing call site compiles unchanged.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block at the bottom of `src/auth.rs`:

```rust
#[test]
fn oidc_audiences_splits_comma_separated_value() {
    let config = AuthConfig::oidc(Some("web-client,desktop-client".to_string()));
    assert_eq!(
        config.oidc_audiences(),
        &["web-client".to_string(), "desktop-client".to_string()]
    );
}

#[test]
fn oidc_audiences_trims_and_drops_empties() {
    let config = AuthConfig::oidc(Some(" a , ,b, ".to_string()));
    assert_eq!(
        config.oidc_audiences(),
        &["a".to_string(), "b".to_string()]
    );
}

#[test]
fn oidc_audiences_single_value_is_back_compatible() {
    let config = AuthConfig::oidc(Some("only-one".to_string()));
    assert_eq!(config.oidc_audiences(), &["only-one".to_string()]);
}

#[test]
fn oidc_audiences_empty_when_unset() {
    let config = AuthConfig::oidc(None);
    assert!(config.oidc_audiences().is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib auth::tests::oidc_audiences -- --nocapture`
Expected: FAIL — `no method named 'oidc_audiences' found for struct 'AuthConfig'`

- [ ] **Step 3: Change the AuthConfig field to a Vec**

In `src/auth.rs`, replace the field declaration inside `pub struct AuthConfig`:

```rust
    oidc_audience: Option<String>,
```

with:

```rust
    /// Accepted ID-token audiences. Populated by splitting
    /// `NETCIDR_OIDC_AUDIENCE` on commas, so a deployment can accept both
    /// the dashboard's web client and the CLI's desktop client. A single
    /// value parses to a one-element vec, keeping older configs working.
    oidc_audiences: Vec<String>,
```

In the hand-written `impl std::fmt::Debug for AuthConfig`, replace:

```rust
            .field("oidc_audience", &self.oidc_audience)
```

with:

```rust
            .field("oidc_audiences", &self.oidc_audiences)
```

In `AuthConfig::new`, replace the struct-literal field:

```rust
            oidc_audience,
```

with:

```rust
            oidc_audiences: split_audiences(oidc_audience.as_deref()),
```

- [ ] **Step 4: Add the splitter and the accessor**

Add this free function near the other helpers in `src/auth.rs` (just above `fn bearer_token`):

```rust
/// Split a comma-separated audience config value into individual
/// audiences. Trims whitespace and drops empty entries, matching the
/// parsing rules `config::resolve_email_list` already uses for the email
/// lists so the two can't drift.
fn split_audiences(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}
```

Replace the existing accessor:

```rust
    pub fn oidc_audience(&self) -> Option<&str> {
        self.oidc_audience.as_deref()
    }
```

with:

```rust
    pub fn oidc_audiences(&self) -> &[String] {
        &self.oidc_audiences
    }
```

- [ ] **Step 5: Update `validate_google_id_token` and its callers**

Change the signature and the audience line in `validate_google_id_token`:

```rust
fn validate_google_id_token(
    jwt: &str,
    expected_audiences: &[String],
    keys: &HashMap<String, GoogleKey>,
) -> Option<OidcClaims> {
```

and inside it, replace:

```rust
    validation.set_audience(&[expected_audience]);
```

with:

```rust
    validation.set_audience(expected_audiences);
```

Change `authenticate_oidc` to match:

```rust
async fn authenticate_oidc(
    headers: &HeaderMap,
    expected_audiences: &[String],
) -> Option<AuthenticatedPrincipal> {
    if expected_audiences.is_empty() {
        return None;
    }
    let jwt = bearer_token(headers.get(header::AUTHORIZATION))?;
    let keys = google_public_keys().await.ok()?;
    let claims = validate_google_id_token(jwt, expected_audiences, &keys)?;

    Some(AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: claims.sub,
        email: claims
            .email
            .filter(|_| claims.email_verified.unwrap_or(false)),
        audience: Some(claims.aud),
        auth_method: AuthMethod::Oidc,
        pat_id: None,
        role: Role::default(),
    })
}
```

Update both call sites (around `src/auth.rs:492` and `src/auth.rs:561`), replacing `self.oidc_audience.as_deref()` / `config.oidc_audience.as_deref()` with `self.oidc_audiences()` / `config.oidc_audiences()` respectively.

- [ ] **Step 6: Run the new tests and the whole auth suite**

Run: `cargo test --lib auth::`
Expected: PASS — including every pre-existing `AuthConfig::oidc(Some("aud".to_string()))` test, which proves the single-value path is back-compatible.

- [ ] **Step 7: Add an end-to-end multi-audience test**

Add to `src/auth.rs`'s `mod tests`, modelled on the existing
`oidc_auth_extracts_identity_from_valid_id_token` test (copy its keypair
and JWKS-install setup verbatim, changing only the audiences):

```rust
#[tokio::test]
async fn oidc_auth_accepts_any_configured_audience() {
    let audiences = vec!["web-client".to_string(), "desktop-client".to_string()];

    for aud in ["web-client", "desktop-client"] {
        let (jwt, kid, n, e) = signed_test_token(aud);
        test_support::clear_jwks().await;
        test_support::install_jwks(&kid, &n, &e).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        );

        let principal = authenticate_oidc(&headers, &audiences)
            .await
            .unwrap_or_else(|| panic!("audience {aud} should be accepted"));
        assert_eq!(principal.auth_method, AuthMethod::Oidc);
    }
}

#[tokio::test]
async fn oidc_auth_rejects_unconfigured_audience() {
    let audiences = vec!["web-client".to_string(), "desktop-client".to_string()];
    let (jwt, kid, n, e) = signed_test_token("some-other-client");
    test_support::clear_jwks().await;
    test_support::install_jwks(&kid, &n, &e).await;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
    );

    assert!(authenticate_oidc(&headers, &audiences).await.is_none());
}
```

If a `signed_test_token(aud) -> (String, String, Vec<u8>, Vec<u8>)` helper
does not already exist in the test module, extract one from the body of
`oidc_auth_extracts_identity_from_valid_id_token` — it returns the signed
JWT, the kid, and the RSA modulus/exponent big-endian bytes.

- [ ] **Step 8: Run and verify**

Run: `cargo test --lib auth::`
Expected: PASS, all tests.

- [ ] **Step 9: Commit**

```bash
just fmt
git add src/auth.rs
git commit -m "feat(auth): accept a list of OIDC audiences

NETCIDR_OIDC_AUDIENCE is now parsed comma-separated so a deployment can
admit both the dashboard's web client and the CLI's desktop client. A
single value still parses to a one-element list, so existing configs are
unaffected."
```

---

### Task 2: Advertise the CLI OAuth client on `/features`

**Files:**
- Modify: `src/config.rs:12-18` (env consts), `src/config.rs:92-150` (ServerConfig fields + Default), `src/config.rs:326-340` (accessors)
- Modify: `src/api.rs:1364-1372` (FeaturesResponse), `src/api.rs:542-554` (router wiring), `src/api.rs:155-170` (utoipa schema list)
- Test: `tests/api_tests.rs`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: the JSON contract Task 8 consumes —
  `GET /features` returns `{"ipam":bool,"swagger":bool,"auth":{"mode":"oidc","cli_client_id":String,"cli_client_secret":String}|null}`.
  Rust-side: `ServerConfig::oidc_cli_client_id(&self) -> Option<String>` and `ServerConfig::oidc_cli_client_secret(&self) -> Option<String>`.

- [ ] **Step 1: Write the failing test**

Add to `tests/api_tests.rs`:

```rust
#[tokio::test]
async fn features_omits_auth_block_when_cli_client_unconfigured() {
    let config = ServerConfig::default();
    let app = create_router(RouterConfig::new(config));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/features")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("auth").is_none() || json["auth"].is_null());
}

#[tokio::test]
async fn features_advertises_cli_client_in_oidc_mode() {
    let mut config = ServerConfig::default();
    config.auth_mode = AuthMode::Oidc;
    config.oidc_audience = Some("web-client,desktop-client".to_string());
    config.oidc_cli_client_id = Some("desktop-client".to_string());
    config.oidc_cli_client_secret = Some("GOCSPX-test".to_string());

    let app = create_router(RouterConfig::new(config));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/features")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["auth"]["mode"], "oidc");
    assert_eq!(json["auth"]["cli_client_id"], "desktop-client");
    assert_eq!(json["auth"]["cli_client_secret"], "GOCSPX-test");
}

#[tokio::test]
async fn features_omits_auth_block_in_bearer_mode() {
    let mut config = ServerConfig::default();
    config.auth_mode = AuthMode::Bearer;
    config.auth_token = Some("static-token".to_string());
    config.oidc_cli_client_id = Some("desktop-client".to_string());
    config.oidc_cli_client_secret = Some("GOCSPX-test".to_string());

    let app = create_router(RouterConfig::new(config));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/features")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("auth").is_none() || json["auth"].is_null());
}
```

Match the existing import style at the top of `tests/api_tests.rs`; add
`use netcidr::config::AuthMode;` if it is not already imported.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test api_tests features_`
Expected: FAIL — `no field 'oidc_cli_client_id' on type 'ServerConfig'`

- [ ] **Step 3: Add the config fields and env constants**

In `src/config.rs`, add two constants alongside the existing ones near line 18:

```rust
const OIDC_CLI_CLIENT_ID_ENV: &str = "NETCIDR_OIDC_CLI_CLIENT_ID";
const OIDC_CLI_CLIENT_SECRET_ENV: &str = "NETCIDR_OIDC_CLI_CLIENT_SECRET";
```

Add two fields to `pub struct ServerConfig`, directly after `oidc_audience`:

```rust
    /// OAuth client ID of type "Desktop app" used by `netcidr login`.
    /// Advertised on `/features` so the CLI needs no local config.
    /// Prefer NETCIDR_OIDC_CLI_CLIENT_ID in production.
    #[serde(default)]
    pub oidc_cli_client_id: Option<String>,
    /// Matching client secret. Non-confidential by design — an installed
    /// app cannot keep a secret (RFC 8252 s8.5); PKCE is what secures the
    /// exchange. Served publicly on `/features` on purpose.
    /// Prefer NETCIDR_OIDC_CLI_CLIENT_SECRET in production.
    #[serde(default)]
    pub oidc_cli_client_secret: Option<String>,
```

Add both to the `impl Default for ServerConfig` literal, next to
`oidc_audience: None`:

```rust
            oidc_cli_client_id: None,
            oidc_cli_client_secret: None,
```

- [ ] **Step 4: Add the accessors**

Add to `impl ServerConfig` in `src/config.rs`, directly after
`oidc_audience()`:

```rust
    pub fn oidc_cli_client_id(&self) -> Option<String> {
        resolve_optional(OIDC_CLI_CLIENT_ID_ENV, self.oidc_cli_client_id.as_deref())
    }

    pub fn oidc_cli_client_secret(&self) -> Option<String> {
        resolve_optional(
            OIDC_CLI_CLIENT_SECRET_ENV,
            self.oidc_cli_client_secret.as_deref(),
        )
    }
```

And add this free function beside `resolve_email_list`:

```rust
/// Env-var-wins resolution for a single optional string setting, with
/// blank values treated as unset. Mirrors the shape of `auth_token()` and
/// `oidc_audience()` so the precedence rule stays uniform.
fn resolve_optional(env_var: &str, fallback: Option<&str>) -> Option<String> {
    std::env::var(env_var)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            fallback
                .map(str::to_string)
                .filter(|value| !value.trim().is_empty())
        })
}
```

- [ ] **Step 5: Add the response type and wire it into the router**

In `src/api.rs`, add above `struct FeaturesResponse`:

```rust
/// CLI OAuth client advertised to `netcidr login`. Present only when the
/// server runs in OIDC mode and both values are configured; absent
/// otherwise so the CLI can report precisely what is missing.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
struct AuthFeatures {
    /// Always "oidc" — the block is omitted in every other mode.
    mode: &'static str,
    /// OAuth client ID of type "Desktop app".
    cli_client_id: String,
    /// Matching client secret. Non-confidential by design (RFC 8252 s8.5).
    cli_client_secret: String,
}
```

Extend `FeaturesResponse`:

```rust
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
struct FeaturesResponse {
    /// Whether the IPAM subsystem is enabled on this server.
    ipam: bool,
    /// Whether Swagger UI / OpenAPI docs are exposed.
    swagger: bool,
    /// CLI OAuth client, when this server has one configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<AuthFeatures>,
}
```

At the router wiring around `src/api.rs:548`, replace the `FeaturesResponse`
literal with:

```rust
    let auth_features = match (
        config.server.auth_mode,
        config.server.oidc_cli_client_id(),
        config.server.oidc_cli_client_secret(),
    ) {
        (AuthMode::Oidc, Some(cli_client_id), Some(cli_client_secret)) => Some(AuthFeatures {
            mode: "oidc",
            cli_client_id,
            cli_client_secret,
        }),
        _ => None,
    };

    let features = FeaturesResponse {
        ipam: ipam_enabled,
        swagger: swagger_enabled,
        auth: auth_features,
    };
```

Add `AuthFeatures` to the `components(schemas(...))` list in the utoipa
`ApiDoc` derive near `src/api.rs:159`, immediately after `FeaturesResponse`.
Ensure `AuthMode` is in scope in `api.rs`; add `use crate::config::AuthMode;`
to the imports if it is not.

- [ ] **Step 6: Run the tests**

Run: `cargo test --test api_tests features_`
Expected: PASS, all three.

- [ ] **Step 7: Verify the swagger build still works**

Run: `cargo test --features swagger --lib openapi_tests`
Expected: PASS — the spec builds without recursion overflow.

- [ ] **Step 8: Commit**

```bash
just fmt
git add src/config.rs src/api.rs tests/api_tests.rs
git commit -m "feat(api): advertise the CLI OAuth client on /features

netcidr is self-hosted, so each deployment has its own Google client and
nothing can be baked into the binary. The server now publishes its
desktop client id/secret on the existing unauthenticated /features
endpoint, emitted only in OIDC mode with both values configured.

The secret is non-confidential by design (RFC 8252 s8.5) — an installed
app cannot keep one, and PKCE is what secures the exchange."
```

---

### Task 3: Credential store

**Files:**
- Create: `src/credentials.rs`
- Modify: `src/lib.rs` (add `pub mod credentials;`), `src/error.rs` (add `Auth` variant)
- Test: inline `mod tests` in `src/credentials.rs`

**Interfaces:**
- Consumes: nothing from Tasks 1-2.
- Produces, all used by Tasks 6-8:
  - `NetcidrError::Auth(String)`
  - `pub struct Account { pub email: String, pub refresh_token: String, pub id_token: String, pub expires_at: String, pub client_id: String }`
  - `pub struct CredentialStore` with `load() -> Result<CredentialStore>`, `save(&self) -> Result<()>`, `get(&self, api_url: &str) -> Option<&Account>`, `insert(&mut self, api_url: &str, account: Account)`, `remove(&mut self, api_url: &str) -> bool`, `clear(&mut self)`, `is_empty(&self) -> bool`
  - `pub fn normalize_api_url(raw: &str) -> Result<String>`
  - `pub fn credentials_path() -> Result<PathBuf>`
  - `CredentialStore::load_from(path: &Path)` / `save_to(&self, path: &Path)` for tests

- [ ] **Step 1: Add the error variant**

In `src/error.rs`, add to the `NetcidrError` enum:

```rust
    #[error("authentication error: {0}")]
    Auth(String),
```

- [ ] **Step 2: Write the failing tests**

Create `src/credentials.rs` containing ONLY this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_account() -> Account {
        Account {
            email: "user@example.com".to_string(),
            refresh_token: "1//0g-refresh".to_string(),
            id_token: "eyJ-id".to_string(),
            expires_at: "2026-08-18T21:04:11Z".to_string(),
            client_id: "desktop-client".to_string(),
        }
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        let mut store = CredentialStore::default();
        store.insert("https://server", sample_account());
        store.save_to(&path).unwrap();

        let loaded = CredentialStore::load_from(&path).unwrap();
        let account = loaded.get("https://server").unwrap();
        assert_eq!(account.email, "user@example.com");
        assert_eq!(account.refresh_token, "1//0g-refresh");
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let store = CredentialStore::load_from(&path).unwrap();
        assert!(store.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        let mut store = CredentialStore::default();
        store.insert("https://server", sample_account());
        store.save_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        let mut store = CredentialStore::default();
        store.insert("https://server", sample_account());
        store.save_to(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = CredentialStore::load_from(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("0644"), "got: {message}");
        assert!(message.contains("0600"), "got: {message}");
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_permissions_on_an_existing_loose_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        // A pre-existing world-readable file is the case the atomic write
        // exists to handle.
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut store = CredentialStore::default();
        store.insert("https://server", sample_account());
        store.save_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(
            !path.with_extension("json.tmp").exists(),
            "temp file must not survive a successful save"
        );
    }

    #[test]
    fn debug_redacts_both_tokens() {
        let rendered = format!("{:?}", sample_account());
        assert!(!rendered.contains("1//0g-refresh"), "got: {rendered}");
        assert!(!rendered.contains("eyJ-id"), "got: {rendered}");
        assert!(rendered.contains("user@example.com"));
    }

    #[test]
    fn trailing_slashes_resolve_to_one_account() {
        let mut store = CredentialStore::default();
        store.insert("https://server/", sample_account());
        assert!(store.get("https://server").is_some());
        assert!(store.get("https://server/").is_some());
    }

    #[test]
    fn remove_and_clear() {
        let mut store = CredentialStore::default();
        store.insert("https://a", sample_account());
        store.insert("https://b", sample_account());

        assert!(store.remove("https://a"));
        assert!(!store.remove("https://a"));
        assert!(store.get("https://b").is_some());

        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn normalize_rejects_bad_urls() {
        assert!(normalize_api_url("https://server").is_ok());
        assert!(normalize_api_url("http://127.0.0.1:8080").is_ok());
        assert!(normalize_api_url("ftp://server").is_err());
        assert!(normalize_api_url("server").is_err());
        assert!(normalize_api_url("https://user:pw@server").is_err());
        assert!(normalize_api_url("https://ser\nver").is_err());
        assert!(normalize_api_url("").is_err());
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(normalize_api_url("https://server/").unwrap(), "https://server");
        assert_eq!(normalize_api_url("  https://server//  ").unwrap(), "https://server");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib credentials::`
Expected: FAIL — `file not found for module 'credentials'` (the module is not registered yet)

- [ ] **Step 4: Register the module**

Add to `src/lib.rs`, in the group with `config`/`error`/`validation`:

```rust
pub mod credentials;
```

Re-run `cargo test --lib credentials::`. Expected: FAIL with `cannot find
type 'Account' in this scope` — the tests now compile far enough to
demand the implementation.

- [ ] **Step 5: Write the implementation**

Prepend this above the test module in `src/credentials.rs`:

```rust
//! On-disk credential cache for `netcidr login`.
//!
//! One JSON file at `~/.config/netcidr/credentials.json`, mode `0600`,
//! keyed by normalized API URL so a user can stay signed in to several
//! deployments at once. Refresh tokens are long-lived credentials, so the
//! loader refuses to read a file that is group- or world-readable rather
//! than silently using it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{NetcidrError, Result};

/// Current on-disk schema version. Bump when the shape changes so a future
/// reader can migrate instead of guessing.
const SCHEMA_VERSION: u32 = 1;

/// Cached credential for a single netcidr deployment.
///
/// `Debug` is hand-written below rather than derived: this struct holds a
/// long-lived refresh token, and a derived impl would print it in any
/// `{:?}`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    /// Verified email reported by the server at login time.
    pub email: String,
    /// Long-lived Google refresh token used to re-mint ID tokens.
    pub refresh_token: String,
    /// Most recently issued ID token.
    pub id_token: String,
    /// RFC3339 expiry of `id_token`.
    pub expires_at: String,
    /// OAuth client this credential was issued to. Recorded so a server
    /// that rotates its CLI client invalidates the cache explicitly
    /// instead of failing with a confusing audience error.
    pub client_id: String,
}

/// Redacts both token fields. Mirrors the hand-written `Debug` on
/// `AuthConfig` in `src/auth.rs`, which does the same for its bearer token.
impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("email", &self.email)
            .field("refresh_token", &"<redacted>")
            .field("id_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// The credential file. `BTreeMap` rather than `HashMap` so the serialized
/// output has a stable key order and diffs cleanly.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CredentialStore {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    accounts: BTreeMap<String, Account>,
}

fn default_version() -> u32 {
    SCHEMA_VERSION
}

impl CredentialStore {
    /// Load from the default path. A missing file is an empty store, not
    /// an error — "never logged in" is a normal state.
    pub fn load() -> Result<Self> {
        Self::load_from(&credentials_path()?)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        check_permissions(path)?;
        let raw = std::fs::read_to_string(path)?;
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(&raw).map_err(|e| {
            NetcidrError::Auth(format!(
                "{} is not valid credential JSON ({e}) - delete it and run `netcidr login` again",
                path.display()
            ))
        })
    }

    /// Persist to the default path, creating the parent directory.
    pub fn save(&self) -> Result<()> {
        self.save_to(&credentials_path()?)
    }

    /// Persist atomically: write a sibling temp file that is `0600` from
    /// birth, fsync it, then rename over the target.
    ///
    /// The ordering matters. `std::fs::write` truncates an *existing* file
    /// without touching its mode, so writing straight to the target would
    /// put the refresh token into a world-readable file whenever one was
    /// already there at a looser mode — and a crash in that window leaves
    /// the secret exposed. Rename is atomic, so the real file is never
    /// observable holding the secret at the wrong mode, and an interrupted
    /// write leaves the previous file intact rather than a truncated one.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        write_owner_only(&tmp, &json).inspect_err(|_| {
            // Never leave a temp file holding a secret behind.
            let _ = std::fs::remove_file(&tmp);
        })?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, api_url: &str) -> Option<&Account> {
        self.accounts.get(&normalize_key(api_url))
    }

    pub fn insert(&mut self, api_url: &str, account: Account) {
        self.version = SCHEMA_VERSION;
        self.accounts.insert(normalize_key(api_url), account);
    }

    /// Remove one account. Returns whether anything was removed, so
    /// `netcidr logout` can tell the user if they were not signed in.
    pub fn remove(&mut self, api_url: &str) -> bool {
        self.accounts.remove(&normalize_key(api_url)).is_some()
    }

    pub fn clear(&mut self) {
        self.accounts.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

/// Default credential file location, honoring XDG via `dirs`.
pub fn credentials_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().ok_or_else(|| {
        NetcidrError::Auth("could not determine a config directory for this platform".to_string())
    })?;
    Ok(dir.join("netcidr").join("credentials.json"))
}

/// Validate and canonicalize an API base URL. This is external input, so
/// it is scrubbed per the project's input-validation rule before it ever
/// becomes a map key or part of a request URL.
pub fn normalize_api_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(NetcidrError::Auth("API URL must not be empty".to_string()));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(NetcidrError::Auth(
            "API URL must not contain control characters".to_string(),
        ));
    }
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| {
            NetcidrError::Auth(format!("API URL {trimmed:?} must start with http:// or https://"))
        })?;
    let host_and_path = rest.trim_end_matches('/');
    if host_and_path.is_empty() {
        return Err(NetcidrError::Auth(format!("API URL {trimmed:?} has no host")));
    }
    // Reject embedded credentials — they would end up in the store key and
    // in log output, and there is no reason to accept them.
    let authority = host_and_path.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        return Err(NetcidrError::Auth(
            "API URL must not embed credentials".to_string(),
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Key normalization for lookups. Deliberately infallible — `get` on a
/// malformed URL should miss, not error. Callers that need validation use
/// `normalize_api_url`.
fn normalize_key(api_url: &str) -> String {
    api_url.trim().trim_end_matches('/').to_string()
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(NetcidrError::Auth(format!(
            "refusing to read {}: mode {:04o}, expected 0600",
            path.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Create `path` with owner-only permissions and write `contents` to it.
/// On unix the mode is set at open time, so the file is never readable by
/// anyone else — not even for the duration of the write.
#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Non-unix fallback. These platforms have no mode bits to set here; the
/// file inherits the platform's own default ACLs.
#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib credentials::`
Expected: PASS, all ten.

- [ ] **Step 7: Commit**

```bash
just fmt
git add src/credentials.rs src/lib.rs src/error.rs
git commit -m "feat(credentials): add the 0600 credential store

Keyed by normalized API URL so one user can stay signed in to several
deployments. Loading refuses a group- or world-readable file rather than
silently using it — the refresh token it holds is long-lived."
```

---

### Task 4: PKCE and the authorization URL

**Files:**
- Create: `src/oauth.rs`
- Modify: `src/lib.rs` (add `pub mod oauth;`), `Cargo.toml` (two direct deps)
- Test: inline `mod tests` in `src/oauth.rs`

**Interfaces:**
- Consumes: `NetcidrError::Auth` from Task 3.
- Produces, used by Tasks 5 and 8:
  - `pub const AUTH_ENDPOINT: &str`, `pub const TOKEN_ENDPOINT: &str`
  - `pub struct Pkce { pub verifier: String, pub challenge: String }` with `Pkce::generate() -> Pkce`
  - `pub fn random_state() -> String`
  - `pub fn build_auth_url(client_id: &str, redirect_uri: &str, challenge: &str, state: &str) -> String`

- [ ] **Step 1: Write the failing tests**

Create `src/oauth.rs` containing only this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B test vector: this exact verifier must produce
    /// this exact S256 challenge. If this fails, the challenge derivation
    /// is wrong and Google will reject every exchange.
    #[test]
    fn s256_challenge_matches_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_for(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifier_is_within_rfc_length_bounds() {
        let pkce = Pkce::generate();
        assert!(
            (43..=128).contains(&pkce.verifier.len()),
            "verifier length {} out of range",
            pkce.verifier.len()
        );
        assert_eq!(pkce.challenge, challenge_for(&pkce.verifier));
    }

    #[test]
    fn generated_verifiers_are_unique() {
        let a = Pkce::generate();
        let b = Pkce::generate();
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn verifier_uses_only_unreserved_characters() {
        let pkce = Pkce::generate();
        assert!(
            pkce.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')),
            "verifier contains a reserved character: {}",
            pkce.verifier
        );
    }

    #[test]
    fn state_is_unique_and_long_enough() {
        let a = random_state();
        let b = random_state();
        assert_ne!(a, b);
        assert!(a.len() >= 43, "state too short: {}", a.len());
    }

    #[test]
    fn auth_url_carries_every_required_parameter() {
        let url = build_auth_url(
            "desktop-client",
            "http://127.0.0.1:51847/callback",
            "test-challenge",
            "test-state",
        );

        assert!(url.starts_with(AUTH_ENDPOINT));
        assert!(url.contains("client_id=desktop-client"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=test-challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=test-state"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        // Redirect URI and scope must be percent-encoded.
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A51847%2Fcallback"));
        assert!(url.contains("scope=openid+email+profile") || url.contains("scope=openid%20email%20profile"));
    }
}
```

- [ ] **Step 2: Add the dependencies and register the module**

Add to `[dependencies]` in `Cargo.toml`:

```toml
percent-encoding = "2"
form_urlencoded = "1"
```

Both are already compiled as transitive dependencies of axum, so this adds
no new crates to the build — confirm with `cargo tree -i percent-encoding`
before and after.

Add to `src/lib.rs`:

```rust
pub mod oauth;
```

Run: `cargo test --lib oauth::`
Expected: FAIL — `cannot find function 'challenge_for' in this scope`

- [ ] **Step 3: Write the implementation**

Prepend above the test module in `src/oauth.rs`:

```rust
//! Google OAuth mechanics for `netcidr login`.
//!
//! Pure protocol code — PKCE derivation, authorization-URL construction,
//! and the two token-endpoint calls. Nothing here touches the filesystem
//! or the terminal, so it is all directly testable.

use base64::Engine;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{NetcidrError, Result};

pub const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Scopes requested at login. `openid` and `email` are what the server
/// needs to identify the principal; `profile` is what makes Google's
/// consent screen show a human name rather than a bare address.
const SCOPES: &str = "openid email profile";

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A PKCE verifier/challenge pair (RFC 7636). S256 only — `plain` is
/// never offered, because it provides no protection at all.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        // 32 random bytes -> 43 base64url chars, the RFC's minimum length
        // and the value Google's own libraries use.
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = b64url(&bytes);
        let challenge = challenge_for(&verifier);
        Self {
            verifier,
            challenge,
        }
    }
}

/// S256 code challenge: BASE64URL(SHA256(ASCII(verifier))), no padding.
fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    b64url(&digest)
}

/// CSRF token echoed back on the callback. 32 random bytes, compared in
/// constant time when the callback arrives.
pub fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    b64url(&bytes)
}

/// Everything outside RFC 3986's unreserved set gets percent-encoded.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode a query-parameter value.
fn encode(value: &str) -> String {
    utf8_percent_encode(value, QUERY_VALUE).to_string()
}

/// Build the browser-facing authorization URL.
///
/// `access_type=offline` plus `prompt=consent` is what makes Google
/// reliably return a refresh token. Without `prompt=consent` a user who
/// has already granted this client gets an exchange with no
/// `refresh_token`, and the login silently degrades to a one-hour session.
pub fn build_auth_url(client_id: &str, redirect_uri: &str, challenge: &str, state: &str) -> String {
    format!(
        "{AUTH_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code&scope={}\
         &code_challenge={}&code_challenge_method=S256&state={}&access_type=offline&prompt=consent",
        encode(client_id),
        encode(redirect_uri),
        encode(SCOPES),
        encode(challenge),
        encode(state),
    )
}
```

Note the scope assertion in the test accepts either `+` or `%20`; this
implementation produces `%20`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib oauth::`
Expected: PASS, all six. The RFC 7636 vector passing is the important one.

- [ ] **Step 5: Commit**

```bash
just fmt
git add src/oauth.rs src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(oauth): add PKCE derivation and authorization-URL building

S256 only. The RFC 7636 Appendix B vector is asserted directly, since a
wrong challenge derivation would fail only at Google's token endpoint
with an opaque error."
```

---

### Task 5: Token exchange and refresh

**Files:**
- Modify: `src/oauth.rs`
- Test: `tests/oauth_token.rs` (create)

**Interfaces:**
- Consumes: `TOKEN_ENDPOINT` from Task 4, `NetcidrError::Auth` from Task 3.
- Produces, used by Tasks 6 and 8:
  - `pub struct TokenResponse { pub id_token: String, pub refresh_token: Option<String>, pub expires_in: u64 }`
  - `pub async fn exchange_code(token_endpoint: &str, client_id: &str, client_secret: &str, code: &str, verifier: &str, redirect_uri: &str) -> Result<TokenResponse>`
  - `pub async fn refresh_id_token(token_endpoint: &str, client_id: &str, client_secret: &str, refresh_token: &str) -> Result<TokenResponse>`
  - `pub fn expiry_from_now(expires_in: u64) -> String` (RFC3339)
  - `pub struct AuthFeatures { pub mode: String, pub cli_client_id: String, pub cli_client_secret: String }`
  - `pub async fn fetch_auth_features(api_url: &str) -> Result<AuthFeatures>`

  Both network functions take the endpoint as a parameter specifically so
  tests can point them at a local stub. Production callers pass
  `oauth::TOKEN_ENDPOINT`.

- [ ] **Step 1: Write the failing tests**

Create `tests/oauth_token.rs`:

```rust
//! Token-endpoint tests against a local axum stub. No test in this file
//! contacts Google.

use axum::{Json, Router, extract::Form, routing::post};
use netcidr::oauth::{exchange_code, refresh_id_token};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
    client_id: String,
    client_secret: String,
}

/// Reject bad input with a 400 carrying a distinctive code rather than
/// panicking. A panic inside an axum handler drops the connection, which
/// reaches the test as an opaque "token request failed" and hides the real
/// cause; a 400 flows through the normal error path and names the problem.
async fn stub_token(
    Form(form): Form<TokenForm>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    fn bad(code: &str) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": code })),
        )
    }
    let ok = |body: serde_json::Value| (axum::http::StatusCode::OK, Json(body));

    if form.client_id != "desktop-client" {
        return bad("stub_bad_client_id");
    }
    if form.client_secret != "GOCSPX-test" {
        return bad("stub_bad_client_secret");
    }

    match form.grant_type.as_str() {
        "authorization_code" => {
            if form.code != "the-code" {
                return bad("stub_bad_code");
            }
            if form.code_verifier != "the-verifier" {
                return bad("stub_bad_verifier");
            }
            ok(json!({
                "id_token": "eyJ-fresh",
                "refresh_token": "1//0g-refresh",
                "expires_in": 3599
            }))
        }
        "refresh_token" => {
            if form.refresh_token != "1//0g-refresh" {
                return bad("stub_bad_refresh_token");
            }
            ok(json!({ "id_token": "eyJ-refreshed", "expires_in": 3599 }))
        }
        _ => bad("stub_unexpected_grant_type"),
    }
}

async fn stub_invalid_grant() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_grant", "error_description": "Token has been revoked." })),
    )
}

async fn spawn(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}/token")
}

#[tokio::test]
async fn exchange_returns_tokens() {
    let url = spawn(Router::new().route("/token", post(stub_token))).await;

    let response = exchange_code(
        &url,
        "desktop-client",
        "GOCSPX-test",
        "the-code",
        "the-verifier",
        "http://127.0.0.1:51847/callback",
    )
    .await
    .unwrap();

    assert_eq!(response.id_token, "eyJ-fresh");
    assert_eq!(response.refresh_token.as_deref(), Some("1//0g-refresh"));
    assert_eq!(response.expires_in, 3599);
}

#[tokio::test]
async fn refresh_returns_a_new_id_token() {
    let url = spawn(Router::new().route("/token", post(stub_token))).await;

    let response = refresh_id_token(&url, "desktop-client", "GOCSPX-test", "1//0g-refresh")
        .await
        .unwrap();

    assert_eq!(response.id_token, "eyJ-refreshed");
    // A refresh response carries no new refresh token; the caller keeps
    // the one it already has.
    assert!(response.refresh_token.is_none());
}

#[tokio::test]
async fn invalid_grant_is_reported_as_an_expired_session() {
    let url = spawn(Router::new().route("/token", post(stub_invalid_grant))).await;

    let err = refresh_id_token(&url, "desktop-client", "GOCSPX-test", "stale")
        .await
        .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("session expired"), "got: {message}");
    assert!(message.contains("netcidr login"), "got: {message}");
}

#[tokio::test]
async fn wrong_credentials_surface_the_stubs_error_code() {
    let url = spawn(Router::new().route("/token", post(stub_token))).await;

    let err = exchange_code(
        &url,
        "wrong-client",
        "GOCSPX-test",
        "the-code",
        "the-verifier",
        "http://127.0.0.1:51847/callback",
    )
    .await
    .unwrap_err();

    // Proves the stub's rejection path produces a legible failure rather
    // than a dropped connection.
    assert!(
        err.to_string().contains("stub_bad_client_id"),
        "got: {err}"
    );
}

#[tokio::test]
async fn exchange_without_a_refresh_token_is_an_error() {
    async fn no_refresh() -> Json<serde_json::Value> {
        Json(json!({ "id_token": "eyJ-fresh", "expires_in": 3599 }))
    }
    let url = spawn(Router::new().route("/token", post(no_refresh))).await;

    let err = exchange_code(
        &url,
        "desktop-client",
        "GOCSPX-test",
        "the-code",
        "the-verifier",
        "http://127.0.0.1:51847/callback",
    )
    .await
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("no refresh token"), "got: {message}");
    assert!(message.contains("Desktop app"), "got: {message}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test oauth_token`
Expected: FAIL — `unresolved import 'netcidr::oauth::exchange_code'`

- [ ] **Step 3: Implement the token calls**

Append to `src/oauth.rs`, above the test module:

```rust
/// Successful token-endpoint response. `refresh_token` is present on an
/// authorization-code exchange and absent on a refresh, which is why it is
/// optional here rather than in two separate types.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: u64,
}

/// Google's error body. `error` is the machine-readable code we branch on;
/// `error_description` is human text we fold into the message.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Convert a token response's `expires_in` into an absolute RFC3339
/// instant, matching the timestamp convention used elsewhere in the
/// project.
pub fn expiry_from_now(expires_in: u64) -> String {
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);
    expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

async fn post_token_form(
    token_endpoint: &str,
    form: &[(&str, &str)],
) -> Result<TokenResponse> {
    let response = reqwest::Client::new()
        .post(token_endpoint)
        .form(form)
        .send()
        .await
        .map_err(|e| NetcidrError::Auth(format!("token request failed: {e}")))?;

    if response.status().is_success() {
        return response
            .json::<TokenResponse>()
            .await
            .map_err(|e| NetcidrError::Auth(format!("unreadable token response: {e}")));
    }

    let status = response.status().as_u16();
    let body = response.json::<TokenErrorResponse>().await.ok();
    match body {
        Some(err) if err.error == "invalid_grant" => Err(NetcidrError::Auth(
            "session expired - run `netcidr login`".to_string(),
        )),
        Some(err) => {
            let detail = err.error_description.unwrap_or_else(|| err.error.clone());
            Err(NetcidrError::Auth(format!(
                "token endpoint rejected the request: {detail}"
            )))
        }
        None => Err(NetcidrError::Auth(format!(
            "token endpoint returned HTTP {status}"
        ))),
    }
}

/// Exchange an authorization code for tokens. A response with no refresh
/// token is treated as a failure: without one the credential dies in an
/// hour, and the usual cause is a client registered as the wrong type.
pub async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse> {
    let response = post_token_form(
        token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
        ],
    )
    .await?;

    if response.refresh_token.is_none() {
        return Err(NetcidrError::Auth(
            "Google returned no refresh token - check the client is of type \"Desktop app\""
                .to_string(),
        ));
    }
    Ok(response)
}

/// Re-mint an ID token from a stored refresh token.
pub async fn refresh_id_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    post_token_form(
        token_endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ],
    )
    .await
}

/// The `auth` block of `GET /features` — a deployment's CLI OAuth client.
///
/// Lives here rather than in the CLI binary because both `netcidr login`
/// and the credential resolver need it: the resolver has no other way to
/// learn the client secret when it refreshes a stale ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthFeatures {
    pub mode: String,
    pub cli_client_id: String,
    pub cli_client_secret: String,
}

#[derive(Deserialize)]
struct FeaturesBody {
    #[serde(default)]
    auth: Option<AuthFeatures>,
}

/// Fetch the CLI OAuth client a server advertises. Errors name the exact
/// missing configuration so the operator knows what to set.
pub async fn fetch_auth_features(api_url: &str) -> Result<AuthFeatures> {
    let body: FeaturesBody = reqwest::Client::new()
        .get(format!("{api_url}/features"))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not reach {api_url}: {e}")))?
        .json()
        .await
        .map_err(|e| NetcidrError::Auth(format!("unreadable /features response: {e}")))?;

    let auth = body.auth.ok_or_else(|| {
        NetcidrError::Auth(format!(
            "server at {api_url} has no CLI OAuth client configured \
             (set NETCIDR_OIDC_CLI_CLIENT_ID)"
        ))
    })?;

    if auth.mode != "oidc" {
        return Err(NetcidrError::Auth(format!(
            "server at {api_url} is not in OIDC mode - use NETCIDR_API_TOKEN instead"
        )));
    }
    Ok(auth)
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --test oauth_token`
Expected: PASS, all four.

- [ ] **Step 5: Commit**

```bash
just fmt
git add src/oauth.rs tests/oauth_token.rs
git commit -m "feat(oauth): add code exchange and refresh-token renewal

Both take the endpoint as a parameter so tests drive them against a local
axum stub instead of Google. invalid_grant maps to a 'session expired'
message naming the fix, and an exchange with no refresh token fails loudly
rather than degrading to a silent one-hour session."
```

---

### Task 6: The credential resolver

**Files:**
- Modify: `src/credentials.rs`
- Modify: `src/token_cli.rs:291-303` (replace `resolve_bearer`), `src/token_cli.rs:319-327` (handler), `src/main.rs:314-318` (`mcp-serve --remote` token resolution)
- Test: `tests/credential_resolver.rs` (create)

**Interfaces:**
- Consumes: `CredentialStore`, `Account` (Task 3); `refresh_id_token`, `expiry_from_now`, `TOKEN_ENDPOINT` (Task 5).
- Produces, used by Tasks 8-9:
  - `pub async fn resolve_credential(api_url: &str, explicit: Option<&str>) -> Result<String>`
  - `pub async fn resolve_from(store_path: &Path, token_endpoint: &str, api_url: &str, explicit: Option<&str>, client_secret: &str) -> Result<String>` (the injectable form the tests drive)
  - `pub fn is_expired(expires_at: &str, skew_secs: i64) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tests/credential_resolver.rs`:

```rust
//! Precedence and refresh behavior of the shared credential resolver.

use netcidr::credentials::{Account, CredentialStore, is_expired, resolve_from};
use tempfile::TempDir;

fn account(expires_at: &str) -> Account {
    Account {
        email: "user@example.com".to_string(),
        refresh_token: "1//0g-refresh".to_string(),
        id_token: "eyJ-cached".to_string(),
        expires_at: expires_at.to_string(),
        client_id: "desktop-client".to_string(),
    }
}

fn far_future() -> String {
    (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn already_past() -> String {
    (chrono::Utc::now() - chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[test]
fn expiry_respects_the_skew_window() {
    assert!(!is_expired(&far_future(), 60));
    assert!(is_expired(&already_past(), 60));
    // Inside the skew window counts as expired: refresh before it bites.
    let in_thirty_seconds = (chrono::Utc::now() + chrono::Duration::seconds(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(is_expired(&in_thirty_seconds, 60));
    // An unparseable timestamp is treated as expired, never as valid.
    assert!(is_expired("not-a-timestamp", 60));
}

#[tokio::test]
async fn explicit_token_wins_over_the_cache() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let mut store = CredentialStore::default();
    store.insert("https://server", account(&far_future()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        Some("explicit-pat"),
        "GOCSPX-test",
    )
    .await
    .unwrap();

    assert_eq!(token, "explicit-pat");
}

#[tokio::test]
async fn cached_token_is_used_when_still_valid() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let mut store = CredentialStore::default();
    store.insert("https://server", account(&far_future()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        "GOCSPX-test",
    )
    .await
    .unwrap();

    assert_eq!(token, "eyJ-cached");
}

#[tokio::test]
async fn no_credential_produces_an_actionable_error() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");

    let err = resolve_from(
        &path,
        "http://unused.invalid/token",
        "https://server",
        None,
        "GOCSPX-test",
    )
    .await
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("not authenticated"), "got: {message}");
    assert!(message.contains("netcidr login"), "got: {message}");
}

#[tokio::test]
async fn a_stale_credential_is_refreshed_and_written_back() {
    use axum::{Json, Router, routing::post};
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn stub() -> Json<serde_json::Value> {
        Json(json!({ "id_token": "eyJ-refreshed", "expires_in": 3599 }))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/token", post(stub)))
            .await
            .unwrap();
    });
    let token_endpoint = format!("http://{addr}/token");

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials.json");
    let mut store = CredentialStore::default();
    store.insert("https://server", account(&already_past()));
    store.save_to(&path).unwrap();

    let token = resolve_from(
        &path,
        &token_endpoint,
        "https://server",
        None,
        "GOCSPX-test",
    )
    .await
    .unwrap();
    assert_eq!(token, "eyJ-refreshed");

    // The refreshed token is persisted, so the next call does no network I/O.
    let reloaded = CredentialStore::load_from(&path).unwrap();
    let stored = reloaded.get("https://server").unwrap();
    assert_eq!(stored.id_token, "eyJ-refreshed");
    assert_eq!(stored.refresh_token, "1//0g-refresh", "refresh token preserved");
    assert!(!is_expired(&stored.expires_at, 60));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test credential_resolver`
Expected: FAIL — `unresolved import 'netcidr::credentials::resolve_from'`

- [ ] **Step 3: Implement the resolver**

Append to `src/credentials.rs`, above the test module:

```rust
/// Seconds of clock skew treated as "already expired", so a token is
/// refreshed slightly before it actually lapses rather than mid-request.
const EXPIRY_SKEW_SECONDS: i64 = 60;

/// Whether a cached ID token should be refreshed. An unparseable
/// timestamp counts as expired — a corrupt cache must never be treated as
/// a live credential.
pub fn is_expired(expires_at: &str, skew_secs: i64) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(parsed) => {
            parsed.with_timezone(&chrono::Utc)
                <= chrono::Utc::now() + chrono::Duration::seconds(skew_secs)
        }
        Err(_) => true,
    }
}

/// Resolve a bearer credential for `api_url`, using the default store.
///
/// Precedence, explicit before implicit:
///   1. `explicit` (a `--token` flag)
///   2. `NETCIDR_API_TOKEN`
///   3. the cached login, refreshed if stale
///   4. error
///
/// Explicit sources win so a PAT exported in a shell profile — or set by
/// CI — is never silently shadowed by a desktop login.
///
/// The client secret needed for a refresh comes from the server's
/// `/features` endpoint, not from the environment — `NETCIDR_OIDC_CLI_*`
/// are server-side settings and are never present on a client machine.
/// That fetch happens only when a refresh is actually required, so the
/// common path (valid cached token) stays free of network I/O.
pub async fn resolve_credential(api_url: &str, explicit: Option<&str>) -> Result<String> {
    if let Some(token) = explicit.map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(token.to_string());
    }
    if let Some(token) = std::env::var("NETCIDR_API_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        return Ok(token);
    }

    let path = credentials_path()?;
    let store = CredentialStore::load_from(&path)?;
    let account = store.get(api_url).ok_or_else(|| {
        NetcidrError::Auth(format!(
            "not authenticated for {api_url} - run `netcidr login`"
        ))
    })?;

    if !is_expired(&account.expires_at, EXPIRY_SKEW_SECONDS) {
        return Ok(account.id_token.clone());
    }

    let auth = crate::oauth::fetch_auth_features(api_url).await?;
    resolve_from(
        &path,
        crate::oauth::TOKEN_ENDPOINT,
        api_url,
        None,
        &auth.cli_client_secret,
    )
    .await
}

/// Injectable form of [`resolve_credential`]. Production callers go
/// through `resolve_credential`; tests pass a temp path and a stub token
/// endpoint.
pub async fn resolve_from(
    store_path: &Path,
    token_endpoint: &str,
    api_url: &str,
    explicit: Option<&str>,
    client_secret: &str,
) -> Result<String> {
    if let Some(token) = explicit.map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(token.to_string());
    }
    if let Some(token) = std::env::var("NETCIDR_API_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        return Ok(token);
    }

    let mut store = CredentialStore::load_from(store_path)?;
    let account = store.get(api_url).cloned().ok_or_else(|| {
        NetcidrError::Auth(format!(
            "not authenticated for {api_url} - run `netcidr login`"
        ))
    })?;

    if !is_expired(&account.expires_at, EXPIRY_SKEW_SECONDS) {
        return Ok(account.id_token);
    }

    let refreshed = match crate::oauth::refresh_id_token(
        token_endpoint,
        &account.client_id,
        client_secret,
        &account.refresh_token,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            // The refresh token is dead (revoked at Google, or aged out).
            // Drop the entry so the next run starts clean instead of
            // retrying a credential that can never work again.
            store.remove(api_url);
            store.save_to(store_path)?;
            return Err(err);
        }
    };

    let updated = Account {
        id_token: refreshed.id_token.clone(),
        expires_at: crate::oauth::expiry_from_now(refreshed.expires_in),
        // A refresh response carries no new refresh token; keep ours.
        refresh_token: refreshed.refresh_token.unwrap_or(account.refresh_token),
        ..account
    };
    store.insert(api_url, updated);
    store.save_to(store_path)?;

    Ok(refreshed.id_token)
}
```

Add `#[derive(Clone, ...)]` to `Account` if it is not already `Clone` —
`store.get(api_url).cloned()` requires it. (Task 3 already derives
`Clone`.)

- [ ] **Step 4: Run the tests**

Run: `cargo test --test credential_resolver`
Expected: PASS, all five.

Note: `explicit_token_wins_over_the_cache` and
`no_credential_produces_an_actionable_error` read `NETCIDR_API_TOKEN`.
If your shell exports it, these fail. Run with it cleared:
`env -u NETCIDR_API_TOKEN cargo test --test credential_resolver`

- [ ] **Step 5: Wire the resolver into `netcidr token`**

In `src/token_cli.rs`, delete the `resolve_bearer` function entirely
(lines 291-303) and change `handle_token_command` to use the resolver:

```rust
pub async fn handle_token_command(
    writer: &OutputWriter,
    output_file: &Option<String>,
    api_url: Option<&str>,
    command: TokenCommands,
) -> Result<()> {
    let base = resolve_api_url(api_url)?;
    let base = netcidr::credentials::normalize_api_url(&base)?;
    let bearer = netcidr::credentials::resolve_credential(&base, None).await?;
    let client = TokenClient::new(base, bearer)?;
```

Remove the now-unused `ENV_API_TOKEN` constant at `src/token_cli.rs:24`.

- [ ] **Step 6: Wire the resolver into `mcp-serve --remote`**

`mcp-serve --remote` already implements precedence steps 1 and 2 by hand
at `src/main.rs:314-318`. Extend it with step 3 — the cached login —
while keeping the credential optional, because a remote server with auth
disabled is a legitimate configuration.

Replace:

```rust
            // Fall back to NETCIDR_API_TOKEN when --api-token is not passed
            // (clap's `env` feature is not enabled, so resolve it here).
            let api_token = api_token
                .or_else(|| std::env::var("NETCIDR_API_TOKEN").ok())
                .filter(|t| !t.trim().is_empty());
```

with:

```rust
            // Precedence: --api-token, then NETCIDR_API_TOKEN, then a
            // cached `netcidr login` for this server. clap's `env` feature
            // is not enabled, so the env fallback is resolved here.
            //
            // Unlike `netcidr token`, a missing credential is not fatal:
            // a remote server may have auth disabled entirely. A resolver
            // error therefore degrades to "no token" rather than aborting.
            let api_token = match api_token
                .or_else(|| std::env::var("NETCIDR_API_TOKEN").ok())
                .filter(|t| !t.trim().is_empty())
            {
                Some(token) => Some(token),
                None => match api_url.as_deref() {
                    Some(url) => match netcidr::credentials::normalize_api_url(url) {
                        Ok(normalized) => {
                            netcidr::credentials::resolve_credential(&normalized, None)
                                .await
                                .ok()
                        }
                        Err(_) => None,
                    },
                    None => None,
                },
            };
```

This arm is already inside an `async` block, so `.await` is available
directly — no executor plumbing is needed.

- [ ] **Step 7: Verify the existing tests still pass**

Run: `cargo test --test cli_token`
Expected: PASS — the test sets `NETCIDR_API_TOKEN`, which is still
precedence step 2, so its behavior is unchanged.

Run: `cargo build --features mcp`
Expected: clean build — the `mcp-serve` arm is feature-gated.

- [ ] **Step 8: Commit**

```bash
just fmt
git add src/credentials.rs src/token_cli.rs src/main.rs tests/credential_resolver.rs
git commit -m "feat(credentials): add the shared credential resolver

Precedence is --token, then NETCIDR_API_TOKEN, then the cached login,
then an error naming 'netcidr login'. Explicit beats implicit so CI and
exported PATs are never shadowed by a desktop session. Stale ID tokens
refresh transparently; a dead refresh token drops the entry rather than
retrying forever."
```

---

### Task 7: Loopback callback listener

**Files:**
- Create: `src/login_cli.rs` (partial — listener only)
- Modify: `src/main.rs` (add `mod login_cli;`)
- Test: inline `mod tests` in `src/login_cli.rs`

**Interfaces:**
- Consumes: `NetcidrError::Auth` (Task 3).
- Produces, used by Task 8:
  - `pub struct Callback { pub code: String }`
  - `pub async fn wait_for_callback(listener: TcpListener, expected_state: String, timeout: Duration) -> Result<Callback>`

- [ ] **Step 1: Write the failing tests**

Create `src/login_cli.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    async fn listener_and_url() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, format!("http://{addr}/callback"))
    }

    #[tokio::test]
    async fn accepts_a_matching_state_and_returns_the_code() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        let response = reqwest::get(format!("{url}?code=the-code&state=the-state"))
            .await
            .unwrap();
        assert!(response.status().is_success());

        let callback = task.await.unwrap().unwrap();
        assert_eq!(callback.code, "the-code");
    }

    #[tokio::test]
    async fn rejects_a_tampered_state() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        let _ = reqwest::get(format!("{url}?code=the-code&state=wrong-state")).await;

        let err = task.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("state validation"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn surfaces_a_declined_sign_in() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        let _ = reqwest::get(format!("{url}?error=access_denied&state=the-state")).await;

        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("declined"), "got: {err}");
    }

    #[tokio::test]
    async fn times_out_when_no_callback_arrives() {
        let (listener, _url) = listener_and_url().await;

        let err = wait_for_callback(listener, "the-state".to_string(), Duration::from_millis(150))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("timed out"), "got: {err}");
    }

    #[test]
    fn parses_query_parameters_with_percent_encoding() {
        let params = parse_query("code=a%2Fb&state=x%20y");
        assert_eq!(params.get("code").map(String::as_str), Some("a/b"));
        assert_eq!(params.get("state").map(String::as_str), Some("x y"));
    }
}
```

- [ ] **Step 2: Register the module and run the tests**

Add to `src/main.rs`, beside `mod token_cli;`:

```rust
mod login_cli;
```

Run: `cargo test --bin netcidr login_cli::`
Expected: FAIL — `cannot find function 'wait_for_callback' in this scope`

- [ ] **Step 3: Implement the listener**

Prepend above the test module in `src/login_cli.rs`:

```rust
//! `netcidr login` / `netcidr logout`.
//!
//! Runs a Google OAuth authorization-code flow with PKCE against a
//! loopback redirect, then caches the credential. The listener binds
//! 127.0.0.1 explicitly, serves exactly one request, and shuts down.

use std::collections::HashMap;
use std::time::Duration;

use netcidr::error::{NetcidrError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Successful authorization callback.
pub struct Callback {
    pub code: String,
}

const SUCCESS_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>netcidr</title>\
<body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
<h1>Signed in</h1><p>You can close this tab and return to the terminal.</p>";

const FAILURE_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>netcidr</title>\
<body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
<h1>Sign-in failed</h1><p>Return to the terminal for details.</p>";

/// Wait for the browser to hit the loopback redirect, validate `state`,
/// and return the authorization code.
///
/// Reads only the request line, which is all that carries the query
/// string — the flow never needs headers or a body.
pub async fn wait_for_callback(
    listener: TcpListener,
    expected_state: String,
    timeout: Duration,
) -> Result<Callback> {
    let accepted = tokio::time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| {
            NetcidrError::Auth(format!(
                "timed out after {}s waiting for the browser callback",
                timeout.as_secs()
            ))
        })?;

    let (mut stream, _peer) = accepted
        .map_err(|e| NetcidrError::Auth(format!("callback connection failed: {e}")))?;

    let mut buffer = [0u8; 4096];
    let read = stream
        .read(&mut buffer)
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not read the callback request: {e}")))?;
    let request = String::from_utf8_lossy(&buffer[..read]);

    let outcome = interpret_request(&request, &expected_state);
    let page = if outcome.is_ok() {
        SUCCESS_PAGE
    } else {
        FAILURE_PAGE
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    outcome
}

/// Pull the query string out of the HTTP request line and turn it into a
/// result. Split out from the socket handling so it is directly testable.
fn interpret_request(request: &str, expected_state: &str) -> Result<Callback> {
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line.split_whitespace().nth(1).unwrap_or_default();
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let params = parse_query(query);

    if let Some(error) = params.get("error") {
        return Err(match error.as_str() {
            "access_denied" => NetcidrError::Auth("sign-in was declined".to_string()),
            other => NetcidrError::Auth(format!("authorization failed: {other}")),
        });
    }

    let state = params.get("state").map(String::as_str).unwrap_or_default();
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(NetcidrError::Auth(
            "authorization response failed state validation - aborting".to_string(),
        ));
    }

    let code = params
        .get("code")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            NetcidrError::Auth("authorization response carried no code".to_string())
        })?;

    Ok(Callback { code: code.clone() })
}

/// Decode the query string. `form_urlencoded` handles both `%XX` escapes
/// and `+` as space, and is already in the dependency tree via axum.
fn parse_query(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

/// Length-independent comparison for the `state` check. Mirrors the helper
/// in `auth.rs`; duplicated rather than made public because the bin and
/// lib halves of this crate should not grow a dependency for six lines.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --bin netcidr login_cli::`
Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
just fmt
git add src/login_cli.rs src/main.rs
git commit -m "feat(login): add the loopback authorization callback listener

Binds 127.0.0.1 explicitly, serves exactly one request, validates state
in constant time, and renders a close-this-tab page either way. Query
parsing is split from socket handling so it is directly testable."
```

---

### Task 8: `netcidr login` and `netcidr logout`

**Files:**
- Modify: `src/login_cli.rs` (add the orchestration)
- Modify: `src/cli.rs` (add `Login` and `Logout` to `Commands`), `src/main.rs:292` area (dispatch)
- Test: `tests/cli_login.rs` (create)

**Interfaces:**
- Consumes: everything from Tasks 2-7.
- Produces: `pub async fn handle_login(api_url: Option<&str>, no_browser: bool, timeout_secs: u64) -> Result<()>` and `pub async fn handle_logout(api_url: Option<&str>, all: bool) -> Result<()>`.

- [ ] **Step 1: Add the CLI commands**

In `src/cli.rs`, add to `pub enum Commands`, directly above the `Token` variant:

```rust
    /// Sign in to a netcidr server with Google and cache the credential
    Login {
        /// API base URL (overrides NETCIDR_API_URL)
        #[arg(long)]
        api_url: Option<String>,

        /// Print the authorization URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,

        /// Seconds to wait for the browser callback
        #[arg(long, default_value_t = 180)]
        timeout: u64,
    },

    /// Discard a cached login
    Logout {
        /// API base URL (overrides NETCIDR_API_URL)
        #[arg(long, conflicts_with = "all")]
        api_url: Option<String>,

        /// Discard every cached login
        #[arg(long)]
        all: bool,
    },
```

- [ ] **Step 2: Write the failing test**

Create `tests/cli_login.rs`:

```rust
//! CLI-level behavior of `netcidr login` that does not require a real
//! Google flow: the two ways a server can be unusable for login.

use std::process::Command;

fn netcidr() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netcidr"));
    cmd.env_remove("NETCIDR_API_TOKEN");
    cmd.env_remove("NETCIDR_API_URL");
    cmd
}

#[test]
fn login_rejects_a_malformed_api_url() {
    let output = netcidr()
        .args(["login", "--api-url", "not-a-url"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("http://") && stderr.contains("https://"),
        "got: {stderr}"
    );
}

#[test]
fn login_requires_an_api_url() {
    let output = netcidr().arg("login").output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("NETCIDR_API_URL"), "got: {stderr}");
}

#[tokio::test]
async fn login_reports_a_server_with_no_cli_client() {
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn features() -> Json<serde_json::Value> {
        Json(json!({ "ipam": true, "swagger": false }))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/features", get(features)))
            .await
            .unwrap();
    });

    let output = tokio::task::spawn_blocking(move || {
        netcidr()
            .args(["login", "--api-url", &format!("http://{addr}"), "--no-browser"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NETCIDR_OIDC_CLI_CLIENT_ID"),
        "got: {stderr}"
    );
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --test cli_login`
Expected: FAIL — `error: unrecognized subcommand 'login'`

- [ ] **Step 4: Implement the orchestration**

Append to `src/login_cli.rs`, above the test module:

```rust
use netcidr::credentials::{Account, CredentialStore, normalize_api_url};
use netcidr::oauth::{self, Pkce};
use serde::Deserialize;

const ENV_API_URL: &str = "NETCIDR_API_URL";

/// Identity echoed back by `GET /me`, used to confirm the server actually
/// accepts the freshly minted token.
#[derive(Deserialize)]
struct Me {
    email: Option<String>,
    #[serde(default)]
    is_allowlisted: bool,
}

fn resolve_api_url(cli_flag: Option<&str>) -> Result<String> {
    let raw = match cli_flag {
        Some(url) => url.to_string(),
        None => std::env::var(ENV_API_URL).map_err(|_| {
            NetcidrError::Auth(format!(
                "no API URL - pass --api-url or set {ENV_API_URL}"
            ))
        })?,
    };
    normalize_api_url(&raw)
}

/// Confirm the server accepts this token, and learn the verified email.
/// Checking against the live server tests the audience list it actually
/// has, rather than the CLI's assumption about it.
async fn verify_with_server(api_url: &str, id_token: &str) -> Result<Me> {
    let response = reqwest::Client::new()
        .get(format!("{api_url}/me"))
        .bearer_auth(id_token)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not reach {api_url}: {e}")))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(NetcidrError::Auth(format!(
            "signed in, but {api_url} will not accept the token \
             (its NETCIDR_OIDC_AUDIENCE likely omits this CLI client)"
        )));
    }
    if !response.status().is_success() {
        return Err(NetcidrError::Auth(format!(
            "{api_url}/me returned HTTP {}",
            response.status().as_u16()
        )));
    }
    response
        .json::<Me>()
        .await
        .map_err(|e| NetcidrError::Auth(format!("unreadable /me response: {e}")))
}

fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let mut command = {
        let mut c = std::process::Command::new("true");
        let _ = url;
        c
    };

    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub async fn handle_login(
    api_url: Option<&str>,
    no_browser: bool,
    timeout_secs: u64,
) -> Result<()> {
    let api_url = resolve_api_url(api_url)?;
    let auth = oauth::fetch_auth_features(&api_url).await?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not bind a loopback port: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| NetcidrError::Auth(format!("could not read the loopback port: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let pkce = Pkce::generate();
    let state = oauth::random_state();
    let auth_url = oauth::build_auth_url(
        &auth.cli_client_id,
        &redirect_uri,
        &pkce.challenge,
        &state,
    );

    if no_browser || !open_browser(&auth_url) {
        println!("Open this URL to sign in:\n\n  {auth_url}\n");
    } else {
        println!("Opening your browser to sign in with Google...");
    }

    let callback = wait_for_callback(
        listener,
        state,
        Duration::from_secs(timeout_secs),
    )
    .await?;

    let tokens = oauth::exchange_code(
        oauth::TOKEN_ENDPOINT,
        &auth.cli_client_id,
        &auth.cli_client_secret,
        &callback.code,
        &pkce.verifier,
        &redirect_uri,
    )
    .await?;

    let me = verify_with_server(&api_url, &tokens.id_token).await?;
    let email = me.email.unwrap_or_else(|| "(unknown)".to_string());

    let mut store = CredentialStore::load()?;
    store.insert(
        &api_url,
        Account {
            email: email.clone(),
            // exchange_code already rejected a response without one.
            refresh_token: tokens.refresh_token.clone().unwrap_or_default(),
            id_token: tokens.id_token,
            expires_at: oauth::expiry_from_now(tokens.expires_in),
            client_id: auth.cli_client_id,
        },
    );
    store.save()?;

    println!("Signed in as {email}");
    println!("Credential cached in {}", netcidr::credentials::credentials_path()?.display());
    if !me.is_allowlisted {
        println!(
            "\nNote: {email} is not yet admitted by this server's users directory.\n\
             Sign-in worked, but IPAM calls will be refused until an admin adds you."
        );
    }
    Ok(())
}

pub async fn handle_logout(api_url: Option<&str>, all: bool) -> Result<()> {
    let mut store = CredentialStore::load()?;

    if all {
        if store.is_empty() {
            println!("No cached logins.");
            return Ok(());
        }
        store.clear();
        store.save()?;
        println!("Discarded every cached login.");
        return Ok(());
    }

    let api_url = resolve_api_url(api_url)?;
    if store.remove(&api_url) {
        store.save()?;
        println!("Signed out of {api_url}");
    } else {
        println!("Not signed in to {api_url}");
    }
    Ok(())
}
```

Note the `is_allowlisted` message: sign-in can succeed while the users
directory still refuses the account (closed allowlist mode). Saying so at
login prevents a confusing 403 later.

- [ ] **Step 5: Wire the dispatch**

In `src/main.rs`, add these arms to the `match` beside `Some(Commands::Token { .. })`:

```rust
        Some(Commands::Login {
            api_url,
            no_browser,
            timeout,
        }) => {
            if let Err(e) =
                login_cli::handle_login(api_url.as_deref(), no_browser, timeout).await
            {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Logout { api_url, all }) => {
            if let Err(e) = login_cli::handle_logout(api_url.as_deref(), all).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --test cli_login`
Expected: PASS, all three.

- [ ] **Step 7: Verify shell completions still generate**

Run: `cargo run -- completions bash | head -20`
Expected: output includes `login` and `logout`.

- [ ] **Step 8: Run the full check**

Run: `just check`
Expected: zero failures.

- [ ] **Step 9: Commit**

```bash
just fmt
git add src/login_cli.rs src/cli.rs src/main.rs tests/cli_login.rs
git commit -m "feat(cli): add netcidr login and netcidr logout

login runs the PKCE loopback flow against the client advertised on
/features, verifies the result with GET /me, and caches the credential.
Verifying against the live server tests the audience list it actually has
rather than the CLI's assumption, and surfaces a not-yet-allowlisted
account at login instead of as a puzzling 403 later."
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md` (PAT section around line 746; env table around line 1020)
- Modify: `CHANGELOG.md` (`[Unreleased]`)
- Modify: `src/token_cli.rs:1-9` (stale module comment)

**Interfaces:**
- Consumes: the finished behavior from Tasks 1-8.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Fix the stale comment**

Replace the header comment block at the top of `src/token_cli.rs` (lines 1-9):

```rust
//! `netcidr token …` CLI handler. Talks to a remote `netcidr serve`
//! instance over the `/me/tokens` REST endpoints. Auth is resolved by
//! `credentials::resolve_credential` — an explicit `NETCIDR_API_TOKEN`
//! first, then a cached `netcidr login` session.
//!
//! The HTTP client is intentionally local to this module rather than
//! reusing `mcp_client::HttpIpamClient`, because that client targets
//! `/ipam/*` and models a long-lived proxy session rather than a handful
//! of one-shot admin calls.
```

- [ ] **Step 2: Update the README PAT section**

In `README.md`, replace the paragraph at line 755-757 that reads
`# Required env (point at your server, set your OIDC ID token).` and its
`export NETCIDR_API_TOKEN="<your-OIDC-id-token>"` line with:

```markdown
Sign in once, then mint tokens:

```bash
netcidr login --api-url https://your-server
# Opens your browser for Google sign-in; caches the credential in
# ~/.config/netcidr/credentials.json (mode 0600).

netcidr token create --name ci --expires-in 90d --role allocator
```

`netcidr login` needs the server to advertise a CLI OAuth client — see
[CLI sign-in setup](#cli-sign-in-setup). If it does not, mint your first
token from the dashboard's **Tokens** page instead, then set
`NETCIDR_API_TOKEN` to a PAT for `/ipam/*` calls.

Sign out with `netcidr logout` (or `netcidr logout --all`). Logout clears
the local credential only; it does not revoke the grant at Google.
```

- [ ] **Step 3: Add the CLI sign-in setup section**

Add a new `#### CLI sign-in setup` subsection immediately after the PAT
section in `README.md`:

```markdown
#### CLI sign-in setup

`netcidr login` runs an OAuth authorization-code flow with PKCE against a
Google **Desktop app** client — a different client from the dashboard's
Web client, because Google stamps the ID token's `aud` with whichever
client performed the sign-in.

1. In the same Google Cloud project as your Web client, create a second
   OAuth client of type **Desktop app**.
2. Add its client ID to `NETCIDR_OIDC_AUDIENCE`, which is now
   comma-separated:
   ```
   NETCIDR_OIDC_AUDIENCE="<web-client-id>,<desktop-client-id>"
   ```
3. Set `NETCIDR_OIDC_CLI_CLIENT_ID` and `NETCIDR_OIDC_CLI_CLIENT_SECRET`
   to the desktop client's credentials.

The server then advertises the desktop client on its unauthenticated
`/features` endpoint, so users need no local OAuth configuration.

**On serving the client secret publicly:** a Desktop-app client secret is
non-confidential by design — an installed application cannot keep a
secret (RFC 8252 §8.5), and PKCE is what actually secures the exchange.
This is the same posture `gcloud` takes.

**On the audience list:** any token minted by any listed client is
accepted. List only clients you control.

Skipping this setup changes nothing — `netcidr login` simply reports that
the server has no CLI client configured, and every other auth path keeps
working as before.
```

- [ ] **Step 4: Update the env var table**

Add these rows to the configuration table around `README.md:1020`,
alongside `NETCIDR_AUTH_MODE`:

```markdown
| `NETCIDR_OIDC_AUDIENCE` | For OIDC | — | Accepted ID token audiences, comma-separated (web client, desktop client) |
| `NETCIDR_OIDC_CLI_CLIENT_ID` | No | — | Desktop-app OAuth client ID advertised to `netcidr login` |
| `NETCIDR_OIDC_CLI_CLIENT_SECRET` | No | — | Matching client secret; non-confidential by design (RFC 8252 §8.5) |
```

If a `NETCIDR_OIDC_AUDIENCE` row already exists, replace it rather than
adding a duplicate.

- [ ] **Step 5: Add the CHANGELOG entry**

Under `## [Unreleased]` in `CHANGELOG.md`, add:

```markdown
### Added

- `netcidr login` / `netcidr logout` — Google OAuth authorization-code
  flow with PKCE over a loopback redirect. Credentials cache to
  `~/.config/netcidr/credentials.json` (mode 0600), keyed by API URL, and
  refresh silently. This removes the previous requirement to mint a first
  PAT from the dashboard.
- `/features` now advertises a deployment's CLI OAuth client, so the CLI
  needs no local OAuth configuration.

### Changed

- `NETCIDR_OIDC_AUDIENCE` accepts a comma-separated list of audiences, so
  a deployment can admit both the dashboard's web client and the CLI's
  desktop client. Single values keep working unchanged.
- `netcidr token` resolves its bearer through a shared precedence chain:
  `--token`, then `NETCIDR_API_TOKEN`, then a cached login. Explicit
  sources still win, so CI behavior is unchanged.
```

- [ ] **Step 6: Verify the docs build and links resolve**

Run: `just check`
Expected: zero failures.

Manually confirm the `#cli-sign-in-setup` anchor referenced in Step 2
matches the heading added in Step 3.

- [ ] **Step 7: Commit**

```bash
just fmt
git add README.md CHANGELOG.md src/token_cli.rs
git commit -m "docs: document netcidr login and the CLI OAuth client setup

Also corrects the token_cli module comment, which claimed
HttpIpamClient never carries an Authorization header - it does."
```

---

## Verification

After all tasks, confirm end-to-end:

- [ ] `just check` passes with zero failures.
- [ ] `env -u NETCIDR_API_TOKEN cargo test` passes (the resolver tests are
      sensitive to an exported token).
- [ ] `cargo test --features swagger` passes — the OpenAPI spec still builds.
- [ ] `cargo run -- login --help` and `cargo run -- logout --help` render.
- [ ] A deployment with none of the new env vars set behaves exactly as
      before: `/features` has no `auth` block, OIDC auth works with a
      single-valued `NETCIDR_OIDC_AUDIENCE`, and `netcidr token` still
      works with `NETCIDR_API_TOKEN`.

## Deferred

Called out so nobody assumes they were missed:

- **Device-code flow** for genuinely headless hosts. `--no-browser` prints
  the URL, but the loopback redirect still needs port forwarding over SSH.
- **`netcidr whoami`.** `/me` already answers it.
- **Revoking the grant at Google on logout.** Local state only.
- **Non-Google OIDC providers.** The server validates Google ID tokens
  specifically.
