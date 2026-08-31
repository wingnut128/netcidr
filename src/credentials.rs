//! On-disk credential cache for `netcidr login`.
//!
//! One JSON file at `~/.config/netcidr/credentials.json`, mode `0600`,
//! keyed by normalized API URL so a user can stay signed in to several
//! deployments at once. Refresh tokens are long-lived credentials, so the
//! loader refuses to read a file that is group- or world-readable rather
//! than silently using it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{NetcidrError, Result};

/// Current on-disk schema version. Bump when the shape changes so a future
/// reader can migrate instead of guessing.
const SCHEMA_VERSION: u32 = 1;

/// Cached credential for a single netcidr deployment.
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

/// Hand-written so `{:?}` never prints the refresh or ID token — mirrors
/// `AuthConfig`'s `Debug` impl in `src/auth.rs`, which redacts its secret
/// fields the same way.
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

    /// Writes via a sibling temp file (created `0600` from birth) and an
    /// atomic rename, rather than truncating `path` in place. If `path`
    /// already exists — restored from backup, copied by another tool,
    /// left over from an older build — a plain `write()` would truncate
    /// it and leave the refresh token sitting in a file whose mode isn't
    /// fixed up until the *next* syscall; a crash or a `set_permissions`
    /// error in that window exposes the secret. Renaming over the target
    /// is atomic, so the real file is never observed holding the secret
    /// at the wrong mode, and a crash mid-write leaves the previous file
    /// (or no file) intact instead of a truncated one.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");

        let result = (|| -> Result<()> {
            let mut f = open_owner_only(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, path)?;
            Ok(())
        })();

        if result.is_err() {
            // Best-effort cleanup: don't leave a temp file holding a
            // secret behind just because the write or rename failed.
            let _ = std::fs::remove_file(&tmp);
        }
        result?;

        // Redundant on unix in the common case — `open_owner_only` already
        // creates the temp file at 0600, and rename preserves the mode of
        // the file being renamed, not the target it replaces. Kept anyway
        // so `save_to` stays correct if that file is ever created some
        // other way, and so non-unix targets (where `open_owner_only` is a
        // no-op on mode) still end up owner-restricted where the platform
        // supports it.
        set_owner_only(path)?;
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
            NetcidrError::Auth(format!(
                "API URL {trimmed:?} must start with http:// or https://"
            ))
        })?;
    let host_and_path = rest.trim_end_matches('/');
    if host_and_path.is_empty() {
        return Err(NetcidrError::Auth(format!(
            "API URL {trimmed:?} has no host"
        )));
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

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Create (or truncate) `path` for writing, owner-only from the moment it
/// is born on unix — there is never a window where the temp file exists
/// with a wider mode. On non-unix platforms this is a plain create/
/// truncate; `save_to` still calls `set_owner_only` on the final path
/// afterward for whatever mode enforcement the platform offers.
#[cfg(unix)]
fn open_owner_only(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(NetcidrError::from)
}

#[cfg(not(unix))]
fn open_owner_only(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(NetcidrError::from)
}

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
/// The entire precedence chain — including the explicit and env steps —
/// lives in [`resolve_from`]; this function only supplies the production
/// values (the default store path, the real token endpoint, and a lazy
/// provider of the refresh client secret) and delegates. Keeping exactly
/// one copy of the chain means a future edit can't desync two hand-copied
/// versions of it.
///
/// The client secret needed for a refresh comes from the server's
/// `/features` endpoint, not from the environment — `NETCIDR_OIDC_CLI_*`
/// are server-side settings and are never present on a client machine.
/// It is passed to `resolve_from` as a closure rather than a resolved
/// `String` so that `/features` is only fetched when a refresh actually
/// happens: `resolve_from` checks the explicit/env/cached-and-valid cases
/// first and calls the closure exclusively on the refresh path, so the
/// common case (explicit token, env token, or a still-valid cached token)
/// never touches the network for this call.
pub async fn resolve_credential(api_url: &str, explicit: Option<&str>) -> Result<String> {
    let env_token = std::env::var("NETCIDR_API_TOKEN").ok();
    let path = credentials_path()?;
    let api_url_owned = api_url.to_string();

    resolve_from(
        &path,
        crate::oauth::TOKEN_ENDPOINT,
        api_url,
        explicit,
        env_token.as_deref(),
        || async move {
            let auth = crate::oauth::fetch_auth_features(&api_url_owned).await?;
            Ok(auth.cli_client_secret)
        },
    )
    .await
}

/// Injectable form of [`resolve_credential`], and the sole place the
/// explicit/env/cache/refresh precedence chain is implemented. Production
/// callers go through `resolve_credential`; tests pass a temp path, a stub
/// token endpoint, and an explicit `env_token` — this function never reads
/// process environment itself, so its behavior does not depend on
/// unstated shell state.
///
/// `client_secret` is a lazy provider (invoked at most once, only when a
/// refresh is actually needed) rather than a plain string, so that callers
/// whose secret comes from a network call (`resolve_credential`'s
/// `/features` fetch) don't pay for it on the explicit/env/valid-cache
/// paths.
pub async fn resolve_from<F, Fut>(
    store_path: &Path,
    token_endpoint: &str,
    api_url: &str,
    explicit: Option<&str>,
    env_token: Option<&str>,
    client_secret: F,
) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    if let Some(token) = explicit.map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(token.to_string());
    }
    if let Some(token) = env_token.map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(token.to_string());
    }

    let mut store = CredentialStore::load_from(store_path)?;
    let account = store.get(api_url).cloned().ok_or_else(|| {
        NetcidrError::NotAuthenticated(format!(
            "not authenticated for {api_url} - run `netcidr login`"
        ))
    })?;

    if !is_expired(&account.expires_at, EXPIRY_SKEW_SECONDS) {
        return Ok(account.id_token);
    }

    let secret = client_secret().await?;

    let refreshed = match crate::oauth::refresh_id_token(
        token_endpoint,
        &account.client_id,
        &secret,
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
    fn save_fixes_permissions_on_a_preexisting_looser_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        // Simulate a file restored from backup / copied by another tool /
        // left by an older build: it exists already, at 0644, before we
        // ever call save_to.
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut store = CredentialStore::default();
        store.insert("https://server", sample_account());
        store.save_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "temp file was left behind: {tmp:?}");
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
        assert_eq!(
            normalize_api_url("https://server/").unwrap(),
            "https://server"
        );
        assert_eq!(
            normalize_api_url("  https://server//  ").unwrap(),
            "https://server"
        );
    }

    #[test]
    fn debug_redacts_tokens() {
        let account = sample_account();
        let formatted = format!("{account:?}");
        assert!(
            !formatted.contains(&account.refresh_token),
            "refresh token leaked into Debug output: {formatted}"
        );
        assert!(
            !formatted.contains(&account.id_token),
            "id token leaked into Debug output: {formatted}"
        );

        let mut store = CredentialStore::default();
        store.insert("https://server", account.clone());
        let store_formatted = format!("{store:?}");
        assert!(
            !store_formatted.contains(&account.refresh_token),
            "refresh token leaked via CredentialStore Debug: {store_formatted}"
        );
        assert!(
            !store_formatted.contains(&account.id_token),
            "id token leaked via CredentialStore Debug: {store_formatted}"
        );
    }
}
