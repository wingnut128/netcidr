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
#[derive(Clone, Debug, Serialize, Deserialize)]
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

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
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
}
