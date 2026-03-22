use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[default]
    Sqlite,
    Postgres,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite => write!(f, "sqlite"),
            Self::Postgres => write!(f, "postgres"),
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" | "postgresql" => Ok(Self::Postgres),
            other => Err(format!("unknown IPAM backend: {other}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IpamConfig {
    pub enabled: bool,
    pub auto_init: bool,
    pub backend: Backend,
    pub sqlite: SqliteConfig,
    pub postgres: PostgresConfig,
}

impl Default for IpamConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_init: true,
            backend: Backend::default(),
            sqlite: SqliteConfig::default(),
            postgres: PostgresConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SqliteConfig {
    pub db_path: Option<String>,
    pub wal_mode: bool,
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            db_path: None,
            wal_mode: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PostgresConfig {
    pub url: Option<String>,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: 10,
            min_connections: 2,
        }
    }
}

/// Resolve the PostgreSQL connection URL using the following precedence:
/// 1. CLI `--ipam-db-url <url>` flag (passed as `cli_url`)
/// 2. `NETCIDR_IPAM_DB_URL` environment variable
/// 3. `url` in config file (via `PostgresConfig`)
pub fn resolve_postgres_url(cli_url: Option<&str>, config: &PostgresConfig) -> Option<String> {
    let env_val = std::env::var("NETCIDR_IPAM_DB_URL").ok();
    resolve_postgres_url_inner(cli_url, env_val.as_deref(), config)
}

fn resolve_postgres_url_inner(
    cli_url: Option<&str>,
    env_url: Option<&str>,
    config: &PostgresConfig,
) -> Option<String> {
    if let Some(url) = cli_url {
        return Some(url.to_string());
    }
    if let Some(url) = env_url
        && !url.is_empty()
    {
        return Some(url.to_string());
    }
    config.url.clone()
}

/// Resolve the SQLite database path using the following precedence:
/// 1. CLI `--db <path>` flag (passed as `cli_db`)
/// 2. `NETCIDR_DB` environment variable
/// 3. `db_path` in config file (via `SqliteConfig`)
/// 4. Default: `$XDG_DATA_HOME/netcidr/netcidr.db` (or `~/.local/share/netcidr/netcidr.db`)
pub fn resolve_db_path(cli_db: Option<&str>, config: &SqliteConfig) -> String {
    let env_val = std::env::var("NETCIDR_DB").ok();
    resolve_db_path_inner(cli_db, env_val.as_deref(), config)
}

/// Pure resolution logic, separated from environment access for testability.
fn resolve_db_path_inner(
    cli_db: Option<&str>,
    env_db: Option<&str>,
    config: &SqliteConfig,
) -> String {
    if let Some(path) = cli_db {
        return path.to_string();
    }

    if let Some(path) = env_db
        && !path.is_empty()
    {
        return path.to_string();
    }

    if let Some(ref path) = config.db_path {
        return path.clone();
    }

    default_db_path()
}

fn default_db_path() -> String {
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("netcidr");
    data_dir.join("netcidr.db").to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_flag_takes_precedence() {
        let config = SqliteConfig {
            db_path: Some("/config/path.db".to_string()),
            wal_mode: true,
        };
        let path = resolve_db_path_inner(Some("/tmp/test.db"), Some("/env/path.db"), &config);
        assert_eq!(path, "/tmp/test.db");
    }

    #[test]
    fn test_env_var_takes_precedence_over_config() {
        let config = SqliteConfig {
            db_path: Some("/config/path.db".to_string()),
            wal_mode: true,
        };
        let path = resolve_db_path_inner(None, Some("/env/path.db"), &config);
        assert_eq!(path, "/env/path.db");
    }

    #[test]
    fn test_empty_env_var_falls_through() {
        let config = SqliteConfig {
            db_path: Some("/config/path.db".to_string()),
            wal_mode: true,
        };
        let path = resolve_db_path_inner(None, Some(""), &config);
        assert_eq!(path, "/config/path.db");
    }

    #[test]
    fn test_config_path_used_when_no_cli_or_env() {
        let config = SqliteConfig {
            db_path: Some("/etc/netcidr/data.db".to_string()),
            wal_mode: true,
        };
        let path = resolve_db_path_inner(None, None, &config);
        assert_eq!(path, "/etc/netcidr/data.db");
    }

    #[test]
    fn test_default_path_fallback() {
        let config = SqliteConfig::default();
        let path = resolve_db_path_inner(None, None, &config);
        assert!(path.ends_with("netcidr/netcidr.db"));
    }

    #[test]
    fn test_backend_from_str() {
        assert_eq!("sqlite".parse::<Backend>().unwrap(), Backend::Sqlite);
        assert_eq!("postgres".parse::<Backend>().unwrap(), Backend::Postgres);
        assert_eq!("postgresql".parse::<Backend>().unwrap(), Backend::Postgres);
        assert!("unknown".parse::<Backend>().is_err());
    }

    #[test]
    fn test_postgres_url_cli_precedence() {
        let config = PostgresConfig {
            url: Some("postgresql://config".to_string()),
            ..Default::default()
        };
        let url =
            resolve_postgres_url_inner(Some("postgresql://cli"), Some("postgresql://env"), &config);
        assert_eq!(url, Some("postgresql://cli".to_string()));
    }

    #[test]
    fn test_postgres_url_env_precedence() {
        let config = PostgresConfig {
            url: Some("postgresql://config".to_string()),
            ..Default::default()
        };
        let url = resolve_postgres_url_inner(None, Some("postgresql://env"), &config);
        assert_eq!(url, Some("postgresql://env".to_string()));
    }

    #[test]
    fn test_postgres_url_config_fallback() {
        let config = PostgresConfig {
            url: Some("postgresql://config".to_string()),
            ..Default::default()
        };
        let url = resolve_postgres_url_inner(None, None, &config);
        assert_eq!(url, Some("postgresql://config".to_string()));
    }

    #[test]
    fn test_postgres_url_none_when_missing() {
        let config = PostgresConfig::default();
        let url = resolve_postgres_url_inner(None, None, &config);
        assert!(url.is_none());
    }

    #[test]
    fn test_postgres_url_empty_env_falls_through() {
        let config = PostgresConfig {
            url: Some("postgresql://config".to_string()),
            ..Default::default()
        };
        let url = resolve_postgres_url_inner(None, Some(""), &config);
        assert_eq!(url, Some("postgresql://config".to_string()));
    }

    #[test]
    fn test_invalid_ipam_toml_syntax() {
        let bad_toml = "enabled = {{{";
        let result = toml::from_str::<IpamConfig>(bad_toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_type_for_ipam_field() {
        let bad_toml = r#"enabled = "not_a_bool""#;
        let result = toml::from_str::<IpamConfig>(bad_toml);
        assert!(result.is_err(), "string for bool field should fail");
    }

    #[test]
    fn test_invalid_backend_name_in_toml() {
        let toml_str = r#"backend = "mysql""#;
        let result = toml::from_str::<IpamConfig>(toml_str);
        assert!(
            result.is_err(),
            "unrecognized backend should fail deserialization"
        );
    }

    #[test]
    fn test_invalid_backend_from_str() {
        let result = "mysql".parse::<Backend>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("unknown IPAM backend"));
    }

    #[test]
    fn test_backend_from_str_case_insensitive() {
        assert_eq!("SQLITE".parse::<Backend>().unwrap(), Backend::Sqlite);
        assert_eq!("Postgres".parse::<Backend>().unwrap(), Backend::Postgres);
        assert_eq!("POSTGRESQL".parse::<Backend>().unwrap(), Backend::Postgres);
    }

    #[test]
    fn test_empty_ipam_toml_yields_defaults() {
        let config: IpamConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert!(config.auto_init);
        assert_eq!(config.backend, Backend::Sqlite);
        assert!(config.sqlite.db_path.is_none());
        assert!(config.sqlite.wal_mode);
        assert!(config.postgres.url.is_none());
        assert_eq!(config.postgres.max_connections, 10);
        assert_eq!(config.postgres.min_connections, 2);
    }

    #[test]
    fn test_partial_ipam_config_fills_defaults() {
        let toml_str = r#"
            enabled = false
            backend = "postgres"
        "#;
        let config: IpamConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.backend, Backend::Postgres);
        // defaults for unspecified fields
        assert!(config.auto_init);
        assert!(config.sqlite.wal_mode);
        assert_eq!(config.postgres.max_connections, 10);
    }

    #[test]
    fn test_sqlite_config_with_special_chars_in_path() {
        let toml_str = r#"
            [sqlite]
            db_path = "/tmp/my data/netcidr (copy).db"
        "#;
        let config: IpamConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.sqlite.db_path,
            Some("/tmp/my data/netcidr (copy).db".to_string())
        );
    }

    #[test]
    fn test_sqlite_config_with_unicode_path() {
        let toml_str = r#"
            [sqlite]
            db_path = "/tmp/données/netcidr.db"
        "#;
        let config: IpamConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.sqlite.db_path,
            Some("/tmp/données/netcidr.db".to_string())
        );
    }

    #[test]
    fn test_postgres_config_boundary_connections() {
        let toml_str = r#"
            [postgres]
            max_connections = 0
            min_connections = 0
        "#;
        let config: IpamConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.postgres.max_connections, 0);
        assert_eq!(config.postgres.min_connections, 0);
    }

    #[test]
    fn test_negative_connections_rejected() {
        let toml_str = r#"
            [postgres]
            max_connections = -1
        "#;
        let result = toml::from_str::<IpamConfig>(toml_str);
        assert!(result.is_err(), "negative value for u32 should fail");
    }

    #[test]
    fn test_unknown_ipam_fields_accepted() {
        let toml_str = r#"
            enabled = true
            fake_field = "ignored"
        "#;
        let config: IpamConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
    }

    #[test]
    fn test_backend_display() {
        assert_eq!(Backend::Sqlite.to_string(), "sqlite");
        assert_eq!(Backend::Postgres.to_string(), "postgres");
    }

    #[test]
    fn test_backend_default_is_sqlite() {
        assert_eq!(Backend::default(), Backend::Sqlite);
    }

    #[test]
    fn test_db_path_with_spaces_via_resolution() {
        let config = SqliteConfig {
            db_path: Some("/path with spaces/db.sqlite".to_string()),
            wal_mode: true,
        };
        let path = resolve_db_path_inner(None, None, &config);
        assert_eq!(path, "/path with spaces/db.sqlite");
    }
}
