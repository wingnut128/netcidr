pub mod config;
pub mod idempotency;
pub mod models;
pub mod operations;
pub mod output;
#[cfg(feature = "ipam-postgres")]
pub mod postgres;
pub mod sqlite;
pub mod store;

use crate::error::{NetcidrError, Result};
use config::IpamConfig;
use std::sync::Arc;
use store::IpamStore;

/// Create and initialize an IPAM store based on the configured backend.
///
/// - `cli_db`: SQLite database path override from CLI `--db` flag
/// - `cli_db_url`: PostgreSQL connection URL override from CLI `--ipam-db-url` flag
pub async fn create_store(
    config: &IpamConfig,
    cli_db: Option<&str>,
    cli_db_url: Option<&str>,
) -> Result<Arc<dyn IpamStore>> {
    match config.backend {
        config::Backend::Sqlite => {
            let db_path = config::resolve_db_path(cli_db, &config.sqlite);
            let store = sqlite::SqliteStore::new(&db_path)?;
            store.initialize().await?;
            store.migrate().await?;
            Ok(Arc::new(store))
        }
        config::Backend::Postgres => {
            #[cfg(feature = "ipam-postgres")]
            {
                let url = config::resolve_postgres_url(cli_db_url, &config.postgres)
                    .ok_or_else(|| {
                        NetcidrError::DatabaseError(
                            "PostgreSQL URL not configured. Set --ipam-db-url, NETCIDR_IPAM_DB_URL, or [ipam.postgres] url in config.".to_string(),
                        )
                    })?;
                let store = postgres::PostgresStore::new(&url, &config.postgres).await?;
                store.initialize().await?;
                store.migrate().await?;
                Ok(Arc::new(store))
            }
            #[cfg(not(feature = "ipam-postgres"))]
            {
                let _ = cli_db_url;
                Err(NetcidrError::DatabaseError(
                    "PostgreSQL backend not available. Rebuild with --features ipam-postgres"
                        .to_string(),
                ))
            }
        }
    }
}

/// Read `total_hosts` from a text column (preferred) with fallback to an i64 column.
/// Used by all storage backends to handle u128 values that exceed i64 range.
pub(crate) fn read_total_hosts(text: Option<String>, legacy_i64: i64) -> u128 {
    text.as_deref()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(legacy_i64 as u128)
}

/// Clamp a u128 to i64::MAX for the legacy INTEGER column.
pub(crate) fn total_hosts_as_i64(total: u128) -> i64 {
    if total > i64::MAX as u128 {
        i64::MAX
    } else {
        total as i64
    }
}

/// Parse a CIDR string and return (network_address, broadcast_address, prefix_length, total_hosts, ip_version).
/// Shared by all storage backends.
pub(crate) fn parse_cidr_metadata(cidr: &str) -> Result<(String, String, u8, u128, u8)> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| NetcidrError::InvalidCidr(cidr.to_string()))?;

    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| NetcidrError::InvalidCidr(cidr.to_string()))?;

    if let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() {
        if prefix > 32 {
            return Err(NetcidrError::InvalidPrefixLength(prefix));
        }
        let addr_u32 = u32::from(addr);
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let network = addr_u32 & mask;
        let broadcast = network | !mask;
        let total: u128 = 1u128 << (32 - prefix);
        Ok((
            std::net::Ipv4Addr::from(network).to_string(),
            std::net::Ipv4Addr::from(broadcast).to_string(),
            prefix,
            total,
            4,
        ))
    } else if let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() {
        if prefix > 128 {
            return Err(NetcidrError::InvalidPrefixLength(prefix));
        }
        let addr_u128 = u128::from(addr);
        let mask = if prefix == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix)
        };
        let network = addr_u128 & mask;
        let last = network | !mask;
        let bits = 128 - prefix;
        // 1 << 128 overflows u128; use checked shift, falling back to u128::MAX
        let total: u128 = if bits == 128 {
            u128::MAX
        } else {
            1u128 << bits
        };
        Ok((
            std::net::Ipv6Addr::from(network).to_string(),
            std::net::Ipv6Addr::from(last).to_string(),
            prefix,
            total,
            6,
        ))
    } else {
        Err(NetcidrError::InvalidCidr(cidr.to_string()))
    }
}
