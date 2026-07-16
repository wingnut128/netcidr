pub mod bootstrap;
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
use tracing::info;

/// Create and initialize an IPAM store based on the configured backend.
///
/// Emits one `tracing::info!` line naming the chosen backend so operators can
/// confirm at startup (CloudWatch / journald) which backend the process is
/// talking to. The Postgres branch logs **host + port + database only** — the
/// raw URL is never logged because it normally carries a password.
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
            info!(backend = "sqlite", path = %db_path, "IPAM store initialized");
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
                log_postgres_target(&url);
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

/// Emit an `info!` line describing the Postgres target (host, port, database)
/// without ever logging the password or username carried in the URL.
///
/// Parsing failures fall through to a non-revealing log line; the connection
/// attempt itself will produce a downstream error if the URL is truly broken.
#[cfg(feature = "ipam-postgres")]
fn log_postgres_target(url: &str) {
    use sqlx::postgres::PgConnectOptions;
    use std::str::FromStr;
    match PgConnectOptions::from_str(url) {
        Ok(opts) => {
            info!(
                backend = "postgres",
                host = opts.get_host(),
                port = opts.get_port(),
                database = opts.get_database().unwrap_or("<default>"),
                "IPAM store initialized",
            );
        }
        Err(_) => {
            info!(
                backend = "postgres",
                "IPAM store initialized (URL not parseable for host/database extraction)",
            );
        }
    }
}

#[cfg(all(test, feature = "ipam-postgres"))]
mod startup_log_tests {
    use super::log_postgres_target;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct BufMaker(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for BufMaker {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            BufWriter(self.0.clone())
        }
    }

    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture<F: FnOnce()>(f: F) -> String {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BufMaker(buf.clone()))
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(buf.lock().unwrap().clone()).expect("utf8")
    }

    #[test]
    fn postgres_log_never_contains_credentials() {
        let url = "postgres://alice:s3cr3t_PaSSworD@db.example.com:5432/netcidr_prod";
        let out = capture(|| log_postgres_target(url));
        assert!(
            out.contains("db.example.com"),
            "host missing from log: {out}"
        );
        assert!(
            out.contains("netcidr_prod"),
            "database name missing from log: {out}"
        );
        assert!(out.contains("5432"), "port missing from log: {out}");
        assert!(
            !out.contains("s3cr3t_PaSSworD"),
            "PASSWORD LEAKED into log: {out}"
        );
        assert!(
            !out.contains("alice"),
            "username also leaked into log: {out}"
        );
    }

    #[test]
    fn postgres_log_handles_unparseable_url_without_panic() {
        let out = capture(|| log_postgres_target("not a postgres url at all"));
        assert!(out.contains("backend"), "expected backend log: {out}");
        assert!(
            !out.contains("not a postgres url at all"),
            "raw URL leaked into log: {out}"
        );
    }
}

/// Read `total_hosts` from a text column (preferred) with fallback to an i64 column.
/// Used by all storage backends to handle u128 values that exceed i64 range.
pub(crate) fn read_total_hosts(text: Option<String>, legacy_i64: i64) -> u128 {
    text.as_deref()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(legacy_i64 as u128)
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
