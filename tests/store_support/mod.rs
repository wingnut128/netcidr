//! Shared `IpamStore` factories for integration tests.
//!
//! Every factory returns a [`Held`] store: the store plus whatever must
//! outlive it (a temp directory, a per-test Postgres database). `Held`
//! derefs to the store, so tests call `IpamStore` methods on it directly.
//!
//! Postgres: each test gets its own database (`CREATE DATABASE t_<uuid>`),
//! dropped when the `Held` value drops. The server comes from
//! `NETCIDR_TEST_DATABASE_URL` (CI's service container); without it, a local
//! `postgres:16-alpine` container named `netcidr-test-pg` on port 15432 is
//! started on first use and left running for later test processes. Remove it
//! with `docker rm -f netcidr-test-pg`.

#![allow(dead_code)]

use std::ops::Deref;
use std::time::Duration;

use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;

/// A store plus the resources that must live as long as it does.
/// Fields drop in declaration order: the store (and its connection pool)
/// goes first, then the guard that deletes its backing database.
pub struct Held<S> {
    store: S,
    _guard: Guard,
}

impl<S> Deref for Held<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.store
    }
}

impl<S> Held<S> {
    /// Split into the store and its guard, e.g. to wrap the store in an
    /// `Arc`. The guard must be kept alive for as long as the store is used.
    pub fn into_parts(self) -> (S, Guard) {
        (self.store, self._guard)
    }
}

/// Keeps a store's backing database alive; cleans it up on drop.
pub enum Guard {
    None,
    TempDir(tempfile::TempDir),
    #[cfg(feature = "ipam-postgres")]
    Postgres(pg::TestDatabase),
}

/// Lock timeout for tests that hold a Lock Scope on purpose: long enough
/// that an uncontended unit never trips it, short enough to keep the
/// timeout tests fast.
pub const SHORT_LOCK_TIMEOUT: Duration = Duration::from_millis(300);

/// In-memory SQLite (pool of one connection).
pub async fn sqlite_memory_store() -> Held<SqliteStore> {
    sqlite_memory_store_with(netcidr::ipam::store::DEFAULT_LOCK_TIMEOUT).await
}

/// In-memory SQLite with [`SHORT_LOCK_TIMEOUT`].
pub async fn sqlite_memory_store_short_timeout() -> Held<SqliteStore> {
    sqlite_memory_store_with(SHORT_LOCK_TIMEOUT).await
}

async fn sqlite_memory_store_with(lock_timeout: Duration) -> Held<SqliteStore> {
    let store =
        SqliteStore::in_memory_with_lock_timeout(lock_timeout).expect("open in-memory sqlite");
    store.initialize().await.expect("initialize");
    store.migrate().await.expect("migrate");
    Held {
        store,
        _guard: Guard::None,
    }
}

/// A fresh file-backed SQLite database in a temp directory.
pub fn sqlite_file_path() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("ipam.db");
    (path.to_string_lossy().into_owned(), dir)
}

/// File-backed SQLite (multi-connection pool), as `netcidr serve` uses.
pub async fn sqlite_file_store() -> Held<SqliteStore> {
    sqlite_file_store_with(netcidr::ipam::store::DEFAULT_LOCK_TIMEOUT).await
}

/// File-backed SQLite with [`SHORT_LOCK_TIMEOUT`].
pub async fn sqlite_file_store_short_timeout() -> Held<SqliteStore> {
    sqlite_file_store_with(SHORT_LOCK_TIMEOUT).await
}

async fn sqlite_file_store_with(lock_timeout: Duration) -> Held<SqliteStore> {
    let (path, dir) = sqlite_file_path();
    let store = SqliteStore::new_with_lock_timeout(&path, lock_timeout).expect("open sqlite file");
    store.initialize().await.expect("initialize");
    store.migrate().await.expect("migrate");
    Held {
        store,
        _guard: Guard::TempDir(dir),
    }
}

/// Open (and migrate) a SQLite file. Opening the same path twice gives two
/// independent stores over one database — the shape of two processes.
pub async fn open_sqlite_file(path: &str) -> SqliteStore {
    let store = SqliteStore::new(path).expect("open sqlite file");
    store.initialize().await.expect("initialize");
    store.migrate().await.expect("migrate");
    store
}

/// Test-only seeding: commit rows straight through `IpamStore::transact`,
/// with none of `IpamOps`'s rules (no overlap, ownership, or delete checks).
/// That is what the store's old `create_*`/`delete_cidr_block` methods did,
/// so test setup written against them keeps working by importing `Seed`.
#[allow(async_fn_in_trait)]
pub trait Seed {
    async fn create_cidr_block(
        &self,
        tenant_id: &str,
        input: &netcidr::ipam::models::CreateCidrBlock,
    ) -> netcidr::error::Result<netcidr::ipam::models::CidrBlock>;

    async fn create_allocation(
        &self,
        tenant_id: &str,
        input: &netcidr::ipam::models::CreateAllocation,
    ) -> netcidr::error::Result<netcidr::ipam::models::Allocation>;

    /// Delete a block and everything in it, without the active-allocation
    /// check.
    async fn delete_cidr_block(&self, tenant_id: &str, id: &str) -> netcidr::error::Result<()>;

    /// Delete a user row, without the platform-admin guards.
    async fn delete_user(&self, email: &str) -> netcidr::error::Result<()>;

    /// Append an audit row on its own, outside any operation.
    async fn append_audit(
        &self,
        entry: &netcidr::ipam::models::AuditEntry,
    ) -> netcidr::error::Result<()>;

    /// Replace an allocation's tags, without checking that it exists.
    async fn set_tags(
        &self,
        tenant_id: &str,
        allocation_id: &str,
        tags: &[netcidr::ipam::models::Tag],
    ) -> netcidr::error::Result<()>;

    /// Insert a PAT row (fresh id, `created_at` now), without the per-owner
    /// limit.
    async fn pat_create(
        &self,
        input: &netcidr::ipam::models::CreatePersonalAccessToken,
    ) -> netcidr::error::Result<netcidr::ipam::models::PersonalAccessToken>;

    /// Set `revoked_at` on an owner's PAT; `PatNotFound` if the owner has no
    /// such PAT. Unlike the lifecycle, re-revoking overwrites `revoked_at`.
    async fn pat_revoke(
        &self,
        tenant_id: &str,
        owner_sub: &str,
        id: &str,
        revoked_at: &str,
    ) -> netcidr::error::Result<()>;
}

impl<S: IpamStore + ?Sized> Seed for S {
    async fn create_cidr_block(
        &self,
        tenant_id: &str,
        input: &netcidr::ipam::models::CreateCidrBlock,
    ) -> netcidr::error::Result<netcidr::ipam::models::CidrBlock> {
        let block = netcidr::ipam::models::CidrBlock::from_input(
            tenant_id,
            input,
            uuid::Uuid::new_v4().to_string(),
            chrono::Utc::now(),
        )?;
        commit_writes(
            self,
            tenant_id,
            vec![netcidr::ipam::store::Write::InsertCidrBlock(block.clone())],
        )
        .await?;
        Ok(block)
    }

    async fn create_allocation(
        &self,
        tenant_id: &str,
        input: &netcidr::ipam::models::CreateAllocation,
    ) -> netcidr::error::Result<netcidr::ipam::models::Allocation> {
        let alloc = netcidr::ipam::models::Allocation::from_input(
            tenant_id,
            input,
            uuid::Uuid::new_v4().to_string(),
            chrono::Utc::now(),
        )?;
        commit_writes(
            self,
            tenant_id,
            vec![netcidr::ipam::store::Write::InsertAllocation(alloc.clone())],
        )
        .await?;
        Ok(alloc)
    }

    async fn delete_cidr_block(&self, tenant_id: &str, id: &str) -> netcidr::error::Result<()> {
        commit_writes(
            self,
            tenant_id,
            vec![netcidr::ipam::store::Write::DeleteCidrBlock {
                tenant_id: tenant_id.to_string(),
                id: id.to_string(),
            }],
        )
        .await
    }

    async fn delete_user(&self, email: &str) -> netcidr::error::Result<()> {
        commit_writes(
            self,
            "local",
            vec![netcidr::ipam::store::Write::DeleteUser {
                email: email.to_ascii_lowercase(),
            }],
        )
        .await
    }

    async fn append_audit(
        &self,
        entry: &netcidr::ipam::models::AuditEntry,
    ) -> netcidr::error::Result<()> {
        let entry = entry.clone();
        self.transact(netcidr::ipam::store::TxUnit {
            scope: netcidr::ipam::store::LockScope::Tenant {
                tenant_id: entry.tenant_id.clone(),
            },
            reads: vec![],
            idempotency: None,
            decide: Box::new(move |_| {
                Ok(netcidr::ipam::store::Plan {
                    audits: vec![entry],
                    ..Default::default()
                })
            }),
        })
        .await
        .map(|_| ())
    }

    async fn set_tags(
        &self,
        tenant_id: &str,
        allocation_id: &str,
        tags: &[netcidr::ipam::models::Tag],
    ) -> netcidr::error::Result<()> {
        commit_writes(
            self,
            tenant_id,
            vec![netcidr::ipam::store::Write::ReplaceTags {
                tenant_id: tenant_id.to_string(),
                allocation_id: allocation_id.to_string(),
                tags: tags.to_vec(),
            }],
        )
        .await
    }

    async fn pat_create(
        &self,
        input: &netcidr::ipam::models::CreatePersonalAccessToken,
    ) -> netcidr::error::Result<netcidr::ipam::models::PersonalAccessToken> {
        let row = netcidr::ipam::models::PersonalAccessToken {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: input.tenant_id.clone(),
            owner_sub: input.owner_sub.clone(),
            owner_email: input.owner_email.clone(),
            name: input.name.clone(),
            prefix: input.prefix.clone(),
            token_hash: input.token_hash.clone(),
            role: input.role,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: input.expires_at.clone(),
            last_used_at: None,
            revoked_at: None,
        };
        commit_writes(
            self,
            &input.tenant_id,
            vec![netcidr::ipam::store::Write::InsertPat(row.clone())],
        )
        .await?;
        Ok(row)
    }

    async fn pat_revoke(
        &self,
        tenant_id: &str,
        owner_sub: &str,
        id: &str,
        revoked_at: &str,
    ) -> netcidr::error::Result<()> {
        commit_writes(
            self,
            tenant_id,
            vec![netcidr::ipam::store::Write::RevokePat {
                tenant_id: tenant_id.to_string(),
                owner_sub: owner_sub.to_string(),
                id: id.to_string(),
                revoked_at: revoked_at.to_string(),
            }],
        )
        .await
    }
}

/// Commit `writes` as one unit under the tenant's scope, with no reads,
/// audit rows, or idempotency record.
pub async fn commit_writes<S: IpamStore + ?Sized>(
    store: &S,
    tenant_id: &str,
    writes: Vec<netcidr::ipam::store::Write>,
) -> netcidr::error::Result<()> {
    store
        .transact(netcidr::ipam::store::TxUnit {
            scope: netcidr::ipam::store::LockScope::Tenant {
                tenant_id: tenant_id.to_string(),
            },
            reads: vec![],
            idempotency: None,
            decide: Box::new(move |_| {
                Ok(netcidr::ipam::store::Plan {
                    writes,
                    ..Default::default()
                })
            }),
        })
        .await
        .map(|_| ())
}

#[cfg(feature = "ipam-postgres")]
#[allow(unused_imports)]
pub use pg::{open_postgres, postgres_store, postgres_store_short_timeout};

#[cfg(feature = "ipam-postgres")]
pub mod pg {
    use std::process::Command;
    use std::sync::OnceLock;
    use std::time::Duration;

    use netcidr::ipam::config::PostgresConfig;
    use netcidr::ipam::postgres::PostgresStore;
    use netcidr::ipam::store::IpamStore;
    use sqlx::Connection;
    use sqlx::postgres::PgConnection;

    use super::{Guard, Held};

    const URL_ENV: &str = "NETCIDR_TEST_DATABASE_URL";
    const CONTAINER: &str = "netcidr-test-pg";
    const LOCAL_URL: &str = "postgresql://postgres@127.0.0.1:15432/postgres";

    /// A per-test database, dropped (with its connections) on drop.
    pub struct TestDatabase {
        server_url: String,
        name: String,
    }

    impl TestDatabase {
        /// Connection URL for this test's database.
        pub fn url(&self) -> String {
            with_database(&self.server_url, &self.name)
        }

        async fn create() -> Self {
            let server_url = server_url().to_string();
            let name = format!("t_{}", uuid::Uuid::new_v4().simple());
            let mut admin = PgConnection::connect(&server_url)
                .await
                .expect("connect to test postgres server");
            // `name` is generated here (hex UUID), never caller input.
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                .execute(&mut admin)
                .await
                .expect("create test database");
            Self { server_url, name }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            // Drop runs inside the test's runtime, which can't be blocked on
            // from here; use a short-lived thread with its own runtime.
            let (url, name) = (self.server_url.clone(), self.name.clone());
            let _ = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("cleanup runtime");
                rt.block_on(async {
                    if let Ok(mut admin) = PgConnection::connect(&url).await {
                        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                        )))
                        .execute(&mut admin)
                        .await;
                    }
                });
            })
            .join();
        }
    }

    /// A migrated `PostgresStore` on its own fresh database.
    pub async fn postgres_store() -> Held<PostgresStore> {
        postgres_store_with(netcidr::ipam::store::DEFAULT_LOCK_TIMEOUT).await
    }

    /// A per-test Postgres store with [`super::SHORT_LOCK_TIMEOUT`].
    pub async fn postgres_store_short_timeout() -> Held<PostgresStore> {
        postgres_store_with(super::SHORT_LOCK_TIMEOUT).await
    }

    async fn postgres_store_with(lock_timeout: Duration) -> Held<PostgresStore> {
        let db = TestDatabase::create().await;
        let store = open_postgres_with(&db.url(), lock_timeout).await;
        Held {
            store,
            _guard: Guard::Postgres(db),
        }
    }

    /// A fresh, empty per-test database without a store; open stores on it
    /// with [`open_postgres`] (e.g. two stores to model two processes).
    pub async fn test_database() -> TestDatabase {
        TestDatabase::create().await
    }

    /// Open (and migrate) a `PostgresStore` on `url`.
    pub async fn open_postgres(url: &str) -> PostgresStore {
        open_postgres_with(url, netcidr::ipam::store::DEFAULT_LOCK_TIMEOUT).await
    }

    async fn open_postgres_with(url: &str, lock_timeout: Duration) -> PostgresStore {
        let config = PostgresConfig {
            url: Some(url.to_string()),
            max_connections: 5,
            min_connections: 1,
        };
        let store = PostgresStore::new_with_lock_timeout(url, &config, lock_timeout)
            .await
            .expect("connect to test database");
        store.initialize().await.expect("initialize");
        store.migrate().await.expect("migrate");
        store
    }

    /// Replace the database component of a `postgresql://` URL.
    fn with_database(server_url: &str, db: &str) -> String {
        let (base, query) = match server_url.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (server_url, None),
        };
        let scheme_end = base.find("://").map_or(0, |i| i + 3);
        let base = match base[scheme_end..].find('/') {
            Some(slash) => &base[..scheme_end + slash],
            None => base,
        };
        match query {
            Some(q) => format!("{base}/{db}?{q}"),
            None => format!("{base}/{db}"),
        }
    }

    /// Server URL from the environment, or the local container (started
    /// once per test process; tolerant of other processes starting it).
    fn server_url() -> &'static str {
        static URL: OnceLock<String> = OnceLock::new();
        URL.get_or_init(|| match std::env::var(URL_ENV) {
            Ok(url) if !url.is_empty() => url,
            _ => {
                ensure_local_container();
                LOCAL_URL.to_string()
            }
        })
    }

    fn ensure_local_container() {
        let running = Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", CONTAINER])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false);
        if !running {
            // A concurrent test process may win the race to create it; a
            // name conflict is fine, so the result is checked via readiness.
            let _ = Command::new("docker")
                .args(["rm", "-f", CONTAINER])
                .output();
            let _ = Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--name",
                    CONTAINER,
                    "-e",
                    "POSTGRES_HOST_AUTH_METHOD=trust",
                    "-p",
                    "15432:5432",
                    "postgres:16-alpine",
                ])
                .output()
                .expect(
                    "failed to run docker — is Docker running? (or set NETCIDR_TEST_DATABASE_URL)",
                );
        }
        for _ in 0..60 {
            let ready = Command::new("docker")
                .args([
                    "exec",
                    CONTAINER,
                    "pg_isready",
                    "-U",
                    "postgres",
                    "-h",
                    "127.0.0.1",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ready {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("local test postgres ({CONTAINER}) did not become ready within 30s");
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn with_database_replaces_path() {
            assert_eq!(
                super::with_database("postgresql://u@h:5432/postgres", "t_1"),
                "postgresql://u@h:5432/t_1"
            );
            assert_eq!(
                super::with_database("postgres://u:p@h/postgres?sslmode=disable", "t_1"),
                "postgres://u:p@h/t_1?sslmode=disable"
            );
            assert_eq!(
                super::with_database("postgresql://h:1", "t_1"),
                "postgresql://h:1/t_1"
            );
        }
    }
}
