//! r2d2 connection manager for rusqlite.
//!
//! Kept in-tree instead of using `r2d2_sqlite` so the rusqlite (and bundled
//! SQLite) version is not held back by that crate's release cadence:
//! security fixes to SQLite ship as `libsqlite3-sys` bumps that need the
//! newest rusqlite.

use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

enum Source {
    File(PathBuf),
    Memory {
        uri: String,
        // SQLite deletes a shared-memory database when its last connection
        // closes. Keep it alive for the manager's lifetime, even during pool
        // recycling. The mutex makes the Send-only Connection safe to retain
        // in a Sync manager; this connection is never used for queries.
        _keeper: Mutex<Connection>,
    },
}

pub(crate) struct SqliteManager {
    source: Source,
    lock_timeout: Duration,
}

impl SqliteManager {
    pub(super) fn file(path: impl Into<PathBuf>, lock_timeout: Duration) -> Self {
        Self {
            source: Source::File(path.into()),
            lock_timeout,
        }
    }

    pub(super) fn memory(lock_timeout: Duration) -> rusqlite::Result<Self> {
        let uri = format!(
            "file:netcidr-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        let keeper = Connection::open(&uri)?;
        Ok(Self {
            source: Source::Memory {
                uri,
                _keeper: Mutex::new(keeper),
            },
            lock_timeout,
        })
    }
}

impl r2d2::ManageConnection for SqliteManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        let conn = match &self.source {
            Source::File(path) => Connection::open(path)?,
            Source::Memory { uri, .. } => Connection::open(uri)?,
        };
        conn.busy_timeout(self.lock_timeout)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        Ok(conn)
    }

    fn is_valid(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("")
    }

    fn has_broken(&self, _conn: &mut Connection) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2d2::ManageConnection;

    #[test]
    fn connect_enables_foreign_keys() {
        let manager = SqliteManager::memory(Duration::from_millis(50)).expect("memory manager");
        let conn = manager.connect().expect("connect");
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(fk, 1);
    }

    #[test]
    fn connect_sets_busy_timeout() {
        let manager = SqliteManager::memory(Duration::from_millis(1234)).expect("memory manager");
        let conn = manager.connect().expect("connect");
        let ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(ms, 1234);
    }

    #[test]
    fn memory_managers_are_isolated() {
        let manager = SqliteManager::memory(Duration::from_millis(50)).expect("memory manager");
        let a = manager.connect().expect("connect a");
        let other = SqliteManager::memory(Duration::from_millis(50)).expect("memory manager");
        let b = other.connect().expect("connect b");
        a.execute_batch("CREATE TABLE t (x INTEGER);")
            .expect("create");
        assert!(b.execute_batch("SELECT x FROM t;").is_err());
    }

    #[test]
    fn memory_survives_connection_replacement() {
        let manager = SqliteManager::memory(Duration::from_millis(50)).expect("memory manager");
        let conn = manager.connect().expect("initial connection");
        conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (42);")
            .expect("seed database");
        // Close every connection handed out by the manager before reconnecting,
        // reproducing pool recycling without sleeps or timer-dependent reaping.
        drop(conn);
        for _ in 0..3 {
            let replacement = manager.connect().expect("replacement connection");
            let value: i64 = replacement
                .query_row("SELECT x FROM t", [], |row| row.get(0))
                .expect("schema and data survive replacement");
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn file_database_survives_manager_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("persistent.db");
        let manager = SqliteManager::file(&path, Duration::from_millis(50));
        let conn = manager.connect().expect("connect");
        conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (42);")
            .expect("seed database");
        drop(conn);
        drop(manager);

        let reopened = SqliteManager::file(&path, Duration::from_millis(50));
        let value: i64 = reopened
            .connect()
            .expect("reopen file")
            .query_row("SELECT x FROM t", [], |row| row.get(0))
            .expect("persisted schema and data");
        assert_eq!(value, 42);
    }

    #[test]
    fn file_connections_share_the_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pool.db");
        let manager = SqliteManager::file(&path, Duration::from_millis(50));
        let mut a = manager.connect().expect("connect a");
        let b = manager.connect().expect("connect b");
        a.execute_batch("CREATE TABLE t (x INTEGER);")
            .expect("create");
        b.execute_batch("SELECT x FROM t;").expect("visible to b");
        manager.is_valid(&mut a).expect("valid");
    }
}
