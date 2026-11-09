//! r2d2 connection manager for rusqlite.
//!
//! Kept in-tree instead of using `r2d2_sqlite` so the rusqlite (and bundled
//! SQLite) version is not held back by that crate's release cadence:
//! security fixes to SQLite ship as `libsqlite3-sys` bumps that need the
//! newest rusqlite.

use rusqlite::Connection;
use std::path::PathBuf;
use std::time::Duration;

enum Source {
    File(PathBuf),
    /// Each connection is its own, private in-memory database.
    Memory,
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

    pub(super) fn memory(lock_timeout: Duration) -> Self {
        Self {
            source: Source::Memory,
            lock_timeout,
        }
    }
}

impl r2d2::ManageConnection for SqliteManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        let conn = match &self.source {
            Source::File(path) => Connection::open(path)?,
            Source::Memory => Connection::open_in_memory()?,
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
        let manager = SqliteManager::memory(Duration::from_millis(50));
        let conn = manager.connect().expect("connect");
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(fk, 1);
    }

    #[test]
    fn connect_sets_busy_timeout() {
        let manager = SqliteManager::memory(Duration::from_millis(1234));
        let conn = manager.connect().expect("connect");
        let ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(ms, 1234);
    }

    #[test]
    fn memory_connections_are_isolated() {
        let manager = SqliteManager::memory(Duration::from_millis(50));
        let a = manager.connect().expect("connect a");
        let b = manager.connect().expect("connect b");
        a.execute_batch("CREATE TABLE t (x INTEGER);")
            .expect("create");
        assert!(b.execute_batch("SELECT x FROM t;").is_err());
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
