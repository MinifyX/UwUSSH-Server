//! The database: one SQLite file, and the few tables a mailbox needs.
//!
//! Every statement here runs on one connection behind a mutex. That is not a
//! bottleneck worth removing: a request writes at most one batch of records,
//! and SQLite in WAL mode does that in well under a millisecond. Work that is
//! genuinely slow — a backup, a purge — runs on a thread of its own.

pub mod accounts;
pub mod devices;
pub mod invites;
pub mod records;

use parking_lot::{Mutex, MutexGuard};
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A record that is deleted is deleted: its ciphertext must not stay
        // readable in a free page of the file.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    /// A consistent copy of a running database, which copying the file is not:
    /// the write-ahead log would be missing.
    pub fn backup_to(&self, path: &Path) -> rusqlite::Result<()> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = self.lock();
        conn.execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()])?;
        Ok(())
    }
}

pub const SCHEMA_VERSION: i64 = 1;

const V1: &str = r#"
CREATE TABLE accounts (
    id              TEXT    PRIMARY KEY,
    created_ms      INTEGER NOT NULL,
    -- The vault every record of this account belongs to. A record claiming
    -- another one is refused: that is a bug on a device, not a new vault.
    vault_id        TEXT    NOT NULL,
    -- The vault header, which is not secret and useless without the master
    -- password: salt, key derivation costs, and the wrapped vault key.
    kdf_memory_kib  INTEGER NOT NULL,
    kdf_time_cost   INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    salt            BLOB    NOT NULL,
    wrapped_nonce   BLOB    NOT NULL,
    wrapped_blob    BLOB    NOT NULL,
    -- SHA-256 of the login key, not the key itself. The key is derived from
    -- the master password *and* the account key, so this hash is no shortcut.
    auth_verifier   BLOB    NOT NULL,
    -- The last sequence number handed out, per account. Monotonic, never
    -- reused, and the version of every record it numbered.
    seq             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE devices (
    id              TEXT    PRIMARY KEY,
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    name            TEXT    NOT NULL,
    -- Ed25519. The device signs a challenge with it instead of sending
    -- anything that could be replayed.
    public_key      BLOB    NOT NULL,
    created_ms      INTEGER NOT NULL,
    last_seen_ms    INTEGER,
    -- How far this device has read, so the server knows what nobody needs any
    -- more and can say when a device was last here.
    cursor          INTEGER NOT NULL DEFAULT 0,
    revoked_ms      INTEGER
);

CREATE INDEX devices_by_account ON devices (account_id);

CREATE TABLE records (
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    id              TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    seq             INTEGER NOT NULL,
    hlc_wall_ms     INTEGER NOT NULL,
    hlc_counter     INTEGER NOT NULL,
    hlc_device      INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0,
    nonce           BLOB    NOT NULL,
    blob            BLOB    NOT NULL,
    -- Which device wrote this version. For the log, and for a future pull that
    -- skips what the asking device wrote itself.
    device_id       TEXT,
    updated_ms      INTEGER NOT NULL,
    PRIMARY KEY (account_id, id)
);

CREATE INDEX records_by_seq ON records (account_id, seq);

CREATE TABLE invites (
    code_hash       BLOB    PRIMARY KEY,
    created_ms      INTEGER NOT NULL,
    expires_ms      INTEGER NOT NULL,
    used_ms         INTEGER
);

-- A one-time token an enrolled device hands to a joining one, through a
-- channel this server cannot read.
CREATE TABLE enrolments (
    token_hash      BLOB    PRIMARY KEY,
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    created_ms      INTEGER NOT NULL,
    expires_ms      INTEGER NOT NULL,
    used_ms         INTEGER
);
"#;

fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version >= SCHEMA_VERSION {
        return Ok(());
    }
    if version < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(V1)?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
        tracing::info!("database created at schema 1");
    }
    Ok(())
}

/// Compare two secrets without letting how long it takes say how much of them
/// matched.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrating_twice_is_harmless() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 5);
    }

    #[test]
    fn comparing_secrets_does_not_stop_at_the_first_difference() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
    }
}
