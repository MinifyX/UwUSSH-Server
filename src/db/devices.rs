//! Devices: a name, a public key, and how far it has read.
//!
//! A device proves who it is by signing a challenge with the key it enrolled,
//! so nothing that travels can be replayed by whoever overhears it. Revoking
//! one is a column, not a deletion: what it already read it already has, and
//! the list should still show that the laptop was here until Tuesday.

use crate::now_ms;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub public_key: [u8; 32],
    pub cursor: u64,
    pub revoked: bool,
}

/// What the device list shows. No key material: the list is for people.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummary {
    pub id: Uuid,
    pub name: String,
    pub created_ms: u64,
    pub last_seen_ms: Option<u64>,
    pub revoked_ms: Option<u64>,
}

/// A name for the device list: one line, not a novel, and nothing that could
/// pass for markup in a log or a list.
pub fn clean_name(name: &str) -> String {
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(60)
        .collect();
    if name.is_empty() {
        "a device".to_string()
    } else {
        name
    }
}

pub fn add(
    conn: &Connection,
    account_id: Uuid,
    name: &str,
    public_key: &[u8; 32],
) -> rusqlite::Result<Device> {
    let id = Uuid::now_v7();
    let name = clean_name(name);
    conn.execute(
        "INSERT INTO devices (id, account_id, name, public_key, created_ms, cursor)
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![
            id.to_string(),
            account_id.to_string(),
            name,
            public_key.to_vec(),
            now_ms() as i64,
        ],
    )?;
    Ok(Device {
        id,
        account_id,
        name,
        public_key: *public_key,
        cursor: 0,
        revoked: false,
    })
}

pub fn get(conn: &Connection, id: Uuid) -> rusqlite::Result<Option<Device>> {
    conn.query_row(
        "SELECT account_id, name, public_key, cursor, revoked_ms FROM devices WHERE id = ?1",
        [id.to_string()],
        |row| {
            let account_id: String = row.get(0)?;
            let key: Vec<u8> = row.get(2)?;
            let cursor: i64 = row.get(3)?;
            let revoked: Option<i64> = row.get(4)?;
            Ok((account_id, row.get::<_, String>(1)?, key, cursor, revoked))
        },
    )
    .optional()
    .map(|row| {
        row.and_then(|(account_id, name, key, cursor, revoked)| {
            Some(Device {
                id,
                account_id: Uuid::parse_str(&account_id).ok()?,
                name,
                public_key: key.try_into().ok()?,
                cursor: cursor as u64,
                revoked: revoked.is_some(),
            })
        })
    })
}

pub fn list(conn: &Connection, account_id: Uuid) -> rusqlite::Result<Vec<DeviceSummary>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, created_ms, last_seen_ms, revoked_ms FROM devices
          WHERE account_id = ?1 ORDER BY created_ms",
    )?;
    let devices = stmt
        .query_map([account_id.to_string()], |row| {
            let id: String = row.get(0)?;
            let created: i64 = row.get(2)?;
            let last_seen: Option<i64> = row.get(3)?;
            let revoked: Option<i64> = row.get(4)?;
            Ok(DeviceSummary {
                id: Uuid::parse_str(&id).unwrap_or(Uuid::nil()),
                name: row.get(1)?,
                created_ms: created as u64,
                last_seen_ms: last_seen.map(|ms| ms as u64),
                revoked_ms: revoked.map(|ms| ms as u64),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(devices)
}

/// Note that a device was here, and how far it has read.
pub fn seen(conn: &Connection, id: Uuid, cursor: u64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE devices SET last_seen_ms = ?2, cursor = max(cursor, ?3) WHERE id = ?1",
        params![id.to_string(), now_ms() as i64, cursor as i64],
    )?;
    Ok(())
}

/// Shut a device out. Only for an account's own devices — the caller passes
/// the account it is authenticated as, so a device id from another account
/// finds nothing.
pub fn revoke(conn: &Connection, account_id: Uuid, id: Uuid) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE devices SET revoked_ms = ?3
          WHERE id = ?1 AND account_id = ?2 AND revoked_ms IS NULL",
        params![id.to_string(), account_id.to_string(), now_ms() as i64],
    )?;
    Ok(changed > 0)
}

/// How many devices can still read. Revoking the last one would leave an
/// account nobody can reach, so the caller checks this first.
pub fn live_count(conn: &Connection, account_id: Uuid) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM devices WHERE account_id = ?1 AND revoked_ms IS NULL",
        [account_id.to_string()],
        |row| row.get(0),
    )
}

/// The lowest cursor of the devices that still read, which is how far the
/// server may forget tombstones nobody needs any more.
pub fn lowest_cursor(conn: &Connection, account_id: Uuid) -> rusqlite::Result<u64> {
    let lowest: Option<i64> = conn.query_row(
        "SELECT min(cursor) FROM devices WHERE account_id = ?1 AND revoked_ms IS NULL",
        [account_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(lowest.unwrap_or(0).max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::accounts;
    use crate::db::Db;

    fn account(conn: &Connection) -> Uuid {
        accounts::create(conn, &accounts::tests::header(), b"key")
            .unwrap()
            .id
    }

    #[test]
    fn a_device_is_enrolled_with_its_key_and_read_nothing_yet() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = account(&conn);
        let device = add(&conn, account, "LVDesk1", &[7u8; 32]).unwrap();
        assert_eq!(device.cursor, 0);
        assert!(!device.revoked);
        assert_eq!(get(&conn, device.id).unwrap(), Some(device.clone()));
        assert_eq!(list(&conn, account).unwrap().len(), 1);
        assert_eq!(list(&conn, account).unwrap()[0].name, "LVDesk1");
    }

    #[test]
    fn a_revoked_device_stays_in_the_list_and_stops_counting() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = account(&conn);
        let one = add(&conn, account, "one", &[1u8; 32]).unwrap();
        add(&conn, account, "two", &[2u8; 32]).unwrap();
        assert_eq!(live_count(&conn, account).unwrap(), 2);

        assert!(revoke(&conn, account, one.id).unwrap());
        assert!(!revoke(&conn, account, one.id).unwrap(), "only once");
        assert_eq!(live_count(&conn, account).unwrap(), 1);
        assert!(get(&conn, one.id).unwrap().unwrap().revoked);
        assert_eq!(list(&conn, account).unwrap().len(), 2);
        assert!(list(&conn, account).unwrap()[0].revoked_ms.is_some());
    }

    #[test]
    fn a_device_of_another_account_cannot_be_revoked() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let mine = account(&conn);
        let theirs = account(&conn);
        let device = add(&conn, theirs, "theirs", &[3u8; 32]).unwrap();
        assert!(!revoke(&conn, mine, device.id).unwrap());
        assert!(!get(&conn, device.id).unwrap().unwrap().revoked);
    }

    #[test]
    fn the_cursor_only_moves_forward() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = account(&conn);
        let device = add(&conn, account, "one", &[1u8; 32]).unwrap();
        seen(&conn, device.id, 12).unwrap();
        seen(&conn, device.id, 4).unwrap();
        assert_eq!(get(&conn, device.id).unwrap().unwrap().cursor, 12);
        assert!(get(&conn, device.id).unwrap().unwrap().cursor > 0);
    }

    #[test]
    fn what_nobody_has_read_is_decided_by_the_device_that_is_furthest_behind() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = account(&conn);
        let one = add(&conn, account, "one", &[1u8; 32]).unwrap();
        let two = add(&conn, account, "two", &[2u8; 32]).unwrap();
        seen(&conn, one.id, 30).unwrap();
        seen(&conn, two.id, 10).unwrap();
        assert_eq!(lowest_cursor(&conn, account).unwrap(), 10);

        // A device that is gone no longer holds anything back.
        revoke(&conn, account, two.id).unwrap();
        assert_eq!(lowest_cursor(&conn, account).unwrap(), 30);
    }

    #[test]
    fn a_device_name_is_one_harmless_line() {
        assert_eq!(clean_name("  LVDesk1\n"), "LVDesk1");
        assert_eq!(clean_name(""), "a device");
        assert_eq!(clean_name("a\u{7}b"), "ab");
        assert_eq!(clean_name(&"x".repeat(200)).len(), 60);
    }
}
