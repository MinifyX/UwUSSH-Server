//! Accounts: one vault, one login verifier, one sequence counter.
//!
//! What the server keeps about an account is exactly what it needs to hand the
//! vault back to a device that proves it knows the master password — and not
//! one field more. The header is not secret; the verifier is a hash of a key
//! that was itself derived from the password *and* the account key, so a copy
//! of this table is not a shortcut to anything.

use crate::db::constant_time_eq;
use crate::{now_ms, sha256};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The vault header as it travels: base64 for the bytes, so it reads as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultHeader {
    pub vault_id: Uuid,
    pub kdf_memory_kib: u32,
    pub kdf_time_cost: u32,
    pub kdf_parallelism: u32,
    pub salt: String,
    pub wrapped_nonce: String,
    pub wrapped_blob: String,
}

/// The part of the header a device may see before it has proved anything: what
/// it needs to turn a master password into keys, and nothing it could attack
/// offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultParams {
    pub vault_id: Uuid,
    pub kdf_memory_kib: u32,
    pub kdf_time_cost: u32,
    pub kdf_parallelism: u32,
    pub salt: String,
}

impl VaultHeader {
    pub fn params(&self) -> VaultParams {
        VaultParams {
            vault_id: self.vault_id,
            kdf_memory_kib: self.kdf_memory_kib,
            kdf_time_cost: self.kdf_time_cost,
            kdf_parallelism: self.kdf_parallelism,
            salt: self.salt.clone(),
        }
    }

    /// Costs a device can actually run. A header asking for a terabyte of
    /// memory would lock every device out of its own vault, so it is refused
    /// on the way in rather than discovered on the way out.
    pub fn plausible(&self) -> bool {
        (1..=1024 * 1024).contains(&self.kdf_memory_kib)
            && (1..=16).contains(&self.kdf_time_cost)
            && (1..=16).contains(&self.kdf_parallelism)
            && !self.salt.is_empty()
            && !self.wrapped_blob.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub id: Uuid,
    pub vault_id: Uuid,
    /// The last sequence number handed out for this account.
    pub seq: u64,
}

pub fn count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM accounts", [], |row| row.get(0))
}

pub fn create(
    conn: &Connection,
    header: &VaultHeader,
    auth_key: &[u8],
) -> rusqlite::Result<Account> {
    let id = Uuid::now_v7();
    conn.execute(
        "INSERT INTO accounts
            (id, created_ms, vault_id, kdf_memory_kib, kdf_time_cost, kdf_parallelism,
             salt, wrapped_nonce, wrapped_blob, auth_verifier, seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
        params![
            id.to_string(),
            now_ms() as i64,
            header.vault_id.to_string(),
            header.kdf_memory_kib,
            header.kdf_time_cost,
            header.kdf_parallelism,
            header.salt,
            header.wrapped_nonce,
            header.wrapped_blob,
            sha256(auth_key).to_vec(),
        ],
    )?;
    Ok(Account {
        id,
        vault_id: header.vault_id,
        seq: 0,
    })
}

pub fn get(conn: &Connection, id: Uuid) -> rusqlite::Result<Option<Account>> {
    conn.query_row(
        "SELECT vault_id, seq FROM accounts WHERE id = ?1",
        [id.to_string()],
        |row| {
            let vault_id: String = row.get(0)?;
            let seq: i64 = row.get(1)?;
            Ok((vault_id, seq))
        },
    )
    .optional()
    .map(|row| {
        row.and_then(|(vault_id, seq)| {
            Some(Account {
                id,
                vault_id: Uuid::parse_str(&vault_id).ok()?,
                seq: seq as u64,
            })
        })
    })
}

pub fn header(conn: &Connection, id: Uuid) -> rusqlite::Result<Option<VaultHeader>> {
    conn.query_row(
        "SELECT vault_id, kdf_memory_kib, kdf_time_cost, kdf_parallelism,
                salt, wrapped_nonce, wrapped_blob
           FROM accounts WHERE id = ?1",
        [id.to_string()],
        |row| {
            let vault_id: String = row.get(0)?;
            Ok(VaultHeader {
                vault_id: Uuid::parse_str(&vault_id).unwrap_or(Uuid::nil()),
                kdf_memory_kib: row.get(1)?,
                kdf_time_cost: row.get(2)?,
                kdf_parallelism: row.get(3)?,
                salt: row.get(4)?,
                wrapped_nonce: row.get(5)?,
                wrapped_blob: row.get(6)?,
            })
        },
    )
    .optional()
}

/// Whether this is the login key of that account. A missing account and a
/// wrong key answer the same.
pub fn verify(conn: &Connection, id: Uuid, auth_key: &[u8]) -> rusqlite::Result<bool> {
    let stored: Option<Vec<u8>> = conn
        .query_row(
            "SELECT auth_verifier FROM accounts WHERE id = ?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match stored {
        Some(stored) => constant_time_eq(&stored, &sha256(auth_key)),
        None => false,
    })
}

/// A new master password: the vault key is wrapped again and the verifier
/// replaced. No record is touched — that is the point of wrapping a key
/// instead of encrypting with the password.
pub fn set_header(
    conn: &Connection,
    id: Uuid,
    header: &VaultHeader,
    auth_key: &[u8],
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE accounts
            SET kdf_memory_kib = ?2, kdf_time_cost = ?3, kdf_parallelism = ?4,
                salt = ?5, wrapped_nonce = ?6, wrapped_blob = ?7, auth_verifier = ?8
          WHERE id = ?1",
        params![
            id.to_string(),
            header.kdf_memory_kib,
            header.kdf_time_cost,
            header.kdf_parallelism,
            header.salt,
            header.wrapped_nonce,
            header.wrapped_blob,
            sha256(auth_key).to_vec(),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::Db;

    pub(crate) fn header() -> VaultHeader {
        VaultHeader {
            vault_id: Uuid::now_v7(),
            kdf_memory_kib: 65536,
            kdf_time_cost: 3,
            kdf_parallelism: 4,
            salt: "c2FsdHktc2FsdA".into(),
            wrapped_nonce: "bm9uY2U".into(),
            wrapped_blob: "d3JhcHBlZA".into(),
        }
    }

    #[test]
    fn an_account_keeps_its_vault_and_starts_at_sequence_zero() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let header = header();
        let account = create(&conn, &header, b"login key").unwrap();
        assert_eq!(account.seq, 0);
        assert_eq!(account.vault_id, header.vault_id);
        assert_eq!(get(&conn, account.id).unwrap(), Some(account));
        assert_eq!(count(&conn).unwrap(), 1);
    }

    #[test]
    fn the_login_key_is_stored_only_as_a_hash() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = create(&conn, &header(), b"login key").unwrap();

        let stored: Vec<u8> = conn
            .query_row(
                "SELECT auth_verifier FROM accounts WHERE id = ?1",
                [account.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(stored, b"login key".to_vec());
        assert_eq!(stored.len(), 32);

        assert!(verify(&conn, account.id, b"login key").unwrap());
        assert!(!verify(&conn, account.id, b"login keY").unwrap());
        assert!(
            !verify(&conn, Uuid::now_v7(), b"login key").unwrap(),
            "an account that does not exist answers like a wrong key"
        );
    }

    #[test]
    fn a_new_password_rewraps_the_key_and_replaces_the_verifier() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = create(&conn, &header(), b"old").unwrap();
        let changed = VaultHeader {
            wrapped_blob: "bmV3bHktd3JhcHBlZA".into(),
            ..header()
        };
        set_header(&conn, account.id, &changed, b"new").unwrap();

        assert!(!verify(&conn, account.id, b"old").unwrap());
        assert!(verify(&conn, account.id, b"new").unwrap());
        assert_eq!(
            super::header(&conn, account.id)
                .unwrap()
                .unwrap()
                .wrapped_blob,
            "bmV3bHktd3JhcHBlZA"
        );
    }

    #[test]
    fn a_header_asking_for_absurd_costs_is_not_plausible() {
        let mut greedy = header();
        greedy.kdf_memory_kib = u32::MAX;
        assert!(!greedy.plausible());
        assert!(header().plausible());
    }

    #[test]
    fn the_parameters_a_joining_device_sees_hold_no_wrapped_key() {
        let params = header().params();
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("salt"));
        assert!(!json.contains("wrapped"), "{json}");
    }
}
