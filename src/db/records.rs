//! Records: the mailbox itself.
//!
//! Two operations and one rule. **Pull** hands out everything after a cursor,
//! in sequence order. **Push** takes a record if the version it was based on is
//! the version stored, and reports a conflict with the current one if it is
//! not. That check is the whole of conflict detection here, and it is all the
//! server can do: it cannot read a record, so it cannot merge one either.
//!
//! Only the newest version of each record is kept. A device that needs an older
//! one has it locally or not at all — and the client is built for that, since a
//! record it has not seen is simply new to it.

use crate::db::accounts::Account;
use crate::{now_ms, ApiError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;
use uwussh_proto::{
    Accepted, EntityKind, Envelope, PullResponse, PushResponse, SyncCursor, MAX_BATCH,
    MAX_BLOB_BYTES,
};

/// An XChaCha20-Poly1305 nonce, as every envelope carries.
const NONCE_BYTES: usize = 24;

fn kind_name(kind: EntityKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn kind_from(name: &str) -> Option<EntityKind> {
    serde_json::from_value(serde_json::Value::String(name.to_string())).ok()
}

/// Everything about an envelope the server can check without a key: that it
/// belongs to this account's vault, that it is shaped like an envelope, and
/// that it is not big enough to be a problem.
fn check(account: &Account, envelope: &Envelope) -> Result<()> {
    if envelope.vault_id != account.vault_id {
        return Err(ApiError::Invalid(
            "a record from another vault than this account's".into(),
        ));
    }
    if envelope.nonce.len() != NONCE_BYTES {
        return Err(ApiError::Invalid("a record without a proper nonce".into()));
    }
    if envelope.blob.is_empty() {
        return Err(ApiError::Invalid(
            "a record with nothing sealed in it".into(),
        ));
    }
    if envelope.blob.len() > MAX_BLOB_BYTES {
        return Err(ApiError::TooLarge(format!(
            "a record of {} bytes, at most {MAX_BLOB_BYTES} are allowed",
            envelope.blob.len()
        )));
    }
    Ok(())
}

/// Offer records. Each one is taken and numbered, or reported as a conflict
/// with the version the server holds.
///
/// The whole batch is one transaction: a push either happens or does not, so a
/// device never has to wonder which half of it landed.
pub fn push(
    conn: &mut Connection,
    account: &Account,
    device: Uuid,
    envelopes: &[Envelope],
) -> Result<PushResponse> {
    if envelopes.len() > MAX_BATCH {
        return Err(ApiError::TooLarge(format!(
            "{} records in one request, at most {MAX_BATCH} are allowed",
            envelopes.len()
        )));
    }
    for envelope in envelopes {
        check(account, envelope)?;
    }

    let tx = conn.transaction()?;
    let mut seq: i64 = tx.query_row(
        "SELECT seq FROM accounts WHERE id = ?1",
        [account.id.to_string()],
        |row| row.get(0),
    )?;
    let mut response = PushResponse::default();

    for envelope in envelopes {
        let current: Option<i64> = tx
            .query_row(
                "SELECT seq FROM records WHERE account_id = ?1 AND id = ?2",
                params![account.id.to_string(), envelope.id.to_string()],
                |row| row.get(0),
            )
            .optional()?;

        // A record the server does not have is new, whatever the device
        // thought it was based on: there is nothing here to conflict with.
        if let Some(current) = current {
            if current as u64 != envelope.base_seq {
                if let Some(held) = get(&tx, account, envelope.id)? {
                    response.conflicts.push(held);
                }
                continue;
            }
        }

        seq += 1;
        tx.execute(
            "INSERT INTO records
                (account_id, id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device,
                 deleted, nonce, blob, device_id, updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT (account_id, id) DO UPDATE SET
                kind = excluded.kind, seq = excluded.seq,
                hlc_wall_ms = excluded.hlc_wall_ms, hlc_counter = excluded.hlc_counter,
                hlc_device = excluded.hlc_device, deleted = excluded.deleted,
                nonce = excluded.nonce, blob = excluded.blob,
                device_id = excluded.device_id, updated_ms = excluded.updated_ms",
            params![
                account.id.to_string(),
                envelope.id.to_string(),
                kind_name(envelope.kind),
                seq,
                envelope.updated_at.wall_ms as i64,
                envelope.updated_at.counter,
                envelope.updated_at.device,
                envelope.deleted,
                envelope.nonce,
                envelope.blob,
                device.to_string(),
                now_ms() as i64,
            ],
        )?;
        response.accepted.push(Accepted {
            id: envelope.id,
            seq: seq as u64,
        });
    }

    tx.execute(
        "UPDATE accounts SET seq = ?2 WHERE id = ?1",
        params![account.id.to_string(), seq],
    )?;
    tx.commit()?;

    response.cursor = SyncCursor(seq as u64);
    Ok(response)
}

/// Everything after a cursor, oldest first. `has_more` is honest: a device
/// that stops at the first page would otherwise believe it had everything.
pub fn pull(
    conn: &Connection,
    account: &Account,
    since: u64,
    limit: usize,
) -> Result<PullResponse> {
    let limit = limit.clamp(1, MAX_BATCH);
    let mut stmt = conn.prepare(
        "SELECT id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device, deleted, nonce, blob
           FROM records
          WHERE account_id = ?1 AND seq > ?2
          ORDER BY seq
          LIMIT ?3",
    )?;
    // One more than asked for, to find out whether there is another page.
    let mut envelopes = stmt
        .query_map(
            params![account.id.to_string(), since as i64, limit as i64 + 1],
            |row| row_to_envelope(account, row),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let has_more = envelopes.len() > limit;
    envelopes.truncate(limit);
    let cursor = envelopes
        .last()
        .and_then(|envelope| envelope.seq)
        .unwrap_or(since);

    Ok(PullResponse {
        envelopes,
        cursor: SyncCursor(cursor),
        has_more,
    })
}

/// One record as the server holds it.
pub fn get(conn: &Connection, account: &Account, id: Uuid) -> Result<Option<Envelope>> {
    Ok(conn
        .query_row(
            "SELECT id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device, deleted, nonce, blob
               FROM records WHERE account_id = ?1 AND id = ?2",
            params![account.id.to_string(), id.to_string()],
            |row| row_to_envelope(account, row),
        )
        .optional()?)
}

fn row_to_envelope(account: &Account, row: &rusqlite::Row<'_>) -> rusqlite::Result<Envelope> {
    let id: String = row.get(0)?;
    let kind: String = row.get(1)?;
    let seq: i64 = row.get(2)?;
    let wall: i64 = row.get(3)?;
    let counter: i64 = row.get(4)?;
    let device: i64 = row.get(5)?;
    Ok(Envelope {
        id: Uuid::parse_str(&id).unwrap_or(Uuid::nil()),
        vault_id: account.vault_id,
        kind: kind_from(&kind).unwrap_or(EntityKind::Host),
        updated_at: uwussh_proto::Hlc::new(wall as u64, counter as u32, device as u32),
        base_seq: seq as u64,
        deleted: row.get(6)?,
        nonce: row.get(7)?,
        blob: row.get(8)?,
        seq: Some(seq as u64),
    })
}

pub fn count(conn: &Connection, account: &Account) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM records WHERE account_id = ?1",
        [account.id.to_string()],
        |row| row.get(0),
    )
}

/// Forget tombstones every device has read and that are older than a season.
///
/// Both conditions matter. A tombstone is what stops a device that was offline
/// during a delete from bringing the record back, so one may only go once
/// every device has seen it — and a device that has been away for months gets
/// a fresh start instead, which is why `below_seq` comes from the devices that
/// still read.
pub fn purge_tombstones(
    conn: &Connection,
    account: &Account,
    before_ms: u64,
    below_seq: u64,
) -> rusqlite::Result<usize> {
    let removed = conn.execute(
        "DELETE FROM records
          WHERE account_id = ?1 AND deleted = 1 AND updated_ms < ?2 AND seq <= ?3",
        params![account.id.to_string(), before_ms as i64, below_seq as i64],
    )?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{accounts, Db};
    use uwussh_proto::Hlc;

    fn account(conn: &Connection) -> Account {
        accounts::create(conn, &accounts::tests::header(), b"key").unwrap()
    }

    fn envelope(account: &Account, id: Uuid, base_seq: u64) -> Envelope {
        Envelope {
            id,
            vault_id: account.vault_id,
            kind: EntityKind::Host,
            updated_at: Hlc::new(1_700_000_000_000, 0, 1),
            base_seq,
            deleted: false,
            nonce: vec![7; NONCE_BYTES],
            blob: vec![1, 2, 3, 4],
            seq: None,
        }
    }

    #[test]
    fn a_pushed_record_gets_the_next_number_and_comes_back_on_a_pull() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let id = Uuid::now_v7();

        let response = push(&mut conn, &account, device, &[envelope(&account, id, 0)]).unwrap();
        assert_eq!(response.accepted.len(), 1);
        assert_eq!(response.accepted[0].seq, 1);
        assert!(response.conflicts.is_empty());
        assert_eq!(response.cursor, SyncCursor(1));

        let page = pull(&conn, &account, 0, 10).unwrap();
        assert_eq!(page.envelopes.len(), 1);
        assert_eq!(page.envelopes[0].id, id);
        assert_eq!(page.envelopes[0].seq, Some(1));
        assert_eq!(page.envelopes[0].vault_id, account.vault_id);
        assert_eq!(page.envelopes[0].blob, vec![1, 2, 3, 4]);
        assert!(!page.has_more);
        assert_eq!(page.cursor, SyncCursor(1));

        // And nothing comes twice.
        let again = pull(&conn, &account, 1, 10).unwrap();
        assert!(again.envelopes.is_empty());
        assert_eq!(again.cursor, SyncCursor(1));
    }

    #[test]
    fn a_push_based_on_an_older_version_is_a_conflict_with_the_current_one() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let id = Uuid::now_v7();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();

        push(&mut conn, &account, first, &[envelope(&account, id, 0)]).unwrap();
        let mut newer = envelope(&account, id, 1);
        newer.blob = vec![9, 9, 9];
        push(&mut conn, &account, first, &[newer]).unwrap();

        // The second device still thinks version 1 is current.
        let mut stale = envelope(&account, id, 1);
        stale.blob = vec![5, 5, 5];
        let response = push(&mut conn, &account, second, &[stale]).unwrap();
        assert!(response.accepted.is_empty());
        assert_eq!(response.conflicts.len(), 1);
        assert_eq!(
            response.conflicts[0].blob,
            vec![9, 9, 9],
            "the conflict carries what the server holds"
        );
        assert_eq!(response.conflicts[0].seq, Some(2));
        assert_eq!(
            response.conflicts[0].base_seq, 2,
            "so the next attempt is based on it"
        );

        // Based on what it holds, the same record is taken.
        let mut retried = envelope(&account, id, 2);
        retried.blob = vec![5, 5, 5];
        let response = push(&mut conn, &account, second, &[retried]).unwrap();
        assert_eq!(response.accepted.len(), 1);
        assert_eq!(response.accepted[0].seq, 3);
    }

    #[test]
    fn one_conflict_does_not_stop_the_rest_of_the_batch() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let taken = Uuid::now_v7();
        push(&mut conn, &account, device, &[envelope(&account, taken, 0)]).unwrap();

        let response = push(
            &mut conn,
            &account,
            device,
            &[
                envelope(&account, taken, 0), // conflicts: it is at 1 now
                envelope(&account, Uuid::now_v7(), 0),
                envelope(&account, Uuid::now_v7(), 0),
            ],
        )
        .unwrap();
        assert_eq!(response.accepted.len(), 2);
        assert_eq!(response.conflicts.len(), 1);
        assert_eq!(count(&conn, &account).unwrap(), 3);
    }

    #[test]
    fn a_page_says_when_there_is_another_one() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        for _ in 0..5 {
            push(
                &mut conn,
                &account,
                device,
                &[envelope(&account, Uuid::now_v7(), 0)],
            )
            .unwrap();
        }

        let page = pull(&conn, &account, 0, 2).unwrap();
        assert_eq!(page.envelopes.len(), 2);
        assert!(page.has_more);
        assert_eq!(page.cursor, SyncCursor(2));

        let page = pull(&conn, &account, page.cursor.0, 2).unwrap();
        assert_eq!(page.envelopes.len(), 2);
        assert!(page.has_more);

        let page = pull(&conn, &account, page.cursor.0, 2).unwrap();
        assert_eq!(page.envelopes.len(), 1);
        assert!(!page.has_more, "the last page says so");
    }

    #[test]
    fn nothing_of_another_account_is_ever_in_the_answer() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let mine = account(&conn);
        let theirs = account(&conn);
        let device = Uuid::now_v7();
        push(
            &mut conn,
            &theirs,
            device,
            &[envelope(&theirs, Uuid::now_v7(), 0)],
        )
        .unwrap();

        assert!(pull(&conn, &mine, 0, 10).unwrap().envelopes.is_empty());
        assert_eq!(count(&conn, &mine).unwrap(), 0);
        assert_eq!(count(&conn, &theirs).unwrap(), 1);
    }

    #[test]
    fn what_the_server_can_check_without_a_key_it_does_check() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let id = Uuid::now_v7();

        let mut stranger = envelope(&account, id, 0);
        stranger.vault_id = Uuid::now_v7();
        assert!(matches!(
            push(&mut conn, &account, device, &[stranger]),
            Err(ApiError::Invalid(_))
        ));

        let mut short_nonce = envelope(&account, id, 0);
        short_nonce.nonce = vec![1, 2, 3];
        assert!(matches!(
            push(&mut conn, &account, device, &[short_nonce]),
            Err(ApiError::Invalid(_))
        ));

        let mut empty = envelope(&account, id, 0);
        empty.blob.clear();
        assert!(matches!(
            push(&mut conn, &account, device, &[empty]),
            Err(ApiError::Invalid(_))
        ));

        let mut huge = envelope(&account, id, 0);
        huge.blob = vec![0; MAX_BLOB_BYTES + 1];
        assert!(matches!(
            push(&mut conn, &account, device, &[huge]),
            Err(ApiError::TooLarge(_))
        ));

        let batch: Vec<Envelope> = (0..MAX_BATCH + 1)
            .map(|_| envelope(&account, Uuid::now_v7(), 0))
            .collect();
        assert!(matches!(
            push(&mut conn, &account, device, &batch),
            Err(ApiError::TooLarge(_))
        ));

        assert_eq!(count(&conn, &account).unwrap(), 0, "and nothing was stored");
    }

    #[test]
    fn a_refused_batch_leaves_nothing_behind() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let mut bad = envelope(&account, Uuid::now_v7(), 0);
        bad.nonce.clear();

        assert!(push(
            &mut conn,
            &account,
            device,
            &[envelope(&account, Uuid::now_v7(), 0), bad]
        )
        .is_err());
        assert_eq!(count(&conn, &account).unwrap(), 0);
        assert_eq!(
            accounts::get(&conn, account.id).unwrap().unwrap().seq,
            0,
            "and did not use up a sequence number"
        );
    }

    #[test]
    fn a_tombstone_goes_only_once_everyone_has_read_it_and_time_has_passed() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let account = account(&conn);
        let device = Uuid::now_v7();
        let id = Uuid::now_v7();
        let mut gone = envelope(&account, id, 0);
        gone.deleted = true;
        push(&mut conn, &account, device, &[gone]).unwrap();

        let ancient = now_ms() + 1;
        assert_eq!(
            purge_tombstones(&conn, &account, ancient, 0).unwrap(),
            0,
            "nobody has read it yet"
        );
        assert_eq!(
            purge_tombstones(&conn, &account, 0, 99).unwrap(),
            0,
            "and it is not old yet"
        );
        assert_eq!(purge_tombstones(&conn, &account, ancient, 99).unwrap(), 1);
        assert_eq!(count(&conn, &account).unwrap(), 0);
    }

    #[test]
    fn every_kind_survives_the_round_trip_through_the_database() {
        for kind in [
            EntityKind::Host,
            EntityKind::Group,
            EntityKind::Identity,
            EntityKind::Key,
            EntityKind::Snippet,
            EntityKind::PortForward,
            EntityKind::KnownHost,
            EntityKind::TerminalProfile,
            EntityKind::Secret,
        ] {
            assert_eq!(kind_from(&kind_name(kind)), Some(kind), "{kind:?}");
        }
    }
}
