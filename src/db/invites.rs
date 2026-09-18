//! Codes that let someone in once.
//!
//! An **invite** creates an account. An **enrolment token** adds a device to an
//! account that exists, and only a device already in that account can make one
//! — it travels to the joining device through a channel this server cannot
//! read, so the server never learns it in the clear.
//!
//! Both are stored as a hash. What is written down cannot be used to get in,
//! and both can only be redeemed once.

use crate::db::constant_time_eq;
use crate::{now_ms, random_bytes, sha256};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

/// Crockford's alphabet without the letters that look like digits: a code gets
/// read aloud and typed in.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

/// Fifteen characters from thirty, in three groups: about 73 bits, which no
/// rate-limited guesser will ever walk through.
fn code() -> String {
    let bytes = random_bytes::<15>();
    let mut code = String::with_capacity(17);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % 5 == 0 {
            code.push('-');
        }
        code.push(ALPHABET[*byte as usize % ALPHABET.len()] as char);
    }
    code
}

/// Codes are compared as typed, not as they look: dashes and case are noise.
fn normalise(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn hash(code: &str) -> Vec<u8> {
    sha256(normalise(code).as_bytes()).to_vec()
}

pub const INVITE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const ENROLMENT_TTL_MS: u64 = 10 * 60 * 1000;

/// Make an invite. The code is returned once and never stored.
pub fn create_invite(conn: &Connection, ttl_ms: u64) -> rusqlite::Result<String> {
    let code = code();
    conn.execute(
        "INSERT INTO invites (code_hash, created_ms, expires_ms) VALUES (?1, ?2, ?3)",
        params![hash(&code), now_ms() as i64, (now_ms() + ttl_ms) as i64],
    )?;
    Ok(code)
}

/// Use an invite up. Returns whether it was one — unused, unexpired, and
/// exactly this one.
pub fn redeem_invite(conn: &Connection, code: &str) -> rusqlite::Result<bool> {
    let now = now_ms() as i64;
    let changed = conn.execute(
        "UPDATE invites SET used_ms = ?2
          WHERE code_hash = ?1 AND used_ms IS NULL AND expires_ms > ?2",
        params![hash(code), now],
    )?;
    Ok(changed > 0)
}

pub fn count_open_invites(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM invites WHERE used_ms IS NULL AND expires_ms > ?1",
        [now_ms() as i64],
        |row| row.get(0),
    )
}

/// A one-time token for a device joining an account that already exists.
pub fn create_enrolment(conn: &Connection, account_id: Uuid) -> rusqlite::Result<String> {
    let token = crate::b64::encode(random_bytes::<32>());
    conn.execute(
        "INSERT INTO enrolments (token_hash, account_id, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            sha256(token.as_bytes()).to_vec(),
            account_id.to_string(),
            now_ms() as i64,
            (now_ms() + ENROLMENT_TTL_MS) as i64,
        ],
    )?;
    Ok(token)
}

/// Which account a token joins, without using it up: the joining device needs
/// the vault's parameters before it can prove it knows the master password.
pub fn peek_enrolment(conn: &Connection, token: &str) -> rusqlite::Result<Option<Uuid>> {
    let row: Option<(Vec<u8>, String)> = conn
        .query_row(
            "SELECT token_hash, account_id FROM enrolments
              WHERE token_hash = ?1 AND used_ms IS NULL AND expires_ms > ?2",
            params![sha256(token.as_bytes()).to_vec(), now_ms() as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(stored, account)| {
        // The lookup already matched, but compare anyway: this is the one
        // place a token decides something, and the habit costs nothing.
        constant_time_eq(&stored, &sha256(token.as_bytes()))
            .then(|| Uuid::parse_str(&account).ok())
            .flatten()
    }))
}

/// Use a token up, once.
pub fn redeem_enrolment(conn: &Connection, token: &str) -> rusqlite::Result<Option<Uuid>> {
    let Some(account) = peek_enrolment(conn, token)? else {
        return Ok(None);
    };
    let changed = conn.execute(
        "UPDATE enrolments SET used_ms = ?2 WHERE token_hash = ?1 AND used_ms IS NULL",
        params![sha256(token.as_bytes()).to_vec(), now_ms() as i64],
    )?;
    Ok((changed > 0).then_some(account))
}

/// Forget codes that are used or long expired. Housekeeping, not security:
/// neither is worth anything any more.
pub fn purge(conn: &Connection) -> rusqlite::Result<()> {
    let cutoff = now_ms().saturating_sub(30 * 24 * 60 * 60 * 1000) as i64;
    conn.execute("DELETE FROM invites WHERE expires_ms < ?1", [cutoff])?;
    conn.execute("DELETE FROM enrolments WHERE expires_ms < ?1", [cutoff])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{accounts, Db};

    #[test]
    fn an_invite_works_once_and_is_never_stored_in_the_clear() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let code = create_invite(&conn, INVITE_TTL_MS).unwrap();

        let stored: Vec<u8> = conn
            .query_row("SELECT code_hash FROM invites", [], |row| row.get(0))
            .unwrap();
        assert!(!String::from_utf8_lossy(&stored).contains(&code));

        assert_eq!(count_open_invites(&conn).unwrap(), 1);
        assert!(redeem_invite(&conn, &code).unwrap());
        assert!(!redeem_invite(&conn, &code).unwrap(), "only once");
        assert_eq!(count_open_invites(&conn).unwrap(), 0);
    }

    #[test]
    fn a_code_is_taken_as_it_was_typed() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let code = create_invite(&conn, INVITE_TTL_MS).unwrap();
        let typed = code.to_lowercase().replace('-', " ");
        assert!(redeem_invite(&conn, &typed).unwrap());
    }

    #[test]
    fn an_expired_invite_is_no_invite() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let code = create_invite(&conn, 0).unwrap();
        assert!(!redeem_invite(&conn, &code).unwrap());
        assert_eq!(count_open_invites(&conn).unwrap(), 0);
    }

    #[test]
    fn a_code_nobody_made_opens_nothing() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        create_invite(&conn, INVITE_TTL_MS).unwrap();
        assert!(!redeem_invite(&conn, "AAAAA-BBBBB-CCCCC").unwrap());
        assert!(!redeem_invite(&conn, "").unwrap());
    }

    #[test]
    fn an_enrolment_token_names_its_account_and_is_spent_on_use() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let account = accounts::create(&conn, &accounts::tests::header(), b"key").unwrap();
        let token = create_enrolment(&conn, account.id).unwrap();

        assert_eq!(peek_enrolment(&conn, &token).unwrap(), Some(account.id));
        assert_eq!(
            peek_enrolment(&conn, &token).unwrap(),
            Some(account.id),
            "peeking does not use it up"
        );
        assert_eq!(redeem_enrolment(&conn, &token).unwrap(), Some(account.id));
        assert_eq!(redeem_enrolment(&conn, &token).unwrap(), None);
        assert_eq!(peek_enrolment(&conn, &token).unwrap(), None);
    }

    #[test]
    fn codes_do_not_repeat() {
        let one = code();
        let two = code();
        assert_ne!(one, two);
        assert_eq!(one.len(), 17, "{one}");
        assert_eq!(normalise(&one).len(), 15);
    }
}
