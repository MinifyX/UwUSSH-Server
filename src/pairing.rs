//! The relay two devices pair through.
//!
//! When a device joins, it needs things the server must never learn: the
//! account key, and the fingerprint to pin. So the two devices run SPAKE2 —
//! a handshake where a short spoken code turns into a strong shared key — and
//! this server carries the messages between them without understanding any of
//! it. It is a post box with two slots and a timer.
//!
//! What that buys, and why the shape is what it is:
//!
//! - **One guess per code.** SPAKE2 gives an attacker who does not know the
//!   code exactly one online attempt, and a failed one leaves both sides with
//!   different keys. So a four-word code is enough, where a four-word password
//!   would not be.
//! - **Nothing is stored.** Sessions live in memory and expire in ten minutes.
//!   A server that restarts mid-pairing means starting the pairing again, not
//!   a message left lying around.
//! - **Small and few.** A handful of messages, a few kilobytes each. This is a
//!   handshake, not a file transfer, and nobody gets to use it as one.

use crate::{now_ms, random_bytes, ApiError, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Notify;
use uuid::Uuid;

/// Ten minutes: long enough to walk to the other machine, short enough that a
/// code read aloud is worthless by the evening.
pub const TTL_MS: u64 = 10 * 60 * 1000;

/// SPAKE2 is one message each way, then one sealed payload and an answer.
/// Four leaves room without leaving room to be abused.
pub const MAX_MESSAGES: usize = 4;

/// A handshake message, decoded. The payload that follows it carries an
/// account key and a token, not a file.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// How long a device waits for the other side before asking again.
pub const POLL_SECS: u64 = 20;

/// The alphabet a code is read aloud in: no letters that look like digits.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The device that is already in and opened the session.
    A,
    /// The device joining.
    B,
}

impl Side {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "a" | "A" => Some(Self::A),
            "b" | "B" => Some(Self::B),
            _ => None,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

struct Session {
    account: Uuid,
    from_a: Vec<Vec<u8>>,
    from_b: Vec<Vec<u8>>,
    expires_ms: u64,
    /// Woken when either side posts, so the other can be waiting rather than
    /// asking again and again.
    arrived: Arc<Notify>,
}

impl Session {
    fn slot(&mut self, side: Side) -> &mut Vec<Vec<u8>> {
        match side {
            Side::A => &mut self.from_a,
            Side::B => &mut self.from_b,
        }
    }

    fn read(&self, side: Side) -> &[Vec<u8>] {
        match side {
            Side::A => &self.from_a,
            Side::B => &self.from_b,
        }
    }
}

#[derive(Clone, Default)]
pub struct Pairings {
    inner: Arc<Mutex<HashMap<String, Session>>>,
}

impl Pairings {
    /// Open a session and return the short id that names it. The words that go
    /// with it are the client's business: they are the SPAKE2 password, and
    /// this server must never see them.
    pub fn open(&self, account: Uuid) -> String {
        let mut inner = self.inner.lock();
        inner.retain(|_, session| session.expires_ms > now_ms());
        let id = loop {
            let id = code();
            if !inner.contains_key(&id) {
                break id;
            }
        };
        inner.insert(
            id.clone(),
            Session {
                account,
                from_a: Vec::new(),
                from_b: Vec::new(),
                expires_ms: now_ms() + TTL_MS,
                arrived: Arc::new(Notify::new()),
            },
        );
        id
    }

    /// Put a message in for the other side.
    pub fn post(&self, id: &str, side: Side, message: Vec<u8>) -> Result<()> {
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(ApiError::TooLarge("a pairing message".into()));
        }
        if message.is_empty() {
            return Err(ApiError::Invalid("an empty pairing message".into()));
        }
        let mut inner = self.inner.lock();
        let session = live(&mut inner, id)?;
        if session.slot(side).len() >= MAX_MESSAGES {
            return Err(ApiError::Invalid(
                "that is more messages than a handshake takes".into(),
            ));
        }
        session.slot(side).push(message);
        session.arrived.notify_waiters();
        Ok(())
    }

    /// What the other side has said, from `after` onwards.
    pub fn read(&self, id: &str, side: Side, after: usize) -> Result<Vec<Vec<u8>>> {
        let mut inner = self.inner.lock();
        let session = live(&mut inner, id)?;
        let messages = session.read(side.other());
        Ok(messages.iter().skip(after).cloned().collect())
    }

    /// Something to wait on, so a device asking for messages can wait for them
    /// instead of asking again every second.
    pub fn waiter(&self, id: &str) -> Result<Arc<Notify>> {
        let mut inner = self.inner.lock();
        Ok(live(&mut inner, id)?.arrived.clone())
    }

    /// Which account a session belongs to — for closing one, which only that
    /// account may do.
    pub fn account_of(&self, id: &str) -> Result<Uuid> {
        let mut inner = self.inner.lock();
        Ok(live(&mut inner, id)?.account)
    }

    /// Done, or given up. Either way it is over.
    pub fn close(&self, id: &str) -> bool {
        self.inner.lock().remove(id).is_some()
    }

    pub fn len(&self) -> usize {
        let mut inner = self.inner.lock();
        inner.retain(|_, session| session.expires_ms > now_ms());
        inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A session that is there and has not run out. An expired one answers like
/// one that never existed, because to the device asking it is the same thing.
fn live<'a>(inner: &'a mut HashMap<String, Session>, id: &str) -> Result<&'a mut Session> {
    match inner.get(id) {
        Some(session) if session.expires_ms > now_ms() => {}
        Some(_) => {
            inner.remove(id);
            return Err(ApiError::NotFound);
        }
        None => return Err(ApiError::NotFound),
    }
    inner.get_mut(id).ok_or(ApiError::NotFound)
}

/// Five characters, spoken once. Guessing one is worth nothing without the
/// words that go with it — those are what SPAKE2 checks.
fn code() -> String {
    random_bytes::<5>()
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_side_hears_the_other_and_not_itself() {
        let pairings = Pairings::default();
        let account = Uuid::now_v7();
        let id = pairings.open(account);

        pairings
            .post(&id, Side::A, b"spake from a".to_vec())
            .unwrap();
        assert!(
            pairings.read(&id, Side::A, 0).unwrap().is_empty(),
            "a device does not read its own messages back"
        );
        assert_eq!(
            pairings.read(&id, Side::B, 0).unwrap(),
            vec![b"spake from a".to_vec()]
        );

        pairings
            .post(&id, Side::B, b"spake from b".to_vec())
            .unwrap();
        assert_eq!(
            pairings.read(&id, Side::A, 0).unwrap(),
            vec![b"spake from b".to_vec()]
        );

        // And each side only asks for what it has not seen.
        pairings
            .post(&id, Side::A, b"sealed payload".to_vec())
            .unwrap();
        assert_eq!(
            pairings.read(&id, Side::B, 1).unwrap(),
            vec![b"sealed payload".to_vec()]
        );
    }

    #[test]
    fn a_session_that_is_over_is_gone() {
        let pairings = Pairings::default();
        let id = pairings.open(Uuid::now_v7());
        assert!(pairings.close(&id));
        assert!(!pairings.close(&id));
        assert!(matches!(
            pairings.post(&id, Side::A, b"late".to_vec()),
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            pairings.read(&id, Side::B, 0),
            Err(ApiError::NotFound)
        ));
        assert!(pairings.is_empty());
    }

    #[test]
    fn an_id_nobody_opened_is_not_found() {
        let pairings = Pairings::default();
        assert!(matches!(
            pairings.read("ZZZZZ", Side::B, 0),
            Err(ApiError::NotFound)
        ));
    }

    #[test]
    fn a_handshake_cannot_turn_into_a_file_transfer() {
        let pairings = Pairings::default();
        let id = pairings.open(Uuid::now_v7());

        assert!(matches!(
            pairings.post(&id, Side::A, vec![0; MAX_MESSAGE_BYTES + 1]),
            Err(ApiError::TooLarge(_))
        ));
        assert!(matches!(
            pairings.post(&id, Side::A, Vec::new()),
            Err(ApiError::Invalid(_))
        ));

        for _ in 0..MAX_MESSAGES {
            pairings.post(&id, Side::A, b"x".to_vec()).unwrap();
        }
        assert!(matches!(
            pairings.post(&id, Side::A, b"one too many".to_vec()),
            Err(ApiError::Invalid(_))
        ));
        // The other side still has its own room.
        pairings.post(&id, Side::B, b"mine".to_vec()).unwrap();
    }

    #[test]
    fn two_sessions_never_get_mixed_up() {
        let pairings = Pairings::default();
        let one = pairings.open(Uuid::now_v7());
        let two = pairings.open(Uuid::now_v7());
        assert_ne!(one, two);

        pairings.post(&one, Side::A, b"for one".to_vec()).unwrap();
        assert!(pairings.read(&two, Side::B, 0).unwrap().is_empty());
        assert_eq!(pairings.len(), 2);
    }

    #[test]
    fn a_session_runs_out() {
        let pairings = Pairings::default();
        let id = pairings.open(Uuid::now_v7());
        pairings.inner.lock().get_mut(&id).unwrap().expires_ms = now_ms() - 1;

        assert!(matches!(
            pairings.read(&id, Side::B, 0),
            Err(ApiError::NotFound)
        ));
        assert!(pairings.is_empty(), "and it is not kept around");
    }

    #[tokio::test]
    async fn waiting_ends_as_soon_as_the_other_side_speaks() {
        let pairings = Pairings::default();
        let id = pairings.open(Uuid::now_v7());
        let waiter = pairings.waiter(&id).unwrap();

        let posting = {
            let pairings = pairings.clone();
            let id = id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                pairings.post(&id, Side::B, b"here".to_vec()).unwrap();
            })
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), waiter.notified())
            .await
            .expect("woken by the other side");
        posting.await.unwrap();
        assert_eq!(pairings.read(&id, Side::A, 0).unwrap().len(), 1);
    }

    #[test]
    fn codes_are_short_and_do_not_repeat() {
        let one = code();
        assert_eq!(one.len(), 5);
        assert!(one.chars().all(|c| ALPHABET.contains(&(c as u8))));
        assert_ne!(one, code());
    }
}
