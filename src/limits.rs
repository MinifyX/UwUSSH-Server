//! How often somebody may try.
//!
//! Two kinds of counting. **Per address**, where guessing would pay: creating
//! an account, answering a challenge, joining with an enrolment token, the
//! pairing relay. And **per account or device**, where one account holder
//! could make the server work for nobody else: pushing and pulling, making
//! tokens, opening pairing sessions, and proving the master password, which is
//! a guess too when the one proving it is not the owner.
//!
//! The counters live in memory. A restart forgets them, which is the right
//! trade for a homelab server: the alternative is a write to disk for every
//! request, to slow down an attacker who would have to survive the restart
//! anyway.

use crate::{ApiError, Result};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// What each protected endpoint allows, per address or per account.
pub struct Bucket {
    pub name: &'static str,
    pub max: usize,
    pub window: Duration,
}

pub const ACCOUNTS: Bucket = Bucket {
    name: "accounts",
    max: 5,
    window: Duration::from_secs(60 * 60),
};

pub const SESSION: Bucket = Bucket {
    name: "session",
    max: 30,
    window: Duration::from_secs(60),
};

pub const ENROL: Bucket = Bucket {
    name: "enrol",
    max: 10,
    window: Duration::from_secs(10 * 60),
};

/// Pairing is a handshake of a few messages, and the devices wait rather than
/// ask again — but they do wait in a loop, so this one is roomier.
pub const PAIR: Bucket = Bucket {
    name: "pair",
    max: 60,
    window: Duration::from_secs(10 * 60),
};

// ── Per account, or per device ──────────────────────────────────────────────

/// A device syncing hard pushes a few batches a pass; this is room for a
/// dozen devices doing that at once.
pub const PUSH: Bucket = Bucket {
    name: "push",
    max: 120,
    window: Duration::from_secs(60),
};

/// A first pull of a large vault is a few hundred pages.
pub const PULL: Bucket = Bucket {
    name: "pull",
    max: 600,
    window: Duration::from_secs(60),
};

/// Enrolment tokens and pairing sessions: a person adds a device now and then.
pub const JOINS: Bucket = Bucket {
    name: "joins",
    max: 10,
    window: Duration::from_secs(10 * 60),
};

/// Proving the master password with a device token — a password change, or
/// revoking another device. Counted **per device**: many wrong proofs are
/// somebody with a stolen device guessing, and counting them for the whole
/// account would let that device use up the owner's tries too — and keep the
/// owner from revoking it.
pub const PROOF: Bucket = Bucket {
    name: "proof",
    max: 10,
    window: Duration::from_secs(60 * 60),
};

/// How many addresses the limiter remembers at most. Beyond that, somebody is
/// making up addresses faster than they fall out of their windows, and a new
/// one is refused rather than remembered — memory stays bounded. Accounts and
/// devices are not addresses: there are only as many as the server took in,
/// and they are never refused for want of room.
const MAX_ADDRESSES: usize = 50_000;

/// How often the limiter forgets whoever is done: once a minute, and when it
/// is full, at most once a second before it refuses anybody.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
const SWEEP_WHEN_FULL: Duration = Duration::from_secs(1);

type Key = (String, &'static str);

/// One address or account in one bucket.
struct Tries {
    /// When it tried, oldest first — at most `bucket.max` of them.
    at: VecDeque<Instant>,
    /// Its bucket's window: how long any of it is worth keeping.
    window: Duration,
    /// Whether the log has already heard that it was refused. A refusal is
    /// logged once, not once per request: a flood of refused requests must
    /// not become a flood of log lines on a small disk.
    said: bool,
}

#[derive(Default)]
struct Table {
    tries: HashMap<Key, Tries>,
}

impl Table {
    /// Forget everyone whose last try has left its bucket's window.
    fn sweep(&mut self, now: Instant) {
        self.tries.retain(|_, tries| {
            tries
                .at
                .back()
                .is_some_and(|last| now.duration_since(*last) < tries.window)
        });
    }
}

struct Hits {
    addresses: Table,
    /// Accounts and devices: bounded by what the server took in, so never
    /// refused for want of room.
    members: Table,
    swept: Instant,
    /// When the log last heard that the table was full.
    said_full: Option<Instant>,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Hits>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Hits {
                addresses: Table::default(),
                members: Table::default(),
                swept: Instant::now(),
                said_full: None,
            })),
        }
    }
}

impl RateLimiter {
    /// Count this attempt from an address, and say whether it is one too many.
    pub fn check(&self, who: &str, bucket: &Bucket) -> Result<()> {
        self.count(who, bucket, true)
    }

    /// Count an attempt on behalf of an account rather than an address.
    pub fn check_account(&self, account: Uuid, bucket: &Bucket) -> Result<()> {
        self.count(&format!("account:{account}"), bucket, false)
    }

    /// Count an attempt on behalf of one device.
    pub fn check_device(&self, device: Uuid, bucket: &Bucket) -> Result<()> {
        self.count(&format!("device:{device}"), bucket, false)
    }

    fn count(&self, who: &str, bucket: &Bucket, address: bool) -> Result<()> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        if now.duration_since(inner.swept) >= SWEEP_EVERY {
            inner.addresses.sweep(now);
            inner.members.sweep(now);
            inner.swept = now;
        }

        let key = (who.to_string(), bucket.name);
        if address
            && !inner.addresses.tries.contains_key(&key)
            && inner.addresses.tries.len() >= MAX_ADDRESSES
        {
            // Before anybody is refused, forget whoever is done.
            if now.duration_since(inner.swept) >= SWEEP_WHEN_FULL {
                inner.addresses.sweep(now);
                inner.swept = now;
            }
            if inner.addresses.tries.len() >= MAX_ADDRESSES {
                if inner
                    .said_full
                    .is_none_or(|said| now.duration_since(said) >= SWEEP_EVERY)
                {
                    tracing::warn!("the rate limiter is full; refusing addresses it does not know");
                    inner.said_full = Some(now);
                }
                return Err(ApiError::RateLimited);
            }
        }

        let table = if address {
            &mut inner.addresses
        } else {
            &mut inner.members
        };
        let tries = table.tries.entry(key).or_insert_with(|| Tries {
            at: VecDeque::new(),
            window: bucket.window,
            said: false,
        });
        while tries
            .at
            .front()
            .is_some_and(|first| now.duration_since(*first) >= bucket.window)
        {
            tries.at.pop_front();
        }
        if tries.at.len() >= bucket.max {
            if !tries.said {
                tracing::warn!(who, bucket = bucket.name, "rate limited");
                tries.said = true;
            }
            return Err(ApiError::RateLimited);
        }
        tries.said = false;
        tries.at.push_back(now);
        Ok(())
    }

    /// A successful attempt need not count against the next one: the limit is
    /// there to slow down guessing, not to punish a device that syncs.
    pub fn forgive(&self, who: &str, bucket: &Bucket) {
        Self::take_back(&mut self.inner.lock().addresses, who, bucket);
    }

    pub fn forgive_device(&self, device: Uuid, bucket: &Bucket) {
        Self::take_back(
            &mut self.inner.lock().members,
            &format!("device:{device}"),
            bucket,
        );
    }

    fn take_back(table: &mut Table, who: &str, bucket: &Bucket) {
        if let Some(tries) = table.tries.get_mut(&(who.to_string(), bucket.name)) {
            tries.at.pop_back();
        }
    }

    #[cfg(test)]
    fn addresses(&self) -> usize {
        self.inner.lock().addresses.tries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: Bucket = Bucket {
        name: "session",
        max: 2,
        window: Duration::from_secs(60),
    };

    #[test]
    fn the_third_try_of_two_is_refused() {
        let limiter = RateLimiter::default();
        assert!(limiter.check("10.0.0.1", &TINY).is_ok());
        assert!(limiter.check("10.0.0.1", &TINY).is_ok());
        assert!(matches!(
            limiter.check("10.0.0.1", &TINY),
            Err(ApiError::RateLimited)
        ));
    }

    #[test]
    fn one_address_does_not_lock_out_another() {
        let limiter = RateLimiter::default();
        for _ in 0..2 {
            limiter.check("10.0.0.1", &TINY).unwrap();
        }
        assert!(limiter.check("10.0.0.2", &TINY).is_ok());
    }

    #[test]
    fn buckets_are_counted_apart() {
        let limiter = RateLimiter::default();
        for _ in 0..2 {
            limiter.check("10.0.0.1", &TINY).unwrap();
        }
        assert!(limiter.check("10.0.0.1", &ACCOUNTS).is_ok());
    }

    #[test]
    fn accounts_and_devices_are_counted_apart_from_addresses() {
        let limiter = RateLimiter::default();
        let account = Uuid::now_v7();
        for _ in 0..2 {
            limiter.check_account(account, &TINY).unwrap();
        }
        assert!(limiter.check_account(account, &TINY).is_err());
        assert!(limiter.check_account(Uuid::now_v7(), &TINY).is_ok());

        let (thief, owner) = (Uuid::now_v7(), Uuid::now_v7());
        for _ in 0..2 {
            limiter.check_device(thief, &TINY).unwrap();
        }
        assert!(limiter.check_device(thief, &TINY).is_err());
        assert!(
            limiter.check_device(owner, &TINY).is_ok(),
            "one device using up its tries leaves the others theirs"
        );
        limiter.forgive_device(thief, &TINY);
        assert!(limiter.check_device(thief, &TINY).is_ok());
    }

    #[test]
    fn what_worked_does_not_count_against_the_next_one() {
        let limiter = RateLimiter::default();
        limiter.check("10.0.0.1", &TINY).unwrap();
        limiter.forgive("10.0.0.1", &TINY);
        limiter.check("10.0.0.1", &TINY).unwrap();
        limiter.check("10.0.0.1", &TINY).unwrap();
        assert!(limiter.check("10.0.0.1", &TINY).is_err());
    }

    #[test]
    fn what_has_fallen_out_of_the_window_is_forgotten() {
        let limiter = RateLimiter::default();
        let gone = Bucket {
            name: "session",
            max: 1,
            window: Duration::from_millis(1),
        };
        limiter.check("10.0.0.1", &gone).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check("10.0.0.1", &gone).is_ok());
        assert_eq!(limiter.addresses(), 1, "one address, one bucket");
    }

    #[test]
    fn a_flood_of_made_up_addresses_does_not_grow_without_end() {
        let limiter = RateLimiter::default();
        for n in 0..MAX_ADDRESSES {
            limiter.check(&format!("key-{n}"), &TINY).unwrap();
        }
        assert!(
            limiter.check("one-more", &TINY).is_err(),
            "a newcomer beyond the cap is refused"
        );
        assert!(
            limiter.check("key-7", &TINY).is_ok(),
            "whoever is known already still gets their tries"
        );
        assert!(
            limiter.check_account(Uuid::now_v7(), &PUSH).is_ok(),
            "and accounts are never refused for want of room"
        );
        assert_eq!(limiter.addresses(), MAX_ADDRESSES);
    }

    #[test]
    fn a_full_table_makes_room_from_whoever_is_done() {
        let limiter = RateLimiter::default();
        let brief = Bucket {
            name: "session",
            max: 5,
            window: Duration::from_millis(1),
        };
        for n in 0..MAX_ADDRESSES {
            limiter.check(&format!("key-{n}"), &brief).unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
        // The last sweep was a moment ago, not a second: still full.
        limiter.inner.lock().swept = Instant::now() - SWEEP_WHEN_FULL;
        assert!(
            limiter.check("newcomer", &TINY).is_ok(),
            "the ones whose short window ended made room"
        );
        assert_eq!(limiter.addresses(), 1);
    }
}
