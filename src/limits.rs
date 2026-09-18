//! How often somebody may try.
//!
//! Only the endpoints where guessing would pay: creating an account, answering
//! a challenge, joining with an enrolment token. Everything else is behind a
//! token already, and a device that syncs too eagerly is a device, not an
//! attacker.
//!
//! The counters live in memory. A restart forgets them, which is the right
//! trade for a homelab server: the alternative is a write to disk for every
//! request, to slow down an attacker who would have to survive the restart
//! anyway.

use crate::{ApiError, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What each protected endpoint allows, per address.
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

fn window_of(name: &str) -> Duration {
    match name {
        "accounts" => ACCOUNTS.window,
        "enrol" => ENROL.window,
        "pair" => PAIR.window,
        _ => SESSION.window,
    }
}

/// When each address last tried, per bucket.
type Hits = HashMap<(String, &'static str), Vec<Instant>>;

#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<Hits>>,
}

impl RateLimiter {
    /// Count this attempt, and say whether it is one too many.
    pub fn check(&self, who: &str, bucket: &Bucket) -> Result<()> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        // Forget what has fallen out of every window, or a server that runs
        // for months keeps an entry per address that ever knocked.
        inner.retain(|(_, name), hits| {
            let window = window_of(name);
            hits.retain(|hit| now.duration_since(*hit) < window);
            !hits.is_empty()
        });

        let hits = inner.entry((who.to_string(), bucket.name)).or_default();
        hits.retain(|hit| now.duration_since(*hit) < bucket.window);
        if hits.len() >= bucket.max {
            tracing::warn!(who, bucket = bucket.name, "rate limited");
            return Err(ApiError::RateLimited);
        }
        hits.push(now);
        Ok(())
    }

    /// A successful attempt need not count against the next one: the limit is
    /// there to slow down guessing, not to punish a device that syncs.
    pub fn forgive(&self, who: &str, bucket: &Bucket) {
        if let Some(hits) = self.inner.lock().get_mut(&(who.to_string(), bucket.name)) {
            hits.pop();
        }
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
        assert_eq!(limiter.inner.lock().len(), 1, "one address, one bucket");
    }
}
