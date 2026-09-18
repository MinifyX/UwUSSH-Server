//! What every request has to hand.

use crate::auth::{Challenges, Sessions};
use crate::db::Db;
use crate::limits::RateLimiter;
use crate::Config;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<Config>,
    pub sessions: Sessions,
    pub challenges: Challenges,
    pub limits: RateLimiter,
    pub events: Events,
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Self {
        Self {
            db: Arc::new(db),
            config: Arc::new(config),
            sessions: Sessions::default(),
            challenges: Challenges::default(),
            limits: RateLimiter::default(),
            events: Events::default(),
        }
    }
}

/// "There is something new from sequence N", per account.
///
/// Only the number travels — a device that hears it pulls, and the pull is the
/// same one it would have made anyway. Nothing about a record is ever pushed
/// out, so this stays a hint rather than a second way in.
#[derive(Clone, Default)]
pub struct Events {
    channels: Arc<Mutex<HashMap<Uuid, broadcast::Sender<u64>>>>,
}

impl Events {
    pub fn subscribe(&self, account: Uuid) -> broadcast::Receiver<u64> {
        self.channels
            .lock()
            .entry(account)
            .or_insert_with(|| broadcast::channel(16).0)
            .subscribe()
    }

    /// Tell whoever is listening. Nobody listening is the normal case.
    pub fn announce(&self, account: Uuid, seq: u64) {
        let mut channels = self.channels.lock();
        // A channel nobody listens to any more is dropped instead of kept for
        // an account that may never come back.
        if let Some(sender) = channels.get(&account) {
            if sender.receiver_count() == 0 {
                channels.remove(&account);
                return;
            }
            let _ = sender.send(seq);
        }
    }

    pub fn listeners(&self, account: Uuid) -> usize {
        self.channels
            .lock()
            .get(&account)
            .map(|sender| sender.receiver_count())
            .unwrap_or(0)
    }
}

/// The address a request came from, as the rate limiter counts it.
///
/// Behind a reverse proxy every request comes from the proxy, so the real
/// address is in `X-Forwarded-For` — which anyone can set, so it is only
/// believed when the server was told there is a proxy in front.
pub fn client_key(
    config: &Config,
    headers: &axum::http::HeaderMap,
    peer: Option<SocketAddr>,
) -> String {
    if config.trust_forwarded {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return forwarded.to_string();
        }
    }
    peer.map(|peer| peer.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(forwarded: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", forwarded.parse().unwrap());
        headers
    }

    #[test]
    fn a_forwarded_address_is_ignored_unless_there_is_a_proxy() {
        let config = Config::default();
        let peer = Some("10.0.0.5:4000".parse().unwrap());
        assert_eq!(
            client_key(&config, &headers("1.2.3.4"), peer),
            "10.0.0.5",
            "anyone can send that header"
        );

        let trusting = Config {
            trust_forwarded: true,
            ..Config::default()
        };
        assert_eq!(client_key(&trusting, &headers("1.2.3.4"), peer), "1.2.3.4");
        assert_eq!(
            client_key(&trusting, &headers("1.2.3.4, 10.0.0.1"), peer),
            "1.2.3.4",
            "the first one is the client"
        );
        assert_eq!(
            client_key(&trusting, &HeaderMap::new(), peer),
            "10.0.0.5",
            "and without the header, the socket"
        );
    }

    #[tokio::test]
    async fn an_announcement_reaches_a_listening_device() {
        let events = Events::default();
        let account = Uuid::now_v7();
        let mut listener = events.subscribe(account);
        assert_eq!(events.listeners(account), 1);

        events.announce(account, 7);
        assert_eq!(listener.recv().await.unwrap(), 7);

        // Another account hears nothing.
        events.announce(Uuid::now_v7(), 9);
        assert!(listener.try_recv().is_err());
    }

    #[test]
    fn a_channel_nobody_listens_to_is_dropped() {
        let events = Events::default();
        let account = Uuid::now_v7();
        drop(events.subscribe(account));
        events.announce(account, 1);
        assert_eq!(events.listeners(account), 0);
        assert!(events.channels.lock().is_empty());
    }
}
