//! Who is asking.
//!
//! A device proves itself by **signing a challenge** with the key it enrolled,
//! and gets a short-lived token for the requests that follow. Nothing that
//! could be replayed travels twice: the challenge is used once, the token
//! expires within the hour, and both live only in memory — a server that
//! restarts asks every device to sign again, which costs one round trip and
//! nobody's sleep.
//!
//! The master password never appears here at all. It is proved once, at
//! enrolment, and never again: after that the device key is the credential.

use crate::db::accounts::Account;
use crate::db::devices::Device;
use crate::db::{accounts, devices};
use crate::{b64, now_ms, random_bytes, state::AppState, ApiError, Result};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ed25519_dalek::{Signature, VerifyingKey};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// A challenge is good for one minute: long enough for a slow link, short
/// enough that a copied one is worthless by the time it is copied.
pub const CHALLENGE_TTL_MS: u64 = 60_000;

/// What a device signs — from the protocol crate, because a client that
/// builds these bytes slightly differently is a client that cannot log in,
/// and the two would be debugged separately for an afternoon.
pub use uwussh_proto::api::session_material;

pub fn verify_signature(public_key: &[u8; 32], material: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    // `verify_strict` rejects the weak keys and malleable forms that plain
    // verification accepts.
    key.verify_strict(material, &Signature::from_bytes(&signature))
        .is_ok()
}

/// What a device was given to sign, and until when.
type Outstanding = HashMap<Uuid, Vec<(Vec<u8>, u64)>>;

/// Challenges a device may have outstanding at once. More than one, so that
/// somebody who learned a device id cannot keep it from ever signing in by
/// asking for a fresh challenge in its name just before it answers.
pub const CHALLENGES_PER_DEVICE: usize = 4;

/// The challenges devices were given and have not answered yet.
#[derive(Clone, Default)]
pub struct Challenges {
    inner: Arc<Mutex<Outstanding>>,
}

impl Challenges {
    /// A fresh challenge. The oldest of that device's goes when there are too
    /// many.
    pub fn issue(&self, device: Uuid) -> Vec<u8> {
        let challenge = random_bytes::<32>().to_vec();
        let now = now_ms();
        let mut inner = self.inner.lock();
        inner.retain(|_, issued| {
            issued.retain(|(_, expires)| *expires > now);
            !issued.is_empty()
        });
        let issued = inner.entry(device).or_default();
        if issued.len() >= CHALLENGES_PER_DEVICE {
            issued.remove(0);
        }
        issued.push((challenge.clone(), now + CHALLENGE_TTL_MS));
        challenge
    }

    /// The challenges a device may answer now.
    pub fn outstanding(&self, device: Uuid) -> Vec<Vec<u8>> {
        let now = now_ms();
        self.inner
            .lock()
            .get(&device)
            .map(|issued| {
                issued
                    .iter()
                    .filter(|(_, expires)| *expires > now)
                    .map(|(challenge, _)| challenge.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Use one up. Returns whether it was still there — two requests carrying
    /// the same signature race here, and only one of them may win.
    pub fn spend(&self, device: Uuid, challenge: &[u8]) -> bool {
        let mut inner = self.inner.lock();
        let Some(issued) = inner.get_mut(&device) else {
            return false;
        };
        let before = issued.len();
        issued.retain(|(held, _)| held.as_slice() != challenge);
        let spent = issued.len() < before;
        if issued.is_empty() {
            inner.remove(&device);
        }
        spent
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub expires_ms: u64,
}

/// Session tokens, in memory only.
#[derive(Clone, Default)]
pub struct Sessions {
    inner: Arc<Mutex<HashMap<String, Session>>>,
}

impl Sessions {
    pub fn issue(&self, account_id: Uuid, device_id: Uuid, ttl_ms: u64) -> (String, u64) {
        let token = b64::encode(random_bytes::<32>());
        let expires_ms = now_ms() + ttl_ms;
        let mut inner = self.inner.lock();
        inner.retain(|_, session| session.expires_ms > now_ms());
        inner.insert(
            token.clone(),
            Session {
                account_id,
                device_id,
                expires_ms,
            },
        );
        (token, expires_ms)
    }

    pub fn get(&self, token: &str) -> Option<Session> {
        let session = *self.inner.lock().get(token)?;
        (session.expires_ms > now_ms()).then_some(session)
    }

    /// Revoking a device must not leave it an hour of access it already holds.
    pub fn drop_device(&self, device_id: Uuid) {
        self.inner
            .lock()
            .retain(|_, session| session.device_id != device_id);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A request that carries a valid token, with the account and device behind it.
///
/// Both are loaded fresh from the database on every request rather than kept in
/// the token, so revoking a device takes effect at once.
pub struct Authenticated {
    pub account: Account,
    pub device: Device,
    /// The token itself, for a request that outlives the moment it was
    /// checked — an event stream asks again whether it is still good.
    pub token: String,
}

/// The device behind the bearer token in `headers`, if there is one and it
/// is still in.
pub fn authenticate(state: &AppState, headers: &axum::http::HeaderMap) -> Result<Authenticated> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or(ApiError::Unauthorized)?;

    let session = state.sessions.get(token).ok_or(ApiError::Unauthorized)?;
    let conn = state.db.lock();
    let device = devices::get(&conn, session.device_id)?.ok_or(ApiError::Unauthorized)?;
    if device.revoked || device.account_id != session.account_id {
        // A token outliving its device would be an hour of access nobody
        // can take away.
        drop(conn);
        state.sessions.drop_device(session.device_id);
        return Err(ApiError::Unauthorized);
    }
    let account = accounts::get(&conn, session.account_id)?.ok_or(ApiError::Unauthorized)?;
    Ok(Authenticated {
        account,
        device,
        token: token.to_string(),
    })
}

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        authenticate(state, &parts.headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn a_signature_only_counts_for_its_own_account_device_and_challenge() {
        let signing = key();
        let public = signing.verifying_key().to_bytes();
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let challenge = random_bytes::<32>();

        let material = session_material(account, device, &challenge);
        let signature = signing.sign(&material).to_bytes();
        assert!(verify_signature(&public, &material, &signature));

        for other in [
            session_material(Uuid::now_v7(), device, &challenge),
            session_material(account, Uuid::now_v7(), &challenge),
            session_material(account, device, &random_bytes::<32>()),
        ] {
            assert!(
                !verify_signature(&public, &other, &signature),
                "a signature must not travel"
            );
        }
        assert!(!verify_signature(&[0u8; 32], &material, &signature));
        assert!(!verify_signature(&public, &material, &[0u8; 64]));
        assert!(!verify_signature(&public, &material, b"short"));
    }

    #[test]
    fn a_challenge_is_answered_once() {
        let challenges = Challenges::default();
        let device = Uuid::now_v7();
        let challenge = challenges.issue(device);
        assert_eq!(challenges.outstanding(device), vec![challenge.clone()]);
        assert!(challenges.spend(device, &challenge));
        assert!(!challenges.spend(device, &challenge), "used up");
        assert!(challenges.outstanding(device).is_empty());
    }

    #[test]
    fn asking_again_does_not_take_the_first_one_away() {
        let challenges = Challenges::default();
        let device = Uuid::now_v7();
        let first = challenges.issue(device);
        let second = challenges.issue(device);
        assert_ne!(first, second);
        assert_eq!(challenges.outstanding(device), vec![first.clone(), second]);
        assert!(challenges.spend(device, &first), "still good to answer");
    }

    #[test]
    fn a_device_holds_only_a_few_challenges() {
        let challenges = Challenges::default();
        let device = Uuid::now_v7();
        let oldest = challenges.issue(device);
        for _ in 0..CHALLENGES_PER_DEVICE {
            challenges.issue(device);
        }
        let outstanding = challenges.outstanding(device);
        assert_eq!(outstanding.len(), CHALLENGES_PER_DEVICE);
        assert!(!outstanding.contains(&oldest));
    }

    #[test]
    fn a_token_lasts_until_it_does_not() {
        let sessions = Sessions::default();
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let (token, expires) = sessions.issue(account, device, 60_000);
        assert!(expires > now_ms());
        assert_eq!(sessions.get(&token).unwrap().device_id, device);
        assert!(sessions.get("something else").is_none());

        let (expired, _) = sessions.issue(account, device, 0);
        assert!(sessions.get(&expired).is_none());
    }

    #[test]
    fn revoking_a_device_takes_its_tokens_with_it() {
        let sessions = Sessions::default();
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let other = Uuid::now_v7();
        let (mine, _) = sessions.issue(account, device, 60_000);
        let (theirs, _) = sessions.issue(account, other, 60_000);

        sessions.drop_device(device);
        assert!(sessions.get(&mine).is_none());
        assert!(sessions.get(&theirs).is_some(), "only that device");
    }
}
