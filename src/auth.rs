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

/// What a device signs. The label keeps this signature from being useful
/// anywhere else, and the ids tie it to one device of one account — a
/// signature made for one server cannot be replayed at another account.
pub fn signing_material(account: Uuid, device: Uuid, challenge: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(16 + 16 + 16 + challenge.len());
    material.extend_from_slice(b"uwussh/session/v1");
    material.extend_from_slice(account.as_bytes());
    material.extend_from_slice(device.as_bytes());
    material.extend_from_slice(challenge);
    material
}

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
type Outstanding = HashMap<Uuid, (Vec<u8>, u64)>;

/// One outstanding challenge per device.
#[derive(Clone, Default)]
pub struct Challenges {
    inner: Arc<Mutex<Outstanding>>,
}

impl Challenges {
    /// A fresh challenge, replacing whatever that device had before.
    pub fn issue(&self, device: Uuid) -> Vec<u8> {
        let challenge = random_bytes::<32>().to_vec();
        let mut inner = self.inner.lock();
        inner.retain(|_, (_, expires)| *expires > now_ms());
        inner.insert(device, (challenge.clone(), now_ms() + CHALLENGE_TTL_MS));
        challenge
    }

    /// Take the challenge back. It is gone either way, so a wrong answer costs
    /// a round trip rather than giving an attacker another try at the same one.
    pub fn take(&self, device: Uuid) -> Option<Vec<u8>> {
        let (challenge, expires) = self.inner.lock().remove(&device)?;
        (expires > now_ms()).then_some(challenge)
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
}

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let session = state
            .sessions
            .get(token.trim())
            .ok_or(ApiError::Unauthorized)?;
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
        Ok(Self { account, device })
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

        let material = signing_material(account, device, &challenge);
        let signature = signing.sign(&material).to_bytes();
        assert!(verify_signature(&public, &material, &signature));

        for other in [
            signing_material(Uuid::now_v7(), device, &challenge),
            signing_material(account, Uuid::now_v7(), &challenge),
            signing_material(account, device, &random_bytes::<32>()),
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
        assert_eq!(challenges.take(device), Some(challenge));
        assert_eq!(challenges.take(device), None, "used up");
    }

    #[test]
    fn asking_again_replaces_the_challenge() {
        let challenges = Challenges::default();
        let device = Uuid::now_v7();
        let first = challenges.issue(device);
        let second = challenges.issue(device);
        assert_ne!(first, second);
        assert_eq!(challenges.take(device), Some(second));
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
