//! Signing in as a device: ask for a challenge, sign it, get a token.
//!
//! The server never learns anything it could be robbed of. The device's key
//! stays on the device, the challenge is used once, and the token lives in
//! memory for an hour.

use super::{who, Peer};
use crate::auth::{session_material, verify_signature};
use crate::db::devices;
use crate::limits;
use crate::state::AppState;
use crate::{b64, random_bytes, ApiError, Result};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;

pub use uwussh_proto::api::{ChallengeRequest, ChallengeResponse, LoginRequest, LoginResponse};

/// Something to sign.
///
/// A device this server has never heard of gets a challenge too — one that
/// leads nowhere. Answering "no such device" would turn this endpoint into a
/// way to find out which device ids exist.
pub async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::SESSION)?;

    let known = {
        let conn = state.db.lock();
        devices::get(&conn, request.device_id)?.is_some_and(|device| !device.revoked)
    };
    let challenge = if known {
        state.challenges.issue(request.device_id)
    } else {
        random_bytes::<32>().to_vec()
    };
    Ok(Json(ChallengeResponse {
        challenge: b64::encode(challenge),
    }))
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::SESSION)?;

    let signature = b64::decode(&request.signature).ok_or(ApiError::Unauthorized)?;
    let device = {
        let conn = state.db.lock();
        devices::get(&conn, request.device_id)?
    };
    let device = device
        .filter(|device| !device.revoked)
        .ok_or(ApiError::Unauthorized)?;

    // Whichever of its challenges the device answered. A wrong answer leaves
    // them where they are — nobody forges an Ed25519 signature by trying
    // again — so asking in its name cannot keep a device from signing in.
    let answered = state
        .challenges
        .outstanding(device.id)
        .into_iter()
        .find(|challenge| {
            let material = session_material(device.account_id, device.id, challenge);
            verify_signature(&device.public_key, &material, &signature)
        });
    // Spent here and only once: two requests racing with the same signature
    // find the challenge there for one of them.
    let Some(_) = answered.filter(|challenge| state.challenges.spend(device.id, challenge)) else {
        tracing::warn!(device = %device.id, "a signature that did not check out");
        return Err(ApiError::Unauthorized);
    };

    state.limits.forgive(&who, &limits::SESSION);
    let (token, expires_ms) = state.sessions.issue(
        device.account_id,
        device.id,
        state.config.session_secs * 1000,
    );
    {
        let conn = state.db.lock();
        devices::seen(&conn, device.id, device.cursor)?;
    }
    Ok(Json(LoginResponse {
        account_id: device.account_id,
        token,
        expires_ms,
    }))
}
