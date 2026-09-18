//! Carrying messages between two devices that are pairing.
//!
//! The server takes no part. It does not know the code, cannot derive the key
//! the two sides agree on, and never sees what they send through it — which is
//! the whole point: what travels here is the account key, and the account key
//! is what makes a copy of this server's database worthless.

use super::{who, Peer};
use crate::auth::Authenticated;
use crate::limits;
use crate::pairing::{self, Side};
use crate::state::AppState;
use crate::{b64, ApiError, Result};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use std::time::Duration;

pub use uwussh_proto::api::{
    PairMessage as PostMessage, PairMessages as Messages, PairOpened as Opened,
};

/// A device that is already in opens the session.
pub async fn open(auth: Authenticated, State(state): State<AppState>) -> Result<Json<Opened>> {
    let id = state.pairings.open(auth.account.id);
    tracing::info!(account = %auth.account.id, "a pairing session was opened");
    Ok(Json(Opened {
        id,
        expires_ms: crate::now_ms() + pairing::TTL_MS,
    }))
}

/// Leave a message for the other side. Not authenticated: the device that is
/// joining has no account yet, and what protects this is the handshake, not a
/// token.
pub async fn post(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    Json(request): Json<PostMessage>,
) -> Result<StatusCode> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::PAIR)?;

    let side = Side::parse(&request.side).ok_or_else(|| ApiError::Invalid("a side".into()))?;
    let message =
        b64::decode(&request.message).ok_or_else(|| ApiError::Invalid("a message".into()))?;
    state.pairings.post(&id, side, message)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadQuery {
    pub side: String,
    /// How many of the other side's messages this device has already seen.
    #[serde(default)]
    pub after: usize,
    /// Wait for something to arrive rather than answering empty at once.
    #[serde(default)]
    pub wait: bool,
}

/// What the other side has said. With `wait=true` this holds the request open
/// for a few seconds rather than answering nothing — a handshake that takes
/// two seconds should not cost two hundred requests.
pub async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Result<Json<Messages>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::PAIR)?;

    let side = Side::parse(&query.side).ok_or_else(|| ApiError::Invalid("a side".into()))?;
    let mut messages = state.pairings.read(&id, side, query.after)?;

    if messages.is_empty() && query.wait {
        let waiter = state.pairings.waiter(&id)?;
        // A timeout is not a failure: the device asks again, and a session
        // that ended in the meantime answers "not found" then.
        let _ =
            tokio::time::timeout(Duration::from_secs(pairing::POLL_SECS), waiter.notified()).await;
        messages = state.pairings.read(&id, side, query.after)?;
    }

    Ok(Json(Messages {
        next: query.after + messages.len(),
        messages: messages.iter().map(b64::encode).collect(),
    }))
}

/// Finished, or given up. Only the account that opened it may say so.
pub async fn close(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    if state.pairings.account_of(&id)? != auth.account.id {
        return Err(ApiError::NotFound);
    }
    state.pairings.close(&id);
    Ok(StatusCode::NO_CONTENT)
}
