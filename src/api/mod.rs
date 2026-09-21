//! The HTTP surface. Not one endpoint on it can read a record.

pub mod accounts;
pub mod devices;
pub mod pairing;
pub mod records;
pub mod session;

use crate::auth::Authenticated;
use crate::db;
use crate::limits;
use crate::state::{client_key, AppState};
use crate::{b64, ApiError, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// The largest request the server reads at all: a push of records. The
/// client stops a batch at 8 MiB of sealed bytes, which is under 11 MiB as
/// JSON; anything above this is a mistake or someone filling the disk.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Everything else: a vault header, a device key, a pairing message. Read in
/// full before anything is checked, so it is kept small — most of these
/// requests come from nobody the server knows yet.
pub const SMALL_BODY_BYTES: usize = 64 * 1024;

/// How long any request may take, from the first byte to the last. Long
/// enough for a full push over a slow uplink; short enough that a connection
/// trickling its body in cannot hold on for ever. The event stream is the one
/// request exempt from it.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/accounts", post(accounts::create))
        .route("/v1/vault", get(accounts::vault))
        .route("/v1/vault/params", post(accounts::vault_params))
        .route("/v1/vault/key", put(accounts::change_password))
        .route("/v1/session/challenge", post(session::challenge))
        .route("/v1/session", post(session::login))
        .route(
            "/v1/records",
            get(records::pull)
                .post(records::push)
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .route("/v1/devices", get(devices::list))
        .route("/v1/devices/invite", post(devices::invite))
        .route("/v1/devices/enrol", post(devices::enrol))
        .route("/v1/devices/{id}/revoke", post(devices::revoke))
        .route("/v1/pair", post(pairing::open))
        .route(
            "/v1/pair/{id}",
            get(pairing::read)
                .post(pairing::post)
                .delete(pairing::close),
        )
        // Only the routes above have a deadline: a layer reaches the routes
        // that are there when it is added.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .route("/v1/events", get(records::events))
        .layer(DefaultBodyLimit::max(SMALL_BODY_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// The master password, proved by a device that is signed in — for a password
/// change, or for revoking another device. Counted per device: from a device
/// that is signed in already, a wrong proof is either a typo or somebody with
/// that device guessing — and that somebody must not use up the tries of the
/// owner's other devices, or the owner could never revoke them.
pub fn prove_password(state: &AppState, auth: &Authenticated, key: &[u8]) -> Result<()> {
    state.limits.check_device(auth.device.id, &limits::PROOF)?;
    let right = db::accounts::verify(&state.db.lock(), auth.account.id, key)?;
    if !right {
        tracing::warn!(
            account = %auth.account.id, device = %auth.device.id,
            "a wrong master password from a signed-in device"
        );
        return Err(ApiError::WrongPassword);
    }
    state.limits.forgive_device(auth.device.id, &limits::PROOF);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Health {
    ok: bool,
    schema: u32,
}

/// Enough for a container health check and no more: whether it is alive and
/// what it speaks. Never how many accounts it has.
async fn health() -> Json<Health> {
    Json(Health {
        ok: true,
        schema: uwussh_proto::SCHEMA_VERSION,
    })
}

/// A device as it enrols, and what it gets when it is let in — both from the
/// protocol crate, so the client cannot spell a field differently.
pub use uwussh_proto::api::{Admitted, NewDevice};

/// The device key out of what arrived, or a refusal.
pub fn device_key(device: &NewDevice) -> Result<[u8; 32]> {
    b64::decode(&device.public_key)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| ApiError::Invalid("a device key must be 32 bytes".into()))
}

/// The key a device proves the master password with, decoded.
pub fn auth_key(encoded: &str) -> Result<Vec<u8>> {
    let key = b64::decode(encoded).ok_or_else(|| ApiError::Invalid("a login key".into()))?;
    // It is a 32-byte key derived from the password and the account key.
    // Anything else is a client that is doing something else.
    if key.len() != 32 {
        return Err(ApiError::Invalid("a login key must be 32 bytes".into()));
    }
    Ok(key)
}

/// The address a request came from, if the server was started in a way that
/// knows one — an extractor of its own rather than an optional `ConnectInfo`,
/// so a handler works either way instead of failing to compile.
pub struct Peer(pub Option<SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(Peer(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0),
        ))
    }
}

/// Who is knocking, for the rate limiter.
pub fn who(state: &AppState, headers: &HeaderMap, peer: Peer) -> String {
    client_key(&state.config, headers, peer.0)
}
