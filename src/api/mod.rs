//! The HTTP surface. Not one endpoint on it can read a record.

pub mod accounts;
pub mod devices;
pub mod pairing;
pub mod records;
pub mod session;

use crate::state::{client_key, AppState};
use crate::{b64, ApiError, Result};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// The largest request the server reads at all. A full batch of records is far
/// below this; anything above is either a mistake or someone filling the disk.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/accounts", post(accounts::create))
        .route("/v1/vault", get(accounts::vault))
        .route("/v1/vault/params", get(accounts::vault_params))
        .route("/v1/vault/key", put(accounts::change_password))
        .route("/v1/session/challenge", post(session::challenge))
        .route("/v1/session", post(session::login))
        .route("/v1/records", get(records::pull).post(records::push))
        .route("/v1/events", get(records::events))
        .route("/v1/devices", get(devices::list))
        .route("/v1/devices/invite", post(devices::invite))
        .route("/v1/devices/enrol", post(devices::enrol))
        .route("/v1/devices/{id}", delete(devices::revoke))
        .route("/v1/pair", post(pairing::open))
        .route(
            "/v1/pair/{id}",
            get(pairing::read)
                .post(pairing::post)
                .delete(pairing::close),
        )
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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
