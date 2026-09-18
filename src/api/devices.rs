//! Devices: list them, let one in, shut one out.
//!
//! Joining is two secrets, not one. The **enrolment token** comes from a device
//! that is already in, through a channel this server cannot read — so the
//! server knows the join was approved. The **login key** comes from the master
//! password — so the server knows the person approving it is the owner. Either
//! one alone gets nowhere, which is what makes an intercepted pairing code
//! worthless.

use super::{auth_key, device_key, who, Admitted, Peer};
use crate::auth::Authenticated;
use crate::db::{accounts, devices, invites};
use crate::limits;
use crate::state::AppState;
use crate::{ApiError, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;
use uwussh_proto::api::DeviceSummary;

pub async fn list(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceSummary>>> {
    let conn = state.db.lock();
    Ok(Json(devices::list(&conn, auth.account.id)?))
}

pub use uwussh_proto::api::{EnrolDevice as EnrolRequest, EnrolmentToken as Enrolment};

/// A one-time token for a device about to join, made by a device that is
/// already in. It travels to the new device through the pairing channel, never
/// through this server in the clear.
pub async fn invite(auth: Authenticated, State(state): State<AppState>) -> Result<Json<Enrolment>> {
    let conn = state.db.lock();
    let token = invites::create_enrolment(&conn, auth.account.id)?;
    tracing::info!(account = %auth.account.id, "an enrolment token was made");
    Ok(Json(Enrolment {
        token,
        expires_ms: crate::now_ms() + invites::ENROLMENT_TTL_MS,
    }))
}

pub async fn enrol(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Json(request): Json<EnrolRequest>,
) -> Result<Json<Admitted>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::ENROL)?;

    let key = auth_key(&request.auth_key)?;
    let device_key = device_key(&request.device)?;

    let conn = state.db.lock();
    // Look first, spend later: a wrong password must not use up the token the
    // other device just showed on its screen.
    let account =
        invites::peek_enrolment(&conn, &request.enrolment)?.ok_or(ApiError::Unauthorized)?;
    if !accounts::verify(&conn, account, &key)? {
        tracing::warn!(%account, "a join with the wrong master password");
        return Err(ApiError::Unauthorized);
    }
    if invites::redeem_enrolment(&conn, &request.enrolment)?.is_none() {
        return Err(ApiError::Unauthorized);
    }
    let device = devices::add(&conn, account, &request.device.name, &device_key)?;
    drop(conn);

    state.limits.forgive(&who, &limits::ENROL);
    let (token, expires_ms) =
        state
            .sessions
            .issue(account, device.id, state.config.session_secs * 1000);
    tracing::info!(%account, device = %device.id, name = %device.name, "a device joined");
    Ok(Json(Admitted {
        account_id: account,
        device_id: device.id,
        token,
        expires_ms,
    }))
}

/// Shut a device out. It stops syncing at once — its tokens go with it — but
/// what it already holds, it holds: the client says so when you do this.
pub async fn revoke(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let conn = state.db.lock();
    if devices::live_count(&conn, auth.account.id)? <= 1 {
        // An account with no device left is an account nobody can reach, and
        // the records in it would be unreachable rather than gone.
        return Err(ApiError::Invalid(
            "this is the only device left; add another one first".into(),
        ));
    }
    if !devices::revoke(&conn, auth.account.id, id)? {
        return Err(ApiError::NotFound);
    }
    drop(conn);

    state.sessions.drop_device(id);
    tracing::info!(account = %auth.account.id, device = %id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}
