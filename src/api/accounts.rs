//! Creating an account, and the vault header that belongs to it.
//!
//! The header — salt, key derivation costs, wrapped vault key — is what a
//! second device needs before it can turn a master password into keys. It is
//! not secret, but the wrapped key is only handed to a device that has proved
//! it knows the password, and the parameters alone are handed to a device that
//! is in the middle of joining. Those are two different endpoints on purpose.

use super::{auth_key, device_key, who, Admitted, Peer};
use crate::auth::Authenticated;
use crate::config::Registration;
use crate::db::accounts::{plausible, VaultHeader, VaultParams};
use crate::db::{accounts, devices, invites};
use crate::limits;
use crate::state::AppState;
use crate::{ApiError, Result};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;

pub use uwussh_proto::api::CreateAccount;

/// The first device of a new account.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Json(request): Json<CreateAccount>,
) -> Result<Json<Admitted>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::ACCOUNTS)?;

    if !plausible(&request.vault) {
        return Err(ApiError::Invalid(
            "a vault header no device could open".into(),
        ));
    }
    let key = auth_key(&request.auth_key)?;
    let device_key = device_key(&request.device)?;

    let conn = state.db.lock();
    match state.config.registration {
        Registration::Closed => return Err(ApiError::RegistrationClosed),
        Registration::Invite => {
            if !invites::redeem_invite(&conn, &request.invite)? {
                // An invite that is used, expired or made up: all the same
                // answer, so the code cannot be probed for.
                return Err(ApiError::Unauthorized);
            }
        }
        Registration::Open => {}
    }

    let account = accounts::create(&conn, &request.vault, &key)?;
    let device = devices::add(&conn, account.id, &request.device.name, &device_key)?;
    drop(conn);

    state.limits.forgive(&who, &limits::ACCOUNTS);
    let (token, expires_ms) =
        state
            .sessions
            .issue(account.id, device.id, state.config.session_secs * 1000);
    tracing::info!(account = %account.id, device = %device.id, name = %device.name, "account created");
    Ok(Json(Admitted {
        account_id: account.id,
        device_id: device.id,
        token,
        expires_ms,
    }))
}

/// The whole header, for a device that is in.
pub async fn vault(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Json<VaultHeader>> {
    let conn = state.db.lock();
    let header = accounts::header(&conn, auth.account.id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(header))
}

#[derive(Debug, Deserialize)]
pub struct ParamsQuery {
    /// The enrolment token the device is joining with.
    enrolment: String,
}

/// What a joining device needs *before* it can prove anything: the salt and
/// the costs, so it can turn the master password into the key it will prove
/// with. The wrapped vault key is not in here — that one is the reward for
/// proving it.
pub async fn vault_params(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Query(query): Query<ParamsQuery>,
) -> Result<Json<VaultParams>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::ENROL)?;

    let conn = state.db.lock();
    let account =
        invites::peek_enrolment(&conn, &query.enrolment)?.ok_or(ApiError::Unauthorized)?;
    let header = accounts::header(&conn, account)?.ok_or(ApiError::Unauthorized)?;
    Ok(Json(header.params()))
}

pub use uwussh_proto::api::ChangePassword;

/// A new master password: the vault key is wrapped again, the verifier
/// replaced, and not one record is touched.
pub async fn change_password(
    auth: Authenticated,
    State(state): State<AppState>,
    Json(request): Json<ChangePassword>,
) -> Result<StatusCode> {
    let current = auth_key(&request.current_auth_key)?;
    let next = auth_key(&request.auth_key)?;
    if !plausible(&request.vault) {
        return Err(ApiError::Invalid(
            "a vault header no device could open".into(),
        ));
    }
    let conn = state.db.lock();
    if !accounts::verify(&conn, auth.account.id, &current)? {
        return Err(ApiError::Unauthorized);
    }
    if request.vault.vault_id != auth.account.vault_id {
        // Changing the password does not change which vault this is. A header
        // for another vault would orphan every record in the account.
        return Err(ApiError::Invalid(
            "that header belongs to another vault".into(),
        ));
    }
    accounts::set_header(&conn, auth.account.id, &request.vault, &next)?;
    tracing::info!(account = %auth.account.id, "master password changed");
    Ok(StatusCode::NO_CONTENT)
}
