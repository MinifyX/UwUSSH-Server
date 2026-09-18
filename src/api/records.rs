//! The mailbox: take records, hand records back, and say when there is news.

use crate::auth::Authenticated;
use crate::db::{devices, records};
use crate::state::AppState;
use crate::{ApiError, Result};
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use futures_core::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uwussh_proto::{PullResponse, PushRequest, PushResponse, MAX_BATCH, SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub since: u64,
    pub limit: Option<usize>,
}

/// Everything after a cursor. The device's own records come back too — it
/// costs one pass and lets a device check that what the server stored is what
/// it sent.
pub async fn pull(
    auth: Authenticated,
    State(state): State<AppState>,
    Query(query): Query<PullQuery>,
) -> Result<Json<PullResponse>> {
    let limit = query.limit.unwrap_or(MAX_BATCH).min(MAX_BATCH);
    let conn = state.db.lock();
    let page = records::pull(&conn, &auth.account, query.since, limit)?;
    // How far this device has read decides what the server may forget.
    devices::seen(&conn, auth.device.id, page.cursor.0)?;
    Ok(Json(page))
}

/// Offer records.
pub async fn push(
    auth: Authenticated,
    State(state): State<AppState>,
    Json(request): Json<PushRequest>,
) -> Result<Json<PushResponse>> {
    if request.schema != SCHEMA_VERSION {
        return Err(ApiError::Schema {
            found: request.schema,
            known: SCHEMA_VERSION,
        });
    }

    let response = {
        let mut conn = state.db.lock();
        records::push(&mut conn, &auth.account, auth.device.id, &request.envelopes)?
    };
    if !response.accepted.is_empty() {
        state.events.announce(auth.account.id, response.cursor.0);
    }
    Ok(Json(response))
}

/// "There is something new from sequence N." Nothing else is ever pushed out:
/// the device pulls, the same way it would have anyway.
pub async fn events(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    let receiver = state.events.subscribe(auth.account.id);
    let stream = BroadcastStream::new(receiver).filter_map(|seq| {
        let seq = seq.ok()?;
        Some(Ok(Event::default().event("records").data(seq.to_string())))
    });
    // A keep-alive every half minute, so a proxy in between does not decide
    // the connection is idle and drop it.
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
}
