//! The mailbox: take records, hand records back, and say when there is news.

use crate::auth::Authenticated;
use crate::connections::Holding;
use crate::db::{devices, records};
use crate::limits;
use crate::state::AppState;
use crate::{ApiError, Result};
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_core::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio_stream::wrappers::ReceiverStream;
use uwussh_proto::{PushRequest, PushResponse, MAX_BATCH, SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub since: u64,
    pub limit: Option<usize>,
    /// Set by clients that know manifests. One from before them fails to
    /// read a whole page with a record kind it has never heard of, so it
    /// gets none.
    /// Clients send `manifests=1`.
    #[serde(default)]
    pub manifests: u8,
}

/// Everything after a cursor. The device's own records come back too — it
/// costs one pass and lets a device check that what the server stored is what
/// it sent.
///
/// A page is up to 11 MiB, and it is held until the client has read it — so
/// it counts as one of the account's pulls until then, not only until it is
/// made.
pub async fn pull(
    auth: Authenticated,
    State(state): State<AppState>,
    Query(query): Query<PullQuery>,
) -> Result<Response> {
    state.limits.check_account(auth.account.id, &limits::PULL)?;
    let going = state.limits.start(auth.account.id, &limits::PULLS)?;
    let limit = query.limit.unwrap_or(MAX_BATCH).min(MAX_BATCH);
    let page = {
        let conn = state.db.lock();
        let page = records::pull(
            &conn,
            &auth.account,
            query.since,
            limit,
            query.manifests != 0,
        )?;
        // How far this device has read decides what the server may forget —
        // so never further than there is: a device with a cursor from another
        // server, or from before a restore, must not let tombstones go it
        // never saw.
        devices::seen(&conn, auth.device.id, page.cursor.0.min(auth.account.seq))?;
        page
    };
    Ok(Json(page)
        .into_response()
        .map(|body| Body::new(Holding::new(body, going))))
}

/// Offer records. Counted before the body is read: it may be 16 MiB.
pub async fn push(
    auth: Authenticated,
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<PushResponse>> {
    state.limits.check_account(auth.account.id, &limits::PUSH)?;
    let _going = state.limits.start(auth.account.id, &limits::PUSHES)?;
    let request: PushRequest = super::body(&state, request).await?;
    if request.schema != SCHEMA_VERSION {
        return Err(ApiError::Schema {
            found: request.schema,
            known: SCHEMA_VERSION,
        });
    }

    let response = {
        let mut conn = state.db.lock();
        records::push_within(
            &mut conn,
            &auth.account,
            auth.device.id,
            &request.envelopes,
            state.config.quota,
        )?
    };
    if !response.accepted.is_empty() {
        state.events.announce(auth.account.id, response.cursor.0);
    }
    Ok(Json(response))
}

/// How often an open event stream asks whether its token is still good.
const RECHECK: Duration = Duration::from_secs(30);

/// "There is something new from sequence N." Nothing else is ever pushed out:
/// the device pulls, the same way it would have anyway.
///
/// A stream lasts as long as the token it was opened with. Every half minute
/// it asks whether that token is still good, and ends when it is not — a
/// revoked device must not go on hearing when the account changes, and an
/// expired token is the device's cue to sign in again and reconnect.
pub async fn events(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let guard = state
        .events
        .open_stream(auth.device.id)
        .ok_or(ApiError::RateLimited)?;
    let mut receiver = state.events.subscribe(auth.account.id);
    let (sender, stream) = tokio::sync::mpsc::channel(16);
    let token = auth.token;
    let device = auth.device.id;
    let state = state.clone();

    tokio::spawn(async move {
        let _open = guard;
        let mut recheck = tokio::time::interval(RECHECK);
        recheck.tick().await;
        loop {
            tokio::select! {
                news = receiver.recv() => match news {
                    Ok(seq) => {
                        let event = Event::default().event("records").data(seq.to_string());
                        if sender.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                    // Missed a few: the next one says the same thing better.
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                },
                _ = recheck.tick() => {
                    if sender.is_closed() || !still_in(&state, &token, device) {
                        return;
                    }
                }
            }
        }
    });

    // A keep-alive every half minute, so a proxy in between does not decide
    // the connection is idle and drop it.
    Ok(Sse::new(ReceiverStream::new(stream)).keep_alive(KeepAlive::new().interval(RECHECK)))
}

/// Whether a stream's token is still good and its device still in. Both: a
/// device revoked from the command line is revoked by another process, whose
/// word reaches this one through the database and not through its tokens.
fn still_in(state: &AppState, token: &str, device: uuid::Uuid) -> bool {
    state.sessions.get(token).is_some()
        && matches!(devices::get(&state.db.lock(), device), Ok(Some(found)) if !found.revoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticate;
    use crate::db::{accounts, Db};
    use crate::Config;
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;

    /// A signed-in device and the headers it sends.
    fn signed_in(state: &AppState) -> (uuid::Uuid, HeaderMap) {
        let conn = state.db.lock();
        let account = accounts::create(&conn, &accounts::tests::header(), b"key").unwrap();
        let device = devices::add(&conn, account.id, "laptop", &[1; 32]).unwrap();
        drop(conn);
        let (token, _) = state.sessions.issue(account.id, device.id, 3_600_000);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        (device.id, headers)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_ends_once_its_device_is_shut_out() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (device, headers) = signed_in(&state);
        let auth = authenticate(&state, &headers).unwrap();
        let body = events(auth, State(state.clone()))
            .await
            .unwrap()
            .into_response()
            .into_body();

        state.sessions.drop_device(device);
        // Time runs on by itself here: the stream notices at its next look.
        let ended = tokio::time::timeout(RECHECK * 3, axum::body::to_bytes(body, usize::MAX)).await;
        assert!(ended.is_ok(), "the stream of a revoked device ends");
        assert!(
            state.events.open_stream(device).is_some(),
            "and its place is free again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_ends_when_its_device_is_revoked_from_elsewhere() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (device, headers) = signed_in(&state);
        let auth = authenticate(&state, &headers).unwrap();
        let account = auth.account.id;
        let body = events(auth, State(state.clone()))
            .await
            .unwrap()
            .into_response()
            .into_body();
        // As `uwusync-server revoke` does it: the database, and no token.
        devices::revoke(&state.db.lock(), account, device).unwrap();
        let ended = tokio::time::timeout(RECHECK * 3, axum::body::to_bytes(body, usize::MAX)).await;
        assert!(ended.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_with_a_good_token_stays_open() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (_, headers) = signed_in(&state);
        let auth = authenticate(&state, &headers).unwrap();
        let body = events(auth, State(state.clone()))
            .await
            .unwrap()
            .into_response()
            .into_body();
        let ended = tokio::time::timeout(RECHECK * 5, axum::body::to_bytes(body, usize::MAX)).await;
        assert!(ended.is_err(), "still open after several looks");
    }

    #[tokio::test]
    async fn a_page_counts_as_a_pull_until_it_has_been_read() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (_, headers) = signed_in(&state);
        let ask = || {
            let auth = authenticate(&state, &headers).unwrap();
            let query = PullQuery {
                since: 0,
                limit: None,
                manifests: 1,
            };
            pull(auth, State(state.clone()), Query(query))
        };

        // Answered, and never read: each one is still held.
        let mut unread = Vec::new();
        for _ in 0..limits::PULLS.max {
            unread.push(ask().await.unwrap().into_body());
        }
        assert!(matches!(ask().await, Err(ApiError::RateLimited)));

        // One read to its end makes room, and so does one given up on.
        axum::body::to_bytes(unread.pop().unwrap(), usize::MAX)
            .await
            .unwrap();
        let another = ask().await.unwrap();
        assert!(matches!(ask().await, Err(ApiError::RateLimited)));
        drop(another);
        assert!(ask().await.is_ok());
    }
}
