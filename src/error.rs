//! What goes wrong, and what the client is told about it.
//!
//! Two rules. The body carries a short machine-readable `error` and a sentence
//! for a log, never a stack trace and never anything about another account. And
//! nothing here distinguishes "no such account" from "wrong credential": a
//! server that answers differently is a server that answers questions nobody
//! asked.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Invalid(String),
    #[error("not allowed")]
    Unauthorized,
    #[error("registration is closed on this server")]
    RegistrationClosed,
    /// A proof of the master password that did not check out, from a device
    /// that is signed in. Not 401: that means "sign in again", and a device
    /// would do exactly that and ask a second time.
    #[error("that is not the master password")]
    WrongPassword,
    #[error("this server has as many accounts as it takes")]
    ServerFull,
    #[error("no such thing")]
    NotFound,
    #[error("too large: {0}")]
    TooLarge(String),
    #[error("too many requests, try again later")]
    RateLimited,
    #[error("this server speaks schema {known}, not {found}")]
    Schema { found: u32, known: u32 },
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("{0}")]
    Internal(String),
}

#[derive(Serialize)]
struct Body {
    error: &'static str,
    message: String,
}

impl ApiError {
    fn code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::RegistrationClosed => (StatusCode::FORBIDDEN, "registration-closed"),
            Self::WrongPassword => (StatusCode::FORBIDDEN, "wrong-password"),
            Self::ServerFull => (StatusCode::FORBIDDEN, "server-full"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not-found"),
            Self::TooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "too-large"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate-limited"),
            Self::Schema { .. } => (StatusCode::BAD_REQUEST, "schema"),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = self.code();
        // What went wrong inside stays inside: it goes to the log, and the
        // client gets the kind of error, not the detail.
        let message = match &self {
            Self::Database(inner) => {
                tracing::error!(%inner, "database error");
                "something went wrong".to_string()
            }
            Self::Internal(inner) => {
                tracing::error!(%inner, "internal error");
                "something went wrong".to_string()
            }
            other => other.to_string(),
        };
        (status, Json(Body { error, message })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_internal_reaches_the_client() {
        let error = ApiError::Database(rusqlite::Error::QueryReturnedNoRows);
        let (status, code) = error.code();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, "internal");
    }

    #[test]
    fn a_wrong_credential_and_a_missing_account_look_the_same() {
        // Both paths end in `Unauthorized`; there is no variant that says
        // "this account exists, the secret was wrong".
        let (status, code) = ApiError::Unauthorized.code();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code, "unauthorized");
    }
}
