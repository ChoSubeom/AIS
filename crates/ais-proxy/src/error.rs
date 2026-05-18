//! Proxy error type with fail-closed HTTP responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// All errors produced by the AIS proxy.
///
/// Every security-sensitive error maps to a rejection response. The proxy
/// never silently recovers from session or integrity failures.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("session not found")]
    SessionNotFound,

    #[error("session validation failed")]
    InvalidSession,

    #[error("frame integrity MAC verification failed")]
    InvalidMac,

    #[error("sequence replay or out-of-order frame")]
    SequenceError,

    #[error("malformed request: {0}")]
    MalformedRequest(String),

    #[error("backend communication failed")]
    BackendError,

    #[error("internal proxy error")]
    InternalError,
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::SessionNotFound
            | Self::InvalidSession
            | Self::InvalidMac
            | Self::SequenceError => StatusCode::UNAUTHORIZED,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::BackendError => StatusCode::BAD_GATEWAY,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = serde_json::json!({ "error": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}

impl From<ais_session::SessionError> for ProxyError {
    fn from(err: ais_session::SessionError) -> Self {
        use ais_session::SessionError;
        match err {
            SessionError::InvalidSequence | SessionError::SequenceOverflow => Self::SequenceError,
            SessionError::IntegrityVerificationFailed => Self::InvalidMac,
            SessionError::SessionNotActive | SessionError::InvalidSessionId => Self::InvalidSession,
            SessionError::SerializationFailed => Self::InternalError,
        }
    }
}
