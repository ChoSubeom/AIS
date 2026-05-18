//! POST /ais/v1/sessions — create a new AIS session.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use ais_session::{generate_integrity_key, Session, SessionId};

use crate::error::ProxyError;
use crate::state::{AppState, SessionEntry};

#[derive(Serialize)]
pub struct CreateSessionResponse {
    /// Hex-encoded 16-byte session identifier.
    pub session_id: String,
    /// Hex-encoded 32-byte integrity key the client must use for MAC computation.
    pub integrity_key: String,
}

/// Creates an active AIS session and returns its credentials.
///
/// The returned `integrity_key` is used by the client to compute the
/// `X-Ais-Integrity-Mac` header on subsequent `/v1/chat/completions` requests.
pub async fn create_session(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CreateSessionResponse>, ProxyError> {
    // TODO(AIS-MVP):
    // Replace unauthenticated session creation with authenticated
    // AIS handshake after AIS-Core protocol stabilizes.
    let id = SessionId::generate();
    let key = generate_integrity_key();

    let mut session = Session::new(id);
    session.activate();

    let session_id_hex = hex::encode(id.as_bytes());
    let integrity_key_hex = hex::encode(key);

    state
        .sessions
        .lock()
        .expect("session lock poisoned")
        .insert(
            *id.as_bytes(),
            SessionEntry {
                session,
                integrity_key: key,
            },
        );

    Ok(Json(CreateSessionResponse {
        session_id: session_id_hex,
        integrity_key: integrity_key_hex,
    }))
}
