//! Axum router wiring.

use std::sync::Arc;

use axum::{routing::post, Router};

use crate::chat_handler::chat_completions;
use crate::session_handler::create_session;
use crate::state::AppState;

/// Builds the AIS proxy router with all routes mounted.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ais/v1/sessions", post(create_session))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state)
}
