//! Minimal deterministic OpenAI-compatible AIS proxy.
//!
//! Request flow:
//!   client request
//!   → AIS session validation (fail-closed)
//!   → forward to backend
//!   → append audit entry
//!   → return response

pub mod chat_handler;
pub mod config;
pub mod error;
pub mod router;
pub mod session_handler;
pub mod state;

pub use config::ProxyConfig;
pub use router::build_router;
pub use state::AppState;
