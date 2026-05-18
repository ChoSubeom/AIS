//! Shared proxy state: in-memory session store and audit chain.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ais_audit::AuditChain;
use ais_session::{IntegrityKey, Session};

use crate::config::ProxyConfig;

/// A single in-memory session entry.
pub struct SessionEntry {
    pub session: Session,
    pub integrity_key: IntegrityKey,
}

/// Shared proxy state accessible from all route handlers.
pub struct AppState {
    pub config: ProxyConfig,
    /// In-memory session store keyed by raw session-id bytes.
    pub sessions: Mutex<HashMap<[u8; 16], SessionEntry>>,
    /// Append-only in-memory audit chain.
    pub audit_chain: Mutex<AuditChain>,
    /// Reusable reqwest client for backend forwarding.
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config: ProxyConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            sessions: Mutex::new(HashMap::new()),
            audit_chain: Mutex::new(AuditChain::new()),
            client: reqwest::Client::new(),
        })
    }
}
