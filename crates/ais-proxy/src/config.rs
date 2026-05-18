//! Proxy configuration.

/// Minimal AIS proxy configuration.
///
/// Single backend URL only. No hot reload, no dynamic config.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// URL of the upstream AI backend (OpenAI-compatible).
    pub backend_url: String,
}
