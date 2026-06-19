//! Error type for tool-integrity operations.

use thiserror::Error;

/// Errors raised while pinning or verifying MCP tool definitions.
#[derive(Debug, Error)]
pub enum ToolIntegrityError {
    /// Input was neither a `tools/list` response nor a bare tool array.
    #[error("input is not a tools/list response or a tool array")]
    InvalidInput,

    /// A tool entry had no string `name` field.
    #[error("tool entry is missing a string `name`")]
    MissingName,

    /// Two tools shared the same name, which would let one shadow the other.
    #[error("duplicate tool name: {0}")]
    DuplicateName(String),

    /// Underlying JSON serialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
