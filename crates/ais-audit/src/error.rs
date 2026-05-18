//! Error types for AIS audit operations.

use thiserror::Error;

/// Errors returned by AIS audit operations.
///
/// All errors are fail-closed. Callers should treat any error as evidence that
/// the audit entry or chain is invalid.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// Canonical audit entry serialization failed.
    #[error("audit entry serialization failed")]
    SerializationFailed,

    /// The entry hash does not match its deterministic payload.
    #[error("audit entry hash mismatch")]
    EntryHashMismatch,

    /// The entry does not link to the current chain head.
    #[error("audit chain previous hash mismatch")]
    PreviousHashMismatch,
}
