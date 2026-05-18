//! Error types for AIS session operations.

use thiserror::Error;

/// Errors returned by AIS session operations.
///
/// All validation errors are fail-closed. Callers should reject the frame or
/// session operation on every error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Canonical frame serialization failed.
    #[error("session frame serialization failed")]
    SerializationFailed,

    /// The sequence counter reached `u64::MAX`.
    #[error("session sequence counter overflow")]
    SequenceOverflow,

    /// The frame sequence did not match the expected sequence.
    #[error("invalid session frame sequence")]
    InvalidSequence,

    /// The frame belongs to a different session.
    #[error("invalid session identifier")]
    InvalidSessionId,

    /// The session is not active.
    #[error("session is not active")]
    SessionNotActive,

    /// The frame integrity MAC did not verify.
    #[error("session frame integrity verification failed")]
    IntegrityVerificationFailed,
}
