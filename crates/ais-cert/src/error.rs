//! Error types for AIS certificate operations.

use thiserror::Error;

/// Errors returned by AIS certificate operations.
///
/// Verification errors are intentionally small and fail-closed. Callers should
/// reject the certificate on every error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CertificateError {
    /// Certificate payload serialization failed.
    #[error("certificate serialization failed")]
    SerializationFailed,

    /// The certificate signature did not verify.
    #[error("certificate signature verification failed")]
    SignatureVerificationFailed,

    /// The supplied model bytes do not match the certificate model hash.
    #[error("certificate model hash mismatch")]
    ModelHashMismatch,
}
