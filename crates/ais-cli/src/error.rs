//! CLI error types.

use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by the AIS CLI.
#[derive(Debug, Error)]
pub enum CliError {
    /// File read failed.
    #[error("failed to read {path}: {source}")]
    ReadFile {
        /// File path.
        path: PathBuf,
        /// IO source error.
        source: std::io::Error,
    },

    /// File write failed.
    #[error("failed to write {path}: {source}")]
    WriteFile {
        /// File path.
        path: PathBuf,
        /// IO source error.
        source: std::io::Error,
    },

    /// Key file was not exactly 32 bytes.
    #[error("issuer key must be exactly 32 bytes")]
    InvalidIssuerKey,

    /// CBOR serialization failed.
    #[error("CBOR serialization failed")]
    SerializationFailed,

    /// CBOR deserialization failed.
    #[error("CBOR deserialization failed")]
    DeserializationFailed,

    /// Encoded bytes had an invalid length.
    #[error("invalid encoded byte length for {field}")]
    InvalidLength {
        /// Field name.
        field: &'static str,
    },

    /// Encoded response status was unknown.
    #[error("invalid response status")]
    InvalidResponseStatus,

    /// Certificate operation failed.
    #[error(transparent)]
    Certificate(#[from] ais_cert::CertificateError),

    /// Audit operation failed.
    #[error(transparent)]
    Audit(#[from] ais_audit::AuditError),
}
