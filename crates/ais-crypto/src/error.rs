//! Error types for AIS cryptographic operations.

use thiserror::Error;

/// Errors returned by AIS cryptographic operations.
///
/// Verification errors are intentionally opaque so callers can fail closed
/// without relying on detailed parsing or signature failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A public key did not have a valid Ed25519 encoding.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,

    /// Ed25519 signature verification failed.
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}
