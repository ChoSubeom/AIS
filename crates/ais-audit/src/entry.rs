//! Audit entry data and deterministic hashing.

use ais_crypto::{secure_random_bytes, sha3_256};
use serde::Serialize;

use crate::error::AuditError;

/// Audit identifier length in bytes.
pub const AUDIT_ID_LENGTH: usize = 16;

/// Audit chain hash length in bytes.
pub const AUDIT_HASH_LENGTH: usize = 32;

/// Empty audit chain hash.
pub const EMPTY_AUDIT_HASH: [u8; AUDIT_HASH_LENGTH] = [0u8; AUDIT_HASH_LENGTH];

/// Fixed-size audit entry identifier.
pub type AuditId = [u8; AUDIT_ID_LENGTH];

/// Fixed-size audit hash.
pub type AuditHash = [u8; AUDIT_HASH_LENGTH];

/// Minimal AIS-Core response status recorded in audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    /// Request completed successfully.
    Ok,
    /// Model attestation failed.
    AttestationFailed,
    /// Session was expired.
    SessionExpired,
    /// Session sequence validation failed.
    SequenceError,
    /// Internal processing error.
    InternalError,
}

impl ResponseStatus {
    fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::AttestationFailed => 1,
            Self::SessionExpired => 2,
            Self::SequenceError => 3,
            Self::InternalError => 4,
        }
    }
}

/// Minimal AIS-Core audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Fixed-size audit identifier.
    pub audit_id: AuditId,
    /// Caller-supplied timestamp.
    pub timestamp: u64,
    /// Fixed-size session identifier.
    pub session_id: [u8; 16],
    /// SHA3-256 hash of the request.
    pub request_hash: [u8; 32],
    /// Minimal response status.
    pub response_status: ResponseStatus,
    /// Previous audit entry hash.
    pub prev_hash: AuditHash,
    /// Deterministic hash of this audit entry.
    pub entry_hash: AuditHash,
}

#[derive(Serialize)]
struct EntryHashPayload<'a>(
    &'a [u8; 16],
    u64,
    &'a [u8; 16],
    &'a [u8; 32],
    u8,
    &'a [u8; 32],
);

impl AuditEntry {
    /// Creates a new audit entry and computes its deterministic entry hash.
    pub fn new(
        audit_id: AuditId,
        timestamp: u64,
        session_id: [u8; 16],
        request_hash: [u8; 32],
        response_status: ResponseStatus,
        prev_hash: AuditHash,
    ) -> Result<Self, AuditError> {
        let mut entry = Self {
            audit_id,
            timestamp,
            session_id,
            request_hash,
            response_status,
            prev_hash,
            entry_hash: [0u8; AUDIT_HASH_LENGTH],
        };
        entry.entry_hash = compute_entry_hash(&entry)?;
        Ok(entry)
    }
}

/// Generates a secure random fixed-size audit identifier.
pub fn generate_audit_id() -> AuditId {
    secure_random_bytes::<AUDIT_ID_LENGTH>()
}

/// Computes an audit entry hash from deterministic canonical CBOR bytes.
///
/// The hash covers `audit_id`, `timestamp`, `session_id`, `request_hash`,
/// `response_status`, and `prev_hash`, in that exact order. It does not cover
/// `entry_hash`.
pub fn compute_entry_hash(entry: &AuditEntry) -> Result<AuditHash, AuditError> {
    let payload = EntryHashPayload(
        &entry.audit_id,
        entry.timestamp,
        &entry.session_id,
        &entry.request_hash,
        entry.response_status.code(),
        &entry.prev_hash,
    );

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded)
        .map_err(|_| AuditError::SerializationFailed)?;

    Ok(sha3_256(&encoded))
}

/// Verifies that an entry hash matches its deterministic payload.
pub fn verify_entry_hash(entry: &AuditEntry) -> Result<(), AuditError> {
    if compute_entry_hash(entry)? == entry.entry_hash {
        Ok(())
    } else {
        Err(AuditError::EntryHashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(prev_hash: AuditHash) -> AuditEntry {
        AuditEntry::new(
            [1u8; 16],
            1_700_000_000,
            [2u8; 16],
            sha3_256(b"request"),
            ResponseStatus::Ok,
            prev_hash,
        )
        .expect("entry should build")
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let first = test_entry(EMPTY_AUDIT_HASH);
        let second = test_entry(EMPTY_AUDIT_HASH);

        assert_eq!(first.entry_hash, second.entry_hash);
    }

    #[test]
    fn entry_hash_excludes_entry_hash_field() {
        let mut first = test_entry(EMPTY_AUDIT_HASH);
        let mut second = first.clone();
        first.entry_hash = [1u8; 32];
        second.entry_hash = [2u8; 32];

        assert_eq!(
            compute_entry_hash(&first).expect("entry should hash"),
            compute_entry_hash(&second).expect("entry should hash")
        );
    }

    #[test]
    fn entry_hash_changes_with_status() {
        let first = test_entry(EMPTY_AUDIT_HASH);
        let second = AuditEntry::new(
            [1u8; 16],
            1_700_000_000,
            [2u8; 16],
            sha3_256(b"request"),
            ResponseStatus::InternalError,
            EMPTY_AUDIT_HASH,
        )
        .expect("entry should build");

        assert_ne!(first.entry_hash, second.entry_hash);
    }

    #[test]
    fn verify_entry_hash_rejects_tampering() {
        let mut entry = test_entry(EMPTY_AUDIT_HASH);
        entry.timestamp += 1;

        assert_eq!(
            verify_entry_hash(&entry),
            Err(AuditError::EntryHashMismatch)
        );
    }
}
