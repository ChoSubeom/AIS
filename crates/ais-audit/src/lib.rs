//! Minimal deterministic audit chain for AIS-Core.
//!
//! This crate intentionally implements only the AIS-Core MVP audit surface:
//!
//! - fixed-size audit identifiers
//! - minimal response statuses
//! - deterministic CBOR entry hashing
//! - append-only in-memory audit chains
//! - fail-closed chain validation

pub mod chain;
pub mod entry;
pub mod error;

pub use chain::AuditChain;
pub use entry::{
    compute_entry_hash, generate_audit_id, verify_entry_hash, AuditEntry, AuditHash, AuditId,
    ResponseStatus, AUDIT_HASH_LENGTH, AUDIT_ID_LENGTH, EMPTY_AUDIT_HASH,
};
pub use error::AuditError;
