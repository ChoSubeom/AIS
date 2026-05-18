//! Minimal deterministic authenticated session framing for AIS-Core.
//!
//! This crate intentionally implements only the AIS-Core MVP session surface:
//!
//! - fixed-size session identifiers
//! - explicit session state
//! - monotonic sequence counters
//! - secure random nonces
//! - deterministic CBOR frame serialization
//! - SHA3-256 based frame integrity verification

pub mod error;
pub mod frame;
pub mod session;
pub mod validation;

pub use error::SessionError;
pub use frame::{
    compute_integrity_mac, create_frame, serialize_frame, verify_frame_integrity, AISFrame,
    IntegrityKey,
};
pub use session::{
    generate_integrity_key, generate_nonce, SequenceCounter, Session, SessionId, SessionState,
    AIS_SESSION_VERSION, INTEGRITY_KEY_LENGTH, NONCE_LENGTH, SESSION_ID_LENGTH,
};
pub use validation::{validate_frame, validate_session};
