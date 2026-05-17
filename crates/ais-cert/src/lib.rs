//! Minimal deterministic AI Certificate support for AIS-Core.
//!
//! This crate intentionally implements only the AIS-Core MVP certificate
//! surface:
//!
//! - model identity data
//! - AI certificate data
//! - deterministic certificate signing
//! - fail-closed certificate verification

pub mod certificate;
pub mod error;
pub mod verification;

pub use certificate::{sign_certificate, AICertificate, ModelIdentity, AIS_CERTIFICATE_VERSION};
pub use error::CertificateError;
pub use verification::verify_certificate;
