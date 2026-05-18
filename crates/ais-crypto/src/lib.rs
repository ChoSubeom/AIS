//! Minimal cryptographic foundation for AIS-Core.
//!
//! This crate intentionally exposes a small API:
//!
//! - SHA3-256 hashing
//! - Ed25519 key generation
//! - Ed25519 signing
//! - Ed25519 signature verification
//!
//! Verification functions fail closed: every verification error is returned as
//! `Err`, and callers should reject the object being checked.

pub mod error;
pub mod hash;
pub mod random;
pub mod signing;

pub use error::CryptoError;
pub use hash::{sha3_256, Sha3Hash, SHA3_256_LENGTH};
pub use random::{generate_private_key, secure_random_bytes};
pub use signing::{
    public_key_from_private_key, sign, verify, PrivateKeyBytes, PublicKeyBytes, SignatureBytes,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
