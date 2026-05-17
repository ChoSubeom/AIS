//! Ed25519 signing and verification helpers.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::CryptoError;

/// Ed25519 private key length in bytes.
pub const PRIVATE_KEY_LENGTH: usize = 32;

/// Ed25519 public key length in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Ed25519 signature length in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// Raw Ed25519 private key bytes.
pub type PrivateKeyBytes = [u8; PRIVATE_KEY_LENGTH];

/// Raw Ed25519 public key bytes.
pub type PublicKeyBytes = [u8; PUBLIC_KEY_LENGTH];

/// Raw Ed25519 signature bytes.
pub type SignatureBytes = [u8; SIGNATURE_LENGTH];

/// Derives an Ed25519 public key from a private key.
///
/// The private key is expected to be a 32-byte Ed25519 seed.
///
/// # Examples
///
/// ```
/// let private_key = ais_crypto::generate_private_key();
/// let public_key = ais_crypto::public_key_from_private_key(&private_key);
/// assert_eq!(public_key.len(), 32);
/// ```
pub fn public_key_from_private_key(private_key: &PrivateKeyBytes) -> PublicKeyBytes {
    let signing_key = SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}

/// Signs `message` with an Ed25519 private key.
///
/// Ed25519 signing is deterministic for a fixed private key and message.
pub fn sign(private_key: &PrivateKeyBytes, message: &[u8]) -> SignatureBytes {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);

    signature.to_bytes()
}

/// Verifies an Ed25519 signature over `message`.
///
/// Any malformed public key or signature mismatch returns an error. Callers
/// should reject the verified object on every error.
pub fn verify(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::generate_private_key;

    #[test]
    fn signature_verifies() {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let signature = sign(&private_key, b"model bytes");

        verify(&public_key, b"model bytes", &signature).expect("signature should verify");
    }

    #[test]
    fn signing_is_deterministic_for_same_key_and_message() {
        let private_key = [7u8; PRIVATE_KEY_LENGTH];

        let first = sign(&private_key, b"model bytes");
        let second = sign(&private_key, b"model bytes");

        assert_eq!(first, second);
    }

    #[test]
    fn verification_fails_for_changed_message() {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let signature = sign(&private_key, b"model bytes");

        let result = verify(&public_key, b"changed bytes", &signature);

        assert_eq!(result, Err(CryptoError::VerificationFailed));
    }

    #[test]
    fn verification_fails_for_changed_signature() {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let mut signature = sign(&private_key, b"model bytes");
        signature[0] ^= 1;

        let result = verify(&public_key, b"model bytes", &signature);

        assert!(result.is_err());
    }

    #[test]
    fn verification_fails_for_wrong_public_key() {
        let private_key = generate_private_key();
        let signature = sign(&private_key, b"model bytes");
        let public_key = [255u8; PUBLIC_KEY_LENGTH];

        let result = verify(&public_key, b"model bytes", &signature);

        assert_eq!(result, Err(CryptoError::VerificationFailed));
    }
}
