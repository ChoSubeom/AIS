//! Secure random key generation.

use rand_core::{OsRng, RngCore};

use crate::signing::{PrivateKeyBytes, PRIVATE_KEY_LENGTH};

/// Generates secure random bytes using the operating system CSPRNG.
///
/// Key generation is intentionally the only non-deterministic operation in
/// this crate. All signing, verification, and hashing operations are
/// deterministic for fixed inputs.
///
/// If OS secure randomness is unavailable, this function terminates execution.
pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut rng = OsRng;

    rng.try_fill_bytes(&mut bytes)
        .expect("OS secure randomness unavailable");

    bytes
}

/// Generates a new Ed25519 private key using the operating system CSPRNG.
pub fn generate_private_key() -> PrivateKeyBytes {
    secure_random_bytes::<PRIVATE_KEY_LENGTH>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{public_key_from_private_key, sign, verify};

    #[test]
    fn generated_key_can_sign_and_verify() {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let signature = sign(&private_key, b"ais");

        verify(&public_key, b"ais", &signature).expect("generated key should verify");
    }
}
