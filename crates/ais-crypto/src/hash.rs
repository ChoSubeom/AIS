//! SHA3-256 hashing helpers.

use sha3::{Digest, Sha3_256};

/// SHA3-256 digest length in bytes.
pub const SHA3_256_LENGTH: usize = 32;

/// A SHA3-256 digest.
pub type Sha3Hash = [u8; SHA3_256_LENGTH];

/// Hashes `data` with SHA3-256.
///
/// This function is deterministic: the same input always produces the same
/// 32-byte digest.
///
/// # Examples
///
/// ```
/// let digest = ais_crypto::sha3_256(b"ais-core");
/// assert_eq!(digest.len(), 32);
/// ```
pub fn sha3_256(data: &[u8]) -> Sha3Hash {
    let digest = Sha3_256::digest(data);
    let mut output = [0u8; SHA3_256_LENGTH];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let first = sha3_256(b"ais-core");
        let second = sha3_256(b"ais-core");

        assert_eq!(first, second);
    }

    #[test]
    fn hash_matches_sha3_256_empty_vector() {
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];

        assert_eq!(sha3_256(b""), expected);
    }

    #[test]
    fn hash_changes_when_input_changes() {
        let first = sha3_256(b"ais-core");
        let second = sha3_256(b"ais-corf");

        assert_ne!(first, second);
    }
}
