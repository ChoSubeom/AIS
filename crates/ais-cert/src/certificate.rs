//! AI Certificate data structures and signing support.

use ais_crypto::{sha3_256, sign, PrivateKeyBytes};
use serde::Serialize;

use crate::error::CertificateError;

/// Current AIS certificate version.
pub const AIS_CERTIFICATE_VERSION: u16 = 1;

/// Deterministic model identity bound into an AI Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    /// Model name.
    pub name: String,
    /// Model version.
    pub version: String,
    /// Model architecture name.
    pub architecture: String,
    /// Number of model parameters.
    pub parameter_count: u64,
    /// SHA3-256 hash of the tokenizer.
    pub tokenizer_hash: [u8; 32],
}

/// Minimal AIS-Core AI Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AICertificate {
    /// Certificate format version.
    pub version: u16,
    /// Certificate serial number.
    pub serial_number: [u8; 16],
    /// Certificate issuer name.
    pub issuer: String,
    /// Model identity described by this certificate.
    pub subject: ModelIdentity,
    /// Certificate validity start timestamp.
    pub valid_from: u64,
    /// Certificate validity end timestamp.
    pub valid_until: u64,
    /// SHA3-256 hash of the model bytes.
    pub model_hash: [u8; 32],
    /// Ed25519 public key used to verify the certificate signature.
    pub public_key: [u8; 32],
    /// Ed25519 signature over the canonical certificate signing payload hash.
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct ModelIdentitySigningPayload<'a>(&'a str, &'a str, &'a str, u64, &'a [u8; 32]);

#[derive(Serialize)]
struct CertificateSigningPayload<'a>(
    u16,
    &'a [u8; 16],
    &'a str,
    ModelIdentitySigningPayload<'a>,
    u64,
    u64,
    &'a [u8; 32],
    &'a [u8; 32],
);

/// Signs an AI Certificate in place.
///
/// The signature is computed over SHA3-256 of the certificate signing payload.
/// The signing payload excludes the `signature` field and is encoded as a
/// fixed-order CBOR array to keep the signed bytes deterministic.
pub fn sign_certificate(
    certificate: &mut AICertificate,
    private_key: &PrivateKeyBytes,
) -> Result<(), CertificateError> {
    let payload_hash = signing_payload_hash(certificate)?;
    certificate.signature = sign(private_key, &payload_hash);
    Ok(())
}

pub(crate) fn signing_payload_hash(
    certificate: &AICertificate,
) -> Result<[u8; 32], CertificateError> {
    let payload = canonical_signing_payload(certificate)?;
    Ok(sha3_256(&payload))
}

pub(crate) fn canonical_signing_payload(
    certificate: &AICertificate,
) -> Result<Vec<u8>, CertificateError> {
    let subject = ModelIdentitySigningPayload(
        &certificate.subject.name,
        &certificate.subject.version,
        &certificate.subject.architecture,
        certificate.subject.parameter_count,
        &certificate.subject.tokenizer_hash,
    );
    let payload = CertificateSigningPayload(
        certificate.version,
        &certificate.serial_number,
        &certificate.issuer,
        subject,
        certificate.valid_from,
        certificate.valid_until,
        &certificate.model_hash,
        &certificate.public_key,
    );

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded)
        .map_err(|_| CertificateError::SerializationFailed)?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ais_crypto::{generate_private_key, public_key_from_private_key};

    fn test_certificate() -> (AICertificate, PrivateKeyBytes) {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let model_bytes = b"model bytes";

        let certificate = AICertificate {
            version: AIS_CERTIFICATE_VERSION,
            serial_number: [1u8; 16],
            issuer: "AIS Test Issuer".to_string(),
            subject: ModelIdentity {
                name: "test-model".to_string(),
                version: "1.0.0".to_string(),
                architecture: "transformer".to_string(),
                parameter_count: 7,
                tokenizer_hash: sha3_256(b"tokenizer"),
            },
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
            model_hash: sha3_256(model_bytes),
            public_key,
            signature: [0u8; 64],
        };

        (certificate, private_key)
    }

    #[test]
    fn signing_is_deterministic_for_same_certificate_and_key() {
        let (certificate, private_key) = test_certificate();
        let mut first = certificate.clone();
        let mut second = certificate;

        sign_certificate(&mut first, &private_key).expect("certificate should sign");
        sign_certificate(&mut second, &private_key).expect("certificate should sign");

        assert_eq!(first.signature, second.signature);
    }

    #[test]
    fn signing_payload_is_deterministic() {
        let (certificate, _) = test_certificate();

        let first = canonical_signing_payload(&certificate).expect("payload should serialize");
        let second = canonical_signing_payload(&certificate).expect("payload should serialize");

        assert_eq!(first, second);
    }

    #[test]
    fn signing_payload_excludes_signature() {
        let (mut first, _) = test_certificate();
        let mut second = first.clone();
        first.signature = [1u8; 64];
        second.signature = [2u8; 64];

        let first_payload = canonical_signing_payload(&first).expect("payload should serialize");
        let second_payload = canonical_signing_payload(&second).expect("payload should serialize");

        assert_eq!(first_payload, second_payload);
    }
}
