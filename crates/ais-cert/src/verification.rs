//! AI Certificate verification support.

use ais_crypto::{sha3_256, verify};

use crate::certificate::{signing_payload_hash, AICertificate};
use crate::error::CertificateError;

/// Verifies an AI Certificate against model bytes.
///
/// Verification fails closed on any model hash mismatch, malformed public key,
/// signature mismatch, or certificate serialization failure.
pub fn verify_certificate(
    certificate: &AICertificate,
    model_bytes: &[u8],
) -> Result<(), CertificateError> {
    if sha3_256(model_bytes) != certificate.model_hash {
        return Err(CertificateError::ModelHashMismatch);
    }

    let payload_hash = signing_payload_hash(certificate)?;
    verify(
        &certificate.public_key,
        &payload_hash,
        &certificate.signature,
    )
    .map_err(|_| CertificateError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{sign_certificate, ModelIdentity, AIS_CERTIFICATE_VERSION};
    use ais_crypto::{generate_private_key, public_key_from_private_key};

    fn signed_certificate() -> (AICertificate, Vec<u8>) {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let model_bytes = b"model bytes".to_vec();
        let mut certificate = AICertificate {
            version: AIS_CERTIFICATE_VERSION,
            serial_number: [3u8; 16],
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
            model_hash: sha3_256(&model_bytes),
            public_key,
            signature: [0u8; 64],
        };

        sign_certificate(&mut certificate, &private_key).expect("certificate should sign");
        (certificate, model_bytes)
    }

    #[test]
    fn signed_certificate_verifies() {
        let (certificate, model_bytes) = signed_certificate();

        verify_certificate(&certificate, &model_bytes).expect("certificate should verify");
    }

    #[test]
    fn verification_fails_for_changed_model_bytes() {
        let (certificate, _) = signed_certificate();

        let result = verify_certificate(&certificate, b"changed model bytes");

        assert_eq!(result, Err(CertificateError::ModelHashMismatch));
    }

    #[test]
    fn verification_fails_for_changed_signature() {
        let (mut certificate, model_bytes) = signed_certificate();
        certificate.signature[0] ^= 1;

        let result = verify_certificate(&certificate, &model_bytes);

        assert_eq!(result, Err(CertificateError::SignatureVerificationFailed));
    }

    #[test]
    fn verification_fails_for_changed_signed_field() {
        let (mut certificate, model_bytes) = signed_certificate();
        certificate.subject.name = "changed-model".to_string();

        let result = verify_certificate(&certificate, &model_bytes);

        assert_eq!(result, Err(CertificateError::SignatureVerificationFailed));
    }
}
