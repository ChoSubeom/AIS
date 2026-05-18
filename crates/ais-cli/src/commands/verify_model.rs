//! `verify-model` command implementation.

use ais_cert::{verify_certificate, AICertificate, ModelIdentity};
use serde::Deserialize;

use crate::cli::VerifyModelArgs;
use crate::commands::sign_model::read_file;
use crate::error::CliError;

#[derive(Deserialize)]
struct StoredModelIdentity(String, String, String, u64, Vec<u8>);

#[derive(Deserialize)]
struct StoredCertificate(
    u16,
    Vec<u8>,
    String,
    StoredModelIdentity,
    u64,
    u64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

/// Runs the `verify-model` command.
pub fn run(args: VerifyModelArgs) -> Result<(), CliError> {
    let model_bytes = read_file(&args.model)?;
    let cert_bytes = read_file(&args.cert)?;
    let certificate = decode_certificate(&cert_bytes)?;

    verify_certificate(&certificate, &model_bytes)?;

    Ok(())
}

pub(crate) fn decode_certificate(bytes: &[u8]) -> Result<AICertificate, CliError> {
    let StoredCertificate(
        version,
        serial_number,
        issuer,
        subject,
        valid_from,
        valid_until,
        model_hash,
        public_key,
        signature,
    ) = ciborium::de::from_reader(bytes).map_err(|_| CliError::DeserializationFailed)?;

    let StoredModelIdentity(name, subject_version, architecture, parameter_count, tokenizer_hash) =
        subject;

    Ok(AICertificate {
        version,
        serial_number: fixed_16(serial_number, "serial_number")?,
        issuer,
        subject: ModelIdentity {
            name,
            version: subject_version,
            architecture,
            parameter_count,
            tokenizer_hash: fixed_32(tokenizer_hash, "tokenizer_hash")?,
        },
        valid_from,
        valid_until,
        model_hash: fixed_32(model_hash, "model_hash")?,
        public_key: fixed_32(public_key, "public_key")?,
        signature: fixed_64(signature, "signature")?,
    })
}

fn fixed_16(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 16], CliError> {
    bytes
        .try_into()
        .map_err(|_| CliError::InvalidLength { field })
}

fn fixed_32(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 32], CliError> {
    bytes
        .try_into()
        .map_err(|_| CliError::InvalidLength { field })
}

fn fixed_64(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 64], CliError> {
    bytes
        .try_into()
        .map_err(|_| CliError::InvalidLength { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::sign_model::encode_certificate;
    use ais_cert::{sign_certificate, AIS_CERTIFICATE_VERSION};
    use ais_crypto::{generate_private_key, public_key_from_private_key, sha3_256};

    #[test]
    fn encoded_certificate_decodes() {
        let private_key = generate_private_key();
        let public_key = public_key_from_private_key(&private_key);
        let mut certificate = AICertificate {
            version: AIS_CERTIFICATE_VERSION,
            serial_number: [1u8; 16],
            issuer: "issuer.key".to_string(),
            subject: ModelIdentity {
                name: "model.gguf".to_string(),
                version: "0".to_string(),
                architecture: "unknown".to_string(),
                parameter_count: 0,
                tokenizer_hash: [0u8; 32],
            },
            valid_from: 0,
            valid_until: u64::MAX,
            model_hash: sha3_256(b"model"),
            public_key,
            signature: [0u8; 64],
        };
        sign_certificate(&mut certificate, &private_key).expect("certificate should sign");

        let encoded = encode_certificate(&certificate).expect("certificate should encode");
        let decoded = decode_certificate(&encoded).expect("certificate should decode");

        assert_eq!(decoded, certificate);
    }
}
