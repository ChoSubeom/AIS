//! `sign-model` command implementation.

use std::path::Path;

use ais_cert::{sign_certificate, AICertificate, ModelIdentity, AIS_CERTIFICATE_VERSION};
use ais_crypto::{public_key_from_private_key, sha3_256, PrivateKeyBytes};
use serde::Serialize;

use crate::cli::SignModelArgs;
use crate::error::CliError;

#[derive(Serialize)]
struct StoredModelIdentity<'a>(&'a str, &'a str, &'a str, u64, &'a [u8]);

#[derive(Serialize)]
struct StoredCertificate<'a>(
    u16,
    &'a [u8],
    &'a str,
    StoredModelIdentity<'a>,
    u64,
    u64,
    &'a [u8],
    &'a [u8],
    &'a [u8],
);

/// Runs the `sign-model` command.
pub fn run(args: SignModelArgs) -> Result<(), CliError> {
    let model_bytes = read_file(&args.model)?;
    let key_bytes = read_file(&args.issuer)?;
    let private_key = private_key_from_bytes(&key_bytes)?;
    let public_key = public_key_from_private_key(&private_key);
    let model_hash = sha3_256(&model_bytes);

    let mut certificate = AICertificate {
        version: AIS_CERTIFICATE_VERSION,
        serial_number: serial_number(&model_hash, &public_key, args.issuer.as_path()),
        issuer: args.issuer.to_string_lossy().into_owned(),
        subject: ModelIdentity {
            name: model_name(args.model.as_path()),
            version: "0".to_string(),
            architecture: "unknown".to_string(),
            parameter_count: 0,
            tokenizer_hash: [0u8; 32],
        },
        // TODO(AIS-MVP):
        // Replace with real validity periods after trust-store design stabilizes.
        valid_from: 0,
        valid_until: u64::MAX,
        model_hash,
        public_key,
        signature: [0u8; 64],
    };

    sign_certificate(&mut certificate, &private_key)?;
    let encoded = encode_certificate(&certificate)?;
    write_file(&args.output, &encoded)?;

    Ok(())
}

pub(crate) fn encode_certificate(certificate: &AICertificate) -> Result<Vec<u8>, CliError> {
    let subject = StoredModelIdentity(
        &certificate.subject.name,
        &certificate.subject.version,
        &certificate.subject.architecture,
        certificate.subject.parameter_count,
        &certificate.subject.tokenizer_hash,
    );
    let stored = StoredCertificate(
        certificate.version,
        &certificate.serial_number,
        &certificate.issuer,
        subject,
        certificate.valid_from,
        certificate.valid_until,
        &certificate.model_hash,
        &certificate.public_key,
        &certificate.signature,
    );

    let mut output = Vec::new();
    ciborium::ser::into_writer(&stored, &mut output).map_err(|_| CliError::SerializationFailed)?;
    Ok(output)
}

pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|source| CliError::ReadFile {
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::write(path, bytes).map_err(|source| CliError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn private_key_from_bytes(bytes: &[u8]) -> Result<PrivateKeyBytes, CliError> {
    bytes.try_into().map_err(|_| CliError::InvalidIssuerKey)
}

fn serial_number(model_hash: &[u8; 32], public_key: &[u8; 32], issuer_path: &Path) -> [u8; 16] {
    let mut input = Vec::new();
    input.extend_from_slice(model_hash);
    input.extend_from_slice(public_key);
    input.extend_from_slice(issuer_path.to_string_lossy().as_bytes());

    let hash = sha3_256(&input);
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&hash[..16]);
    serial
}

fn model_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("model")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ais_crypto::{generate_private_key, public_key_from_private_key};

    #[test]
    fn encoded_certificate_is_deterministic() {
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

        let first = encode_certificate(&certificate).expect("certificate should encode");
        let second = encode_certificate(&certificate).expect("certificate should encode");

        assert_eq!(first, second);
    }
}
