fn main() -> Result<(), ais_cert::CertificateError> {
    let private_key = ais_crypto::generate_private_key();
    let public_key = ais_crypto::public_key_from_private_key(&private_key);
    let model_bytes = b"model bytes";

    let mut certificate = ais_cert::AICertificate {
        version: ais_cert::AIS_CERTIFICATE_VERSION,
        serial_number: [1u8; 16],
        issuer: "AIS Example Issuer".to_string(),
        subject: ais_cert::ModelIdentity {
            name: "example-model".to_string(),
            version: "1.0.0".to_string(),
            architecture: "transformer".to_string(),
            parameter_count: 7,
            tokenizer_hash: ais_crypto::sha3_256(b"tokenizer"),
        },
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        model_hash: ais_crypto::sha3_256(model_bytes),
        public_key,
        signature: [0u8; 64],
    };

    ais_cert::sign_certificate(&mut certificate, &private_key)?;
    ais_cert::verify_certificate(&certificate, model_bytes)?;

    println!("certificate verified");
    Ok(())
}
