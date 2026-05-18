fn main() -> Result<(), ais_crypto::CryptoError> {
    let private_key = ais_crypto::generate_private_key();
    let public_key = ais_crypto::public_key_from_private_key(&private_key);
    let message = b"model weights";

    let signature = ais_crypto::sign(&private_key, message);
    ais_crypto::verify(&public_key, message, &signature)?;

    println!("signature verified");
    Ok(())
}
