//! Rogue model demonstration.
//!
//! AIS binds a SHA3-256 hash of the model weights into an AI Certificate.
//! The certificate is Ed25519-signed by the issuer. Any modification to the
//! model bytes — even a single bit — causes certificate verification to fail
//! deterministically.
//!
//! Two attacks are shown:
//!   1. tampered model weights (hash mismatch)
//!   2. forged certificate with a changed field (signature mismatch)
//!
//! Run:
//!   cargo run --example rogue_model_demo -p ais-demos

use ais_cert::{
    sign_certificate, verify_certificate, AICertificate, ModelIdentity, AIS_CERTIFICATE_VERSION,
};
use ais_crypto::{generate_private_key, public_key_from_private_key, sha3_256};

fn hex8(bytes: &[u8]) -> String {
    bytes[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "..."
}

fn main() {
    println!("┌────────────────────────────────────────────────┐");
    println!("│  AIS Demo: Rogue Model Detection               │");
    println!("└────────────────────────────────────────────────┘");

    // Issuer key pair (represents a trusted model vendor).
    let private_key = generate_private_key();
    let public_key = public_key_from_private_key(&private_key);

    // Simulate model weights as 256 bytes.
    let model_bytes: Vec<u8> = (0u8..=255).collect();
    let model_hash = sha3_256(&model_bytes);

    println!();
    println!("  [Setup] Model weights:     {} bytes", model_bytes.len());
    println!("          SHA3-256 hash:     {}", hex8(&model_hash));
    println!("          Issuer public key: {}", hex8(&public_key));

    // Issue and sign the AI Certificate.
    let mut cert = AICertificate {
        version: AIS_CERTIFICATE_VERSION,
        serial_number: [0x41, 0x49, 0x53, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        issuer: "AIS Demo Issuer".to_string(),
        subject: ModelIdentity {
            name: "demo-llm-7b".to_string(),
            version: "1.0.0".to_string(),
            architecture: "transformer".to_string(),
            parameter_count: 7_000_000_000,
            tokenizer_hash: sha3_256(b"demo-tokenizer-v1"),
        },
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        model_hash,
        public_key,
        signature: [0u8; 64],
    };
    sign_certificate(&mut cert, &private_key).expect("certificate signed");

    println!();
    println!("  [Step 1] Certificate issued");
    println!("           Issuer:    \"{}\"", cert.issuer);
    println!(
        "           Subject:   \"{}\" v{}",
        cert.subject.name, cert.subject.version
    );
    println!("           Signature: {}", hex8(&cert.signature));

    // ── Attack 1: tampered model weights ─────────────────────────────────────

    println!();
    println!("  ATTACK 1: tampered model weights");
    println!("  ─────────────────────────────────");

    match verify_certificate(&cert, &model_bytes) {
        Ok(()) => println!("  [Original bytes]  → ACCEPTED: model identity confirmed"),
        Err(e) => println!("  [Original bytes]  → ERROR: {e}"),
    }

    let mut tampered = model_bytes.clone();
    tampered[42] ^= 0xFF;
    let tampered_hash = sha3_256(&tampered);

    println!();
    println!(
        "  Tampered:  byte[42] flipped (0x{:02x} → 0x{:02x})",
        model_bytes[42], tampered[42]
    );
    println!("             new hash: {}  (differs)", hex8(&tampered_hash));

    match verify_certificate(&cert, &tampered) {
        Ok(()) => println!("  [Tampered bytes]  → ACCEPTED  ← bug"),
        Err(e) => println!("  [Tampered bytes]  → REJECTED: {e}"),
    }

    // ── Attack 2: forged certificate (changed subject field) ─────────────────

    println!();
    println!("  ATTACK 2: forged certificate (attacker changes subject name)");
    println!("  ──────────────────────────────────────────────────────────────");

    let mut forged = cert.clone();
    forged.subject.name = "rogue-model".to_string();

    println!(
        "  Forged subject: \"{}\"  (signature not updated)",
        forged.subject.name
    );

    match verify_certificate(&forged, &model_bytes) {
        Ok(()) => println!("  [Forged cert]     → ACCEPTED  ← bug"),
        Err(e) => println!("  [Forged cert]     → REJECTED: {e}"),
    }

    println!();
    println!("  Result: AIS-Core rejects both attacks deterministically.");
    println!("  Model hash mismatch and signature forgery are caught without");
    println!("  any probabilistic classifier.");
    println!();
}
