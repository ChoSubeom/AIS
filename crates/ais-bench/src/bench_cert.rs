//! Benchmark: AI Certificate verification throughput and latency.
//!
//! Measures the cost of `verify_certificate` — the path every AIS deployment
//! walks when confirming that a model's weights match its signed certificate.
//! This covers SHA3-256 hashing of the model bytes, CBOR payload construction,
//! and Ed25519 signature verification.

use std::time::Instant;

use ais_cert::{
    sign_certificate, verify_certificate, AICertificate, ModelIdentity, AIS_CERTIFICATE_VERSION,
};
use ais_crypto::{generate_private_key, public_key_from_private_key, sha3_256};

use crate::report::BenchReport;

/// Runs `iterations` certificate verifications and returns timing data.
///
/// Setup (key generation, certificate signing) is performed once and is not
/// counted in the elapsed time.
pub fn run(iterations: u64) -> BenchReport {
    // One-time setup — not timed.
    let private_key = generate_private_key();
    let public_key = public_key_from_private_key(&private_key);

    // Simulate model bytes (4 KiB — small enough to be fast, large enough to
    // exercise the SHA3-256 hash path realistically).
    let model_bytes: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let mut cert = AICertificate {
        version: AIS_CERTIFICATE_VERSION,
        serial_number: [0x41u8; 16],
        issuer: "AIS-Bench Issuer".to_string(),
        subject: ModelIdentity {
            name: "bench-model".to_string(),
            version: "1.0.0".to_string(),
            architecture: "transformer".to_string(),
            parameter_count: 7_000_000_000,
            tokenizer_hash: sha3_256(b"bench-tokenizer"),
        },
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        model_hash: sha3_256(&model_bytes),
        public_key,
        signature: [0u8; 64],
    };
    sign_certificate(&mut cert, &private_key).expect("certificate should sign");

    // Timed section.
    let mut latencies_ns = Vec::with_capacity(iterations as usize);
    let total_start = Instant::now();

    for _ in 0..iterations {
        let op_start = Instant::now();
        verify_certificate(&cert, &model_bytes).expect("verification should pass");
        latencies_ns.push(op_start.elapsed().as_nanos() as u64);
    }

    BenchReport {
        name: "Certificate Verification",
        iterations,
        elapsed: total_start.elapsed(),
        rejected: 0,
        latencies_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_iteration_returns_one_sample() {
        let r = run(1);
        assert_eq!(r.iterations, 1);
        assert_eq!(r.rejected, 0);
        assert_eq!(r.latencies_ns.len(), 1);
        assert!(r.elapsed.as_nanos() > 0);
    }

    #[test]
    fn ten_iterations_return_ten_samples() {
        let r = run(10);
        assert_eq!(r.iterations, 10);
        assert_eq!(r.latencies_ns.len(), 10);
    }

    #[test]
    fn throughput_is_positive() {
        let r = run(5);
        assert!(r.throughput() > 0.0);
    }
}
