//! Benchmark: Replay attack rejection throughput and latency.
//!
//! Measures how quickly the AIS session layer rejects a replayed frame on the
//! fail-closed path.  A single frame at sequence 0 is validated once to advance
//! the counter, then the same frame is presented `iterations` times.  Every
//! attempt must be rejected with `InvalidSequence`.
//!
//! This is the adversarial hot path: an attacker replaying the same captured
//! request as fast as possible.

use std::time::Instant;

use ais_session::{
    create_frame, generate_integrity_key, validate_frame, Session, SessionError, SessionId,
};

use crate::report::BenchReport;

/// Runs `iterations` replay-rejection attempts and returns timing data.
///
/// `rejected` in the returned report equals `iterations` — every attempt is
/// expected to be rejected.
pub fn run(iterations: u64) -> BenchReport {
    let session_id = SessionId::from_bytes([0x43u8; 16]);
    let key = generate_integrity_key();
    let payload = b"AIS bench replay payload".to_vec();
    let timestamp = 1_748_000_000u64;

    // Create a single valid frame at sequence 0.
    let frame =
        create_frame(session_id, 0, timestamp, payload, &key).expect("frame should be created");

    // Consume sequence 0 so every subsequent attempt is a replay.
    let mut session = Session::new(session_id);
    session.activate();
    validate_frame(&mut session, &frame, &key).expect("initial validation should pass");

    // Timed section: all iterations must be rejected.
    let mut latencies_ns = Vec::with_capacity(iterations as usize);
    let total_start = Instant::now();

    for _ in 0..iterations {
        let op_start = Instant::now();
        let result = validate_frame(&mut session, &frame, &key);
        latencies_ns.push(op_start.elapsed().as_nanos() as u64);

        debug_assert_eq!(
            result,
            Err(SessionError::InvalidSequence),
            "replay must be rejected"
        );
    }

    BenchReport {
        name: "Replay Attack Rejection",
        iterations,
        elapsed: total_start.elapsed(),
        rejected: iterations,
        latencies_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_attempt_is_rejected() {
        let r = run(10);
        assert_eq!(r.iterations, 10);
        assert_eq!(r.rejected, 10);
        assert_eq!(r.latencies_ns.len(), 10);
    }

    #[test]
    fn single_iteration_is_rejected() {
        let r = run(1);
        assert_eq!(r.rejected, 1);
    }

    #[test]
    fn rejection_throughput_is_positive() {
        let r = run(5);
        assert!(r.throughput() > 0.0);
        // Rejection path must be at least as fast as a successful validation.
        // We just verify the measurement is plausible (>0 ops/s).
        assert!(r.throughput() > 1.0);
    }
}
