//! Benchmark: AIS session frame validation throughput and latency.
//!
//! Measures `validate_frame` on the hot path — the per-request cost every AIS
//! proxy pays for each inference call.  This covers CBOR MAC payload
//! construction, SHA3-256 recomputation, constant-time comparison, and the
//! sequence counter advance.
//!
//! Frames are pre-created outside the timed loop so that only the validation
//! path is measured.

use std::time::Instant;

use ais_session::{
    create_frame, generate_integrity_key, validate_frame, AISFrame, Session, SessionId,
};

use crate::report::BenchReport;

/// Runs `iterations` frame validations and returns timing data.
///
/// All frames are pre-computed before the timed section begins.
pub fn run(iterations: u64) -> BenchReport {
    let session_id = SessionId::from_bytes([0x42u8; 16]);
    let key = generate_integrity_key();
    let payload = b"AIS bench session payload".to_vec();
    let timestamp = 1_748_000_000u64;

    // Pre-create all frames (not timed).
    let frames: Vec<AISFrame> = (0..iterations)
        .map(|seq| {
            create_frame(session_id, seq, timestamp, payload.clone(), &key)
                .expect("frame should be created")
        })
        .collect();

    let mut session = Session::new(session_id);
    session.activate();

    // Timed section.
    let mut latencies_ns = Vec::with_capacity(iterations as usize);
    let total_start = Instant::now();

    for frame in &frames {
        let op_start = Instant::now();
        validate_frame(&mut session, frame, &key).expect("frame should validate");
        latencies_ns.push(op_start.elapsed().as_nanos() as u64);
    }

    BenchReport {
        name: "Session Frame Validation",
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
    }

    #[test]
    fn sequence_advances_monotonically() {
        // run() internally validates frames 0..N in order; any sequence error
        // would panic on the expect() call inside run().  Reaching here means
        // the sequence counter advanced correctly for all N frames.
        let r = run(20);
        assert_eq!(r.iterations, 20);
        assert_eq!(r.latencies_ns.len(), 20);
    }

    #[test]
    fn throughput_is_positive() {
        let r = run(5);
        assert!(r.throughput() > 0.0);
    }
}
