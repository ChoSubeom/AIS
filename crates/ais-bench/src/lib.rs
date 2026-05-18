//! AIS-Core performance benchmarks.
//!
//! Measures throughput and per-operation latency for the core AIS-Core
//! security primitives: certificate verification, session frame validation,
//! replay attack rejection, and proxy latency overhead.
//!
//! Each benchmark module exposes a `run(iterations: u64)` function.
//! The proxy module's `run` is `async`; the others are synchronous.
//!
//! # Iteration defaults
//!
//! | Benchmark          | Default    | Rationale                          |
//! |--------------------|------------|------------------------------------|
//! | Certificate        | 5,000      | Ed25519 verify ≈ 0.1 ms            |
//! | Session validation | 20,000     | SHA3-256 MAC ≈ 5–15 µs             |
//! | Replay rejection   | 20,000     | same path as session validation     |
//! | Proxy latency      | 1,000      | localhost HTTP ≈ 1–5 ms            |

pub mod bench_cert;
pub mod bench_proxy;
pub mod bench_replay;
pub mod bench_session;
pub mod report;

/// Default iteration count for certificate verification.
pub const CERT_ITERATIONS: u64 = 5_000;

/// Default iteration count for session frame validation.
pub const SESSION_ITERATIONS: u64 = 20_000;

/// Default iteration count for replay attack rejection.
pub const REPLAY_ITERATIONS: u64 = 20_000;

/// Default iteration count for each leg of the proxy latency benchmark.
///
/// 1,000 iterations provide enough samples (~200–400 ms of wall time per leg)
/// for stable median and p99 measurements suitable for research reporting.
pub const PROXY_ITERATIONS: u64 = 1_000;
