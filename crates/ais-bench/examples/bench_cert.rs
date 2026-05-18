//! Standalone certificate verification benchmark.
//!
//! Usage:
//!   cargo run --example bench_cert -p ais-bench
//!
//! Override iterations via the first argument:
//!   cargo run --example bench_cert -p ais-bench -- 10000

use ais_bench::{bench_cert, CERT_ITERATIONS};

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(CERT_ITERATIONS);

    bench_cert::run(iterations).print();
}
