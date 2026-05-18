//! Standalone session frame validation benchmark.
//!
//! Usage:
//!   cargo run --example bench_session -p ais-bench
//!
//! Override iterations via the first argument:
//!   cargo run --example bench_session -p ais-bench -- 50000

use ais_bench::{bench_session, SESSION_ITERATIONS};

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(SESSION_ITERATIONS);

    bench_session::run(iterations).print();
}
