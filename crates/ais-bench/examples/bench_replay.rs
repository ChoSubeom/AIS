//! Standalone replay attack rejection benchmark.
//!
//! Usage:
//!   cargo run --example bench_replay -p ais-bench
//!
//! Override iterations via the first argument:
//!   cargo run --example bench_replay -p ais-bench -- 50000

use ais_bench::{bench_replay, REPLAY_ITERATIONS};

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(REPLAY_ITERATIONS);

    bench_replay::run(iterations).print();
}
