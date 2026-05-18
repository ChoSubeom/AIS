//! Standalone proxy latency overhead benchmark.
//!
//! Usage:
//!   cargo run --example bench_proxy -p ais-bench
//!
//! Override iterations via the first argument:
//!   cargo run --example bench_proxy -p ais-bench -- 500

use ais_bench::{bench_proxy, PROXY_ITERATIONS};

#[tokio::main]
async fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(PROXY_ITERATIONS);

    bench_proxy::run(iterations).await.print();
}
