//! AIS benchmark suite — runs all four benchmarks and prints a summary.
//!
//! Usage:
//!   cargo run --bin ais-bench -p ais-bench

use ais_bench::{
    bench_cert, bench_proxy, bench_replay, bench_session, CERT_ITERATIONS, PROXY_ITERATIONS,
    REPLAY_ITERATIONS, SESSION_ITERATIONS,
};

#[tokio::main]
async fn main() {
    println!("┌────────────────────────────────────────────────┐");
    println!("│  AIS Benchmark Suite                           │");
    println!("└────────────────────────────────────────────────┘");
    println!();

    bench_cert::run(CERT_ITERATIONS).print();
    bench_session::run(SESSION_ITERATIONS).print();
    bench_replay::run(REPLAY_ITERATIONS).print();
    bench_proxy::run(PROXY_ITERATIONS).await.print();
}
