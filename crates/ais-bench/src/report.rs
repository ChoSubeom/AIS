//! Benchmark report types and display helpers.

use std::time::Duration;

/// Result from a single benchmark run.
pub struct BenchReport {
    /// Benchmark name shown in output.
    pub name: &'static str,
    /// Number of operations attempted.
    pub iterations: u64,
    /// Wall-clock time for all iterations.
    pub elapsed: Duration,
    /// Number of operations that returned an error (fail-closed rejections).
    pub rejected: u64,
    /// Per-operation wall-clock latency in nanoseconds, in execution order.
    ///
    /// Nanosecond resolution is required for the replay rejection path, which
    /// completes in tens of nanoseconds.
    pub latencies_ns: Vec<u64>,
}

impl BenchReport {
    /// Operations per second over the full run.
    pub fn throughput(&self) -> f64 {
        self.iterations as f64 / self.elapsed.as_secs_f64()
    }

    /// Mean per-operation latency in nanoseconds.
    pub fn mean_ns(&self) -> f64 {
        if self.latencies_ns.is_empty() {
            return 0.0;
        }
        self.latencies_ns.iter().sum::<u64>() as f64 / self.latencies_ns.len() as f64
    }

    /// Median per-operation latency in nanoseconds.
    ///
    /// Returns `None` when no latency samples are recorded.
    pub fn median_ns(&self) -> Option<u64> {
        if self.latencies_ns.is_empty() {
            return None;
        }
        let mut sorted = self.latencies_ns.clone();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }

    /// 99th-percentile per-operation latency in nanoseconds.
    ///
    /// Returns `None` when no latency samples are recorded.
    pub fn p99_ns(&self) -> Option<u64> {
        if self.latencies_ns.is_empty() {
            return None;
        }
        let mut sorted = self.latencies_ns.clone();
        sorted.sort_unstable();
        let idx = (sorted.len() * 99) / 100;
        Some(sorted[idx])
    }

    /// Prints a formatted one-block summary to stdout.
    pub fn print(&self) {
        println!("  {}", self.name);
        println!("  {}", "─".repeat(self.name.len()));
        println!("  Iterations:  {:>13}", fmt_num(self.iterations));
        println!("  Elapsed:     {:>13}", fmt_duration(self.elapsed));
        println!(
            "  Throughput:  {:>13}",
            format!("{:.0} ops/s", self.throughput())
        );
        if self.rejected > 0 {
            println!("  Rejected:    {:>13}", fmt_num(self.rejected));
        }
        if !self.latencies_ns.is_empty() {
            println!("  Mean:        {:>13}", fmt_ns(self.mean_ns()));
            if let Some(m) = self.median_ns() {
                println!("  Median:      {:>13}", fmt_ns(m as f64));
            }
            if let Some(p) = self.p99_ns() {
                println!("  p99:         {:>13}", fmt_ns(p as f64));
            }
        }
        println!();
    }
}

/// Side-by-side result for the proxy latency benchmark.
pub struct ProxyBenchResult {
    /// Requests sent directly to the mock backend (no AIS).
    pub direct: BenchReport,
    /// Requests sent through the AIS proxy.
    pub proxy: BenchReport,
}

impl ProxyBenchResult {
    /// Median AIS overhead: proxy median minus direct median, in nanoseconds.
    pub fn overhead_ns(&self) -> f64 {
        let proxy = self.proxy.median_ns().unwrap_or(0) as f64;
        let direct = self.direct.median_ns().unwrap_or(0) as f64;
        proxy - direct
    }

    /// Prints a combined summary with the computed AIS overhead.
    pub fn print(&self) {
        let title = "Proxy Latency Overhead";
        println!("  {title}");
        println!("  {}", "─".repeat(title.len()));
        println!("  Iterations:  {:>13}", fmt_num(self.direct.iterations));
        println!();

        println!("  Direct backend (no AIS):");
        println!(
            "    Throughput: {:>10}",
            format!("{:.0} ops/s", self.direct.throughput())
        );
        print_latency_pair(self.direct.median_ns(), self.direct.p99_ns());

        println!();
        println!("  AIS proxy:");
        println!(
            "    Throughput: {:>10}",
            format!("{:.0} ops/s", self.proxy.throughput())
        );
        print_latency_pair(self.proxy.median_ns(), self.proxy.p99_ns());

        println!();
        let overhead = self.overhead_ns();
        if overhead >= 0.0 {
            println!("  AIS overhead (median): +{}", fmt_ns(overhead));
        } else {
            println!("  AIS overhead (median):  {}", fmt_ns(overhead));
        }
        println!();
    }
}

fn print_latency_pair(median: Option<u64>, p99: Option<u64>) {
    let m = median
        .map(|v| fmt_ns(v as f64))
        .unwrap_or_else(|| "n/a".into());
    let p = p99
        .map(|v| fmt_ns(v as f64))
        .unwrap_or_else(|| "n/a".into());
    println!("    Median: {m:>10}   p99: {p:>10}");
}

pub(crate) fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i != 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

pub(crate) fn fmt_duration(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:.3} s", ms / 1_000.0)
    } else {
        format!("{:.1} ms", ms)
    }
}

/// Auto-scaling nanosecond formatter: ns → us → ms depending on magnitude.
///
/// Values below 1 ns are reported as `< 1 ns` rather than `0 ns`, because a
/// zero reading indicates the operation completed within the timer's resolution
/// rather than taking literally no time.
pub(crate) fn fmt_ns(ns: f64) -> String {
    if ns >= 1_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else if ns >= 1_000.0 {
        format!("{:.2} us", ns / 1_000.0)
    } else if ns < 1.0 {
        "< 1 ns".to_string()
    } else {
        format!("{:.0} ns", ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(latencies: Vec<u64>) -> BenchReport {
        let elapsed = Duration::from_secs(1);
        let iterations = latencies.len() as u64;
        BenchReport {
            name: "test",
            iterations,
            elapsed,
            rejected: 0,
            latencies_ns: latencies,
        }
    }

    #[test]
    fn median_odd_count() {
        // 5 elements sorted → middle is index 2 → value 5
        let r = report(vec![9, 1, 5, 3, 7]);
        assert_eq!(r.median_ns(), Some(5));
    }

    #[test]
    fn median_even_count() {
        // 6 elements sorted [1,3,5,7,9,11] → index 3 → value 7
        let r = report(vec![11, 1, 7, 3, 9, 5]);
        assert_eq!(r.median_ns(), Some(7));
    }

    #[test]
    fn median_single() {
        let r = report(vec![42]);
        assert_eq!(r.median_ns(), Some(42));
    }

    #[test]
    fn median_empty() {
        let r = report(vec![]);
        assert_eq!(r.median_ns(), None);
    }

    #[test]
    fn p99_small_sample() {
        // 10 elements: idx = (10*99)/100 = 9 → last element
        let mut lat: Vec<u64> = (1..=10).collect();
        let r = report(lat.clone());
        lat.sort_unstable();
        assert_eq!(r.p99_ns(), Some(lat[9]));
    }

    #[test]
    fn mean_exact() {
        let r = report(vec![10, 20, 30]);
        let mean = r.mean_ns();
        assert!(
            (mean - 20.0).abs() < 0.001,
            "mean should be 20.0, got {mean}"
        );
    }

    #[test]
    fn throughput_one_second() {
        let r = BenchReport {
            name: "t",
            iterations: 1_000,
            elapsed: Duration::from_secs(1),
            rejected: 0,
            latencies_ns: vec![],
        };
        assert!((r.throughput() - 1_000.0).abs() < 0.01);
    }

    #[test]
    fn throughput_half_second() {
        let r = BenchReport {
            name: "t",
            iterations: 500,
            elapsed: Duration::from_millis(500),
            rejected: 0,
            latencies_ns: vec![],
        };
        assert!((r.throughput() - 1_000.0).abs() < 1.0);
    }

    #[test]
    fn fmt_num_no_comma() {
        assert_eq!(fmt_num(999), "999");
    }

    #[test]
    fn fmt_num_one_comma() {
        assert_eq!(fmt_num(1_000), "1,000");
        assert_eq!(fmt_num(12_345), "12,345");
    }

    #[test]
    fn fmt_num_two_commas() {
        assert_eq!(fmt_num(1_234_567), "1,234,567");
    }

    #[test]
    fn fmt_ns_zero_shows_resolution_limit() {
        assert_eq!(fmt_ns(0.0), "< 1 ns");
    }

    #[test]
    fn fmt_ns_sub_one_shows_resolution_limit() {
        assert_eq!(fmt_ns(0.5), "< 1 ns");
    }

    #[test]
    fn fmt_ns_nanoseconds() {
        assert_eq!(fmt_ns(42.0), "42 ns");
    }

    #[test]
    fn fmt_ns_microseconds() {
        assert_eq!(fmt_ns(14_860.0), "14.86 us");
    }

    #[test]
    fn fmt_ns_milliseconds() {
        assert_eq!(fmt_ns(2_794_000.0), "2.79 ms");
    }
}
