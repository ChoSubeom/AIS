//! Benchmark: AIS proxy latency overhead.
//!
//! Compares two request paths over localhost:
//!
//!   Direct:  client → mock backend
//!   AIS:     client → AIS proxy (validate + audit) → mock backend
//!
//! The overhead is the additional per-request latency introduced by AIS:
//! header parsing, session lookup, MAC verification, sequence check, request
//! hashing, and audit chain append.
//!
//! Both legs use the same mock backend and the same request body so the only
//! variable is the AIS proxy processing path.

use std::time::Instant;

use axum::{routing::post, Json, Router};
use reqwest::Client;
use tokio::net::TcpListener;

use ais_proxy::{AppState, ProxyConfig};
use ais_session::{create_frame, SessionId};

use crate::report::{BenchReport, ProxyBenchResult};

async fn start_mock_backend() -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            Json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "ok"}}]
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

async fn start_proxy(backend_url: &str) -> String {
    let state = AppState::new(ProxyConfig {
        backend_url: backend_url.to_string(),
    });
    let app = ais_proxy::build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

/// Runs `iterations` requests on each path and returns a side-by-side report.
///
/// Infrastructure (mock backend, proxy, session creation, frame pre-computation)
/// is set up before the timed sections begin.
pub async fn run(iterations: u64) -> ProxyBenchResult {
    let client = Client::new();
    let backend_url = start_mock_backend().await;
    let proxy_url = start_proxy(&backend_url).await;

    // Create an AIS session via the proxy API.
    let session_resp: serde_json::Value = client
        .post(format!("{proxy_url}/ais/v1/sessions"))
        .send()
        .await
        .expect("session creation should succeed")
        .json()
        .await
        .expect("session response should be JSON");

    let session_id_hex = session_resp["session_id"].as_str().unwrap().to_string();
    let key_hex = session_resp["integrity_key"].as_str().unwrap();
    let key_bytes = hex::decode(key_hex).expect("integrity key should be valid hex");
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let id_bytes = hex::decode(&session_id_hex).expect("session id should be valid hex");
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(&id_bytes);
    let session_id = SessionId::from_bytes(id_arr);

    let body_bytes = serde_json::to_vec(&serde_json::json!({
        "model": "bench-model",
        "messages": [{"role": "user", "content": "bench"}]
    }))
    .unwrap();

    let timestamp = 1_748_000_000u64;

    // Pre-compute AIS frames (not timed).
    let macs: Vec<String> = (0..iterations)
        .map(|seq| {
            let frame = create_frame(session_id, seq, timestamp, body_bytes.clone(), &key)
                .expect("frame should be created");
            hex::encode(frame.integrity_mac)
        })
        .collect();

    // Warm-up: one request on each path to populate OS TCP buffers.
    let _ = client
        .post(format!("{backend_url}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone())
        .send()
        .await;

    // ── Timed section A: direct backend ──────────────────────────────────────

    let mut direct_latencies_ns = Vec::with_capacity(iterations as usize);
    let direct_start = Instant::now();

    for _ in 0..iterations {
        let op_start = Instant::now();
        client
            .post(format!("{backend_url}/v1/chat/completions"))
            .header("Content-Type", "application/json")
            .body(body_bytes.clone())
            .send()
            .await
            .expect("direct request should succeed");
        direct_latencies_ns.push(op_start.elapsed().as_nanos() as u64);
    }

    let direct_elapsed = direct_start.elapsed();

    // ── Timed section B: AIS proxy ────────────────────────────────────────────

    let mut proxy_latencies_ns = Vec::with_capacity(iterations as usize);
    let proxy_start = Instant::now();

    for (seq, mac) in macs.iter().enumerate() {
        let op_start = Instant::now();
        client
            .post(format!("{proxy_url}/v1/chat/completions"))
            .header("x-ais-session-id", &session_id_hex)
            .header("x-ais-sequence", seq.to_string())
            .header("x-ais-timestamp", timestamp.to_string())
            .header("x-ais-integrity-mac", mac)
            .header("Content-Type", "application/json")
            .body(body_bytes.clone())
            .send()
            .await
            .expect("proxy request should succeed");
        proxy_latencies_ns.push(op_start.elapsed().as_nanos() as u64);
    }

    let proxy_elapsed = proxy_start.elapsed();

    ProxyBenchResult {
        direct: BenchReport {
            name: "Direct Backend",
            iterations,
            elapsed: direct_elapsed,
            rejected: 0,
            latencies_ns: direct_latencies_ns,
        },
        proxy: BenchReport {
            name: "AIS Proxy",
            iterations,
            elapsed: proxy_elapsed,
            rejected: 0,
            latencies_ns: proxy_latencies_ns,
        },
    }
}
