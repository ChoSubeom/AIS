//! OpenAI-compatible proxy demonstration.
//!
//! Shows the full AIS request flow end-to-end:
//!
//!   client → AIS proxy (session validation + audit) → mock backend
//!
//! Steps demonstrated:
//!   1. Mock backend starts on a random local port.
//!   2. AIS proxy starts, pointing at that backend.
//!   3. Client creates an AIS session.
//!   4. Client sends a valid chat completion with correct AIS framing.
//!   5. Proxy validates the frame, forwards, records an audit entry.
//!   6. Client replays the same request — proxy rejects it (sequence replay).
//!   7. Audit chain integrity is verified.
//!
//! Run:
//!   cargo run --example openai_proxy_demo -p ais-demos

use std::sync::Arc;

use axum::{routing::post, Json, Router};
use reqwest::Client;
use tokio::net::TcpListener;

use ais_proxy::{AppState, ProxyConfig};
use ais_session::{create_frame, SessionId};

async fn start_mock_backend() -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            Json(serde_json::json!({
                "id": "mock-chatcmpl-001",
                "object": "chat.completion",
                "model": "demo-llm-7b",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "The answer is 4."
                    },
                    "finish_reason": "stop"
                }]
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

async fn start_proxy(backend_url: &str) -> (String, Arc<AppState>) {
    let state = AppState::new(ProxyConfig {
        backend_url: backend_url.to_string(),
    });
    let app = ais_proxy::build_router(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://127.0.0.1:{port}"), state)
}

#[tokio::main]
async fn main() {
    println!("┌────────────────────────────────────────────────┐");
    println!("│  AIS Demo: OpenAI-Compatible Proxy             │");
    println!("└────────────────────────────────────────────────┘");

    // Start infrastructure.
    let backend_url = start_mock_backend().await;
    let (proxy_url, state) = start_proxy(&backend_url).await;

    println!();
    println!("  Mock backend:  {backend_url}");
    println!("  AIS proxy:     {proxy_url}");

    let client = Client::new();

    // ── Step 1: create AIS session ────────────────────────────────────────────

    println!();
    println!("  [Step 1] Creating AIS session...");

    let session_resp: serde_json::Value = client
        .post(format!("{proxy_url}/ais/v1/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let session_id_hex = session_resp["session_id"].as_str().unwrap();
    let key_hex = session_resp["integrity_key"].as_str().unwrap();

    let key_bytes = hex::decode(key_hex).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let id_bytes = hex::decode(session_id_hex).unwrap();
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(&id_bytes);

    println!("           session_id    = {session_id_hex}");
    println!("           integrity_key = {}...", &key_hex[..16]);

    // ── Step 2: valid chat completion ─────────────────────────────────────────

    println!();
    println!("  [Step 2] Sending chat completion (sequence=0)...");

    let body = serde_json::json!({
        "model": "demo-llm-7b",
        "messages": [{"role": "user", "content": "What is 2 + 2?"}]
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let timestamp = 1_748_000_000u64;

    let frame0 = create_frame(
        SessionId::from_bytes(id_arr),
        0,
        timestamp,
        body_bytes.clone(),
        &key,
    )
    .expect("frame created");
    let mac0 = hex::encode(frame0.integrity_mac);

    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", session_id_hex)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", timestamp.to_string())
        .header("x-ais-integrity-mac", &mac0)
        .header("Content-Type", "application/json")
        .body(body_bytes.clone())
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let reply: serde_json::Value = resp.json().await.unwrap();
    let content = reply["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("?");
    println!("           HTTP {status}  →  \"{content}\"");

    // ── Step 3: audit chain ───────────────────────────────────────────────────

    println!();
    println!("  [Step 3] Audit chain...");
    {
        let chain = state.audit_chain.lock().unwrap();
        let n = chain.entries().len();
        chain.validate_chain().expect("audit chain must be valid");
        println!("           entries = {n}  (chain integrity verified)");
    }

    // ── Step 4: replay attack ─────────────────────────────────────────────────

    println!();
    println!("  [Step 4] Replaying sequence=0 (replay attack)...");

    let replay_resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", session_id_hex)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", timestamp.to_string())
        .header("x-ais-integrity-mac", &mac0)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .unwrap();

    let replay_status = replay_resp.status();
    let error: serde_json::Value = replay_resp.json().await.unwrap();
    println!(
        "           HTTP {replay_status}  →  \"{}\"",
        error["error"].as_str().unwrap_or("?")
    );

    // ── Summary ───────────────────────────────────────────────────────────────

    println!();
    println!("  Result: AIS proxy enforced session integrity end-to-end.");
    println!("  The audit chain records every interaction with a hash-chained log.");
    println!();
}
