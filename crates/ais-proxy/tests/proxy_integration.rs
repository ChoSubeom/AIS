//! Integration tests for the AIS proxy.
//!
//! Tests cover the full request flow including session creation, AIS frame
//! validation, fail-closed rejection, and backend forwarding.

use std::sync::Arc;

use axum::routing::post;
use axum::{Json, Router};
use reqwest::Client;
use tokio::net::TcpListener;

use ais_proxy::{AppState, ProxyConfig};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Starts the AIS proxy on a random port and returns its base URL.
async fn start_proxy(backend_url: &str) -> (String, Arc<AppState>) {
    let config = ProxyConfig {
        backend_url: backend_url.to_string(),
    };
    let state = AppState::new(config);
    let app = ais_proxy::build_router(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://127.0.0.1:{port}"), state)
}

/// Starts a minimal mock backend that returns a fixed JSON response.
async fn start_mock_backend() -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            Json(serde_json::json!({
                "id": "mock-response",
                "choices": [{"message": {"role": "assistant", "content": "hello"}}]
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://127.0.0.1:{port}")
}

/// Creates an AIS session via the proxy and returns (session_id_hex, integrity_key_bytes).
async fn create_session(client: &Client, proxy_url: &str) -> (String, [u8; 32]) {
    let resp = client
        .post(format!("{proxy_url}/ais/v1/sessions"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "session creation should succeed");

    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap().to_string();
    let key_hex = body["integrity_key"].as_str().unwrap();
    let key_bytes = hex::decode(key_hex).unwrap();

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    (session_id, key)
}

/// Builds the AIS frame MAC for a request.
fn compute_mac(
    session_id_hex: &str,
    sequence: u64,
    timestamp: u64,
    body: &[u8],
    integrity_key: &[u8; 32],
) -> String {
    use ais_session::{create_frame, SessionId};

    let id_bytes = hex::decode(session_id_hex).unwrap();
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&id_bytes);

    let frame = create_frame(
        SessionId::from_bytes(arr),
        sequence,
        timestamp,
        body.to_vec(),
        integrity_key,
    )
    .unwrap();

    hex::encode(frame.integrity_mac)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_session_returns_credentials() {
    let (proxy_url, _state) = start_proxy("http://localhost:1").await;
    let client = Client::new();

    let resp = client
        .post(format!("{proxy_url}/ais/v1/sessions"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["session_id"].as_str().is_some(), "session_id present");
    assert!(
        body["integrity_key"].as_str().is_some(),
        "integrity_key present"
    );

    let session_id_hex = body["session_id"].as_str().unwrap();
    assert_eq!(session_id_hex.len(), 32, "session_id is 16 bytes hex");

    let key_hex = body["integrity_key"].as_str().unwrap();
    assert_eq!(key_hex.len(), 64, "integrity_key is 32 bytes hex");
}

#[tokio::test]
async fn test_missing_ais_headers_rejected() {
    let (proxy_url, _state) = start_proxy("http://localhost:1").await;
    let client = Client::new();

    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "missing AIS headers → 400");
}

#[tokio::test]
async fn test_unknown_session_id_rejected() {
    let (proxy_url, _state) = start_proxy("http://localhost:1").await;
    let client = Client::new();

    let body = br#"{"model":"test","messages":[]}"#;
    let fake_session_id = hex::encode([0xddu8; 16]);
    let fake_key = [0u8; 32];
    let mac = compute_mac(&fake_session_id, 0, 1_700_000_000, body, &fake_key);

    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", &fake_session_id)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", "1700000000")
        .header("x-ais-integrity-mac", &mac)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "unknown session → 401");
}

#[tokio::test]
async fn test_invalid_mac_rejected() {
    let (proxy_url, _state) = start_proxy("http://localhost:1").await;
    let client = Client::new();

    let (session_id, _key) = create_session(&client, &proxy_url).await;

    let body = br#"{"model":"test","messages":[]}"#;
    // Use a wrong key so MAC is incorrect.
    let wrong_key = [0xffu8; 32];
    let bad_mac = compute_mac(&session_id, 0, 1_700_000_000, body, &wrong_key);

    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", &session_id)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", "1700000000")
        .header("x-ais-integrity-mac", &bad_mac)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "invalid MAC → 401");
}

#[tokio::test]
async fn test_sequence_replay_rejected() {
    let backend_url = start_mock_backend().await;
    let (proxy_url, _state) = start_proxy(&backend_url).await;
    let client = Client::new();

    let (session_id, key) = create_session(&client, &proxy_url).await;

    let body = br#"{"model":"test","messages":[]}"#;
    let ts = 1_700_000_000u64;

    // First request at sequence 0 — should succeed (forwarded to mock backend).
    let mac0 = compute_mac(&session_id, 0, ts, body, &key);
    let resp0 = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", &session_id)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", ts.to_string())
        .header("x-ais-integrity-mac", &mac0)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp0.status(), 200, "first request should succeed");

    // Replay of sequence 0 — must be rejected.
    let resp1 = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", &session_id)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", ts.to_string())
        .header("x-ais-integrity-mac", &mac0)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 401, "replayed sequence → 401");
}

#[tokio::test]
async fn test_full_proxy_flow_with_mock_backend() {
    let backend_url = start_mock_backend().await;
    let (proxy_url, state) = start_proxy(&backend_url).await;
    let client = Client::new();

    let (session_id, key) = create_session(&client, &proxy_url).await;

    let body = br#"{"model":"test","messages":[{"role":"user","content":"hi"}]}"#;
    let ts = 1_700_000_000u64;
    let mac = compute_mac(&session_id, 0, ts, body, &key);

    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", &session_id)
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", ts.to_string())
        .header("x-ais-integrity-mac", &mac)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "valid request should be forwarded");

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["id"], "mock-response", "backend response forwarded");

    // Audit chain should have one entry.
    let chain = state.audit_chain.lock().unwrap();
    assert_eq!(chain.entries().len(), 1, "one audit entry recorded");
    chain.validate_chain().expect("audit chain must be valid");
}

#[tokio::test]
async fn test_monotonic_sequence_advances() {
    let backend_url = start_mock_backend().await;
    let (proxy_url, state) = start_proxy(&backend_url).await;
    let client = Client::new();

    let (session_id, key) = create_session(&client, &proxy_url).await;

    let body = br#"{"model":"test","messages":[]}"#;
    let ts = 1_700_000_000u64;

    for seq in 0u64..3 {
        let mac = compute_mac(&session_id, seq, ts, body, &key);

        let resp = client
            .post(format!("{proxy_url}/v1/chat/completions"))
            .header("x-ais-session-id", &session_id)
            .header("x-ais-sequence", seq.to_string())
            .header("x-ais-timestamp", ts.to_string())
            .header("x-ais-integrity-mac", &mac)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200, "sequence {seq} should succeed");
    }

    // Skip sequence 3, try sequence 4 — must be rejected (out-of-order).
    let mac4 = compute_mac(&session_id, 4, ts, body, &key);
    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", &session_id)
        .header("x-ais-sequence", "4")
        .header("x-ais-timestamp", ts.to_string())
        .header("x-ais-integrity-mac", &mac4)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "out-of-order sequence → 401");

    // Audit chain should have exactly 3 entries (the successful ones).
    let chain = state.audit_chain.lock().unwrap();
    assert_eq!(chain.entries().len(), 3);
    chain.validate_chain().expect("audit chain must be valid");
}

#[tokio::test]
async fn test_malformed_hex_session_id_rejected() {
    let (proxy_url, _state) = start_proxy("http://localhost:1").await;
    let client = Client::new();

    let resp = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("x-ais-session-id", "not-valid-hex!!")
        .header("x-ais-sequence", "0")
        .header("x-ais-timestamp", "1700000000")
        .header("x-ais-integrity-mac", hex::encode([0u8; 32]))
        .header("Content-Type", "application/json")
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "malformed hex → 400");
}
