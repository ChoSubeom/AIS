//! POST /v1/chat/completions — AIS-validated OpenAI-compatible inference proxy.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use ais_audit::{generate_audit_id, AuditEntry, ResponseStatus};
use ais_crypto::sha3_256;
use ais_session::{validate_frame, AISFrame, SessionId, AIS_SESSION_VERSION};

use crate::error::ProxyError;
use crate::state::AppState;

/// Parses a hex header value into a fixed-size byte array.
fn parse_hex_header<const N: usize>(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<[u8; N], ProxyError> {
    let value = headers
        .get(name)
        .ok_or_else(|| ProxyError::MalformedRequest(format!("missing header: {name}")))?
        .to_str()
        .map_err(|_| ProxyError::MalformedRequest(format!("invalid header encoding: {name}")))?;

    let bytes = hex::decode(value)
        .map_err(|_| ProxyError::MalformedRequest(format!("invalid hex in header: {name}")))?;

    if bytes.len() != N {
        return Err(ProxyError::MalformedRequest(format!(
            "header {name} must be {N} bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parses a decimal u64 header value.
fn parse_u64_header(headers: &HeaderMap, name: &'static str) -> Result<u64, ProxyError> {
    headers
        .get(name)
        .ok_or_else(|| ProxyError::MalformedRequest(format!("missing header: {name}")))?
        .to_str()
        .map_err(|_| ProxyError::MalformedRequest(format!("invalid header encoding: {name}")))?
        .parse::<u64>()
        .map_err(|_| ProxyError::MalformedRequest(format!("invalid u64 in header: {name}")))
}

/// Validates an AIS-framed request and forwards it to the upstream backend.
///
/// Request flow:
///   client request
///   → parse AIS headers
///   → session lookup + frame integrity validation (fail-closed)
///   → forward body to backend
///   → append audit entry
///   → return backend response
pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProxyError> {
    // Parse AIS framing headers.
    let session_id_bytes: [u8; 16] = parse_hex_header(&headers, "x-ais-session-id")?;
    let sequence = parse_u64_header(&headers, "x-ais-sequence")?;
    let timestamp = parse_u64_header(&headers, "x-ais-timestamp")?;
    let integrity_mac: [u8; 32] = parse_hex_header(&headers, "x-ais-integrity-mac")?;

    // Construct the frame from parsed headers and request body.
    let frame = AISFrame {
        version: AIS_SESSION_VERSION,
        session_id: SessionId::from_bytes(session_id_bytes),
        sequence,
        timestamp,
        payload: body.to_vec(),
        integrity_mac,
    };

    // Validate session and frame (advances sequence counter only on success).
    {
        let mut sessions = state.sessions.lock().expect("session lock poisoned");
        let entry = sessions
            .get_mut(&session_id_bytes)
            .ok_or(ProxyError::SessionNotFound)?;
        validate_frame(&mut entry.session, &frame, &entry.integrity_key)
            .map_err(ProxyError::from)?;
    }

    // Compute request hash for the audit entry.
    let request_hash = sha3_256(&body);

    // Forward the request to the upstream backend.
    let backend_url = format!("{}/v1/chat/completions", state.config.backend_url);
    let mut req = state.client.post(&backend_url).body(body.to_vec());

    // Forward the Authorization header if present.
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            req = req.header("Authorization", auth_str);
        }
    }
    req = req.header("Content-Type", "application/json");

    let (ais_status, http_status, response_body) = match req.send().await {
        Ok(resp) => {
            let http_status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let ais_status = if resp.status().is_success() {
                ResponseStatus::Ok
            } else {
                ResponseStatus::InternalError
            };
            let body_bytes = resp.bytes().await.map_err(|_| ProxyError::BackendError)?;
            (ais_status, http_status, body_bytes)
        }
        Err(_) => (
            ResponseStatus::InternalError,
            StatusCode::BAD_GATEWAY,
            Bytes::from_static(b"{\"error\":\"backend unavailable\"}"),
        ),
    };

    // Append audit entry regardless of backend outcome.
    let audit_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    {
        let mut chain = state.audit_chain.lock().expect("audit chain lock poisoned");
        let prev_hash = chain.latest_hash();
        let audit_id = generate_audit_id();
        let entry = AuditEntry::new(
            audit_id,
            audit_timestamp,
            session_id_bytes,
            request_hash,
            ais_status,
            prev_hash,
        )
        .map_err(|_| ProxyError::InternalError)?;
        chain.append(entry).map_err(|_| ProxyError::InternalError)?;
    }

    Ok((http_status, response_body).into_response())
}
