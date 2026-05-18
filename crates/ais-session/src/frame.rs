//! AIS authenticated session frame support.

use ais_crypto::sha3_256;
use serde::Serialize;

use crate::error::SessionError;
use crate::session::{SessionId, AIS_SESSION_VERSION};

/// SHA3-256 based integrity key.
pub type IntegrityKey = [u8; 32];

/// Minimal AIS authenticated frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AISFrame {
    /// Frame format version.
    pub version: u16,
    /// Session identifier.
    pub session_id: SessionId,
    /// Monotonic session sequence.
    pub sequence: u64,
    /// Caller-supplied timestamp.
    pub timestamp: u64,
    /// Authenticated payload bytes.
    pub payload: Vec<u8>,
    /// SHA3-256 integrity MAC.
    pub integrity_mac: [u8; 32],
}

#[derive(Serialize)]
struct FrameMacPayload<'a>(u16, &'a [u8; 16], u64, u64, &'a [u8]);

#[derive(Serialize)]
struct SerializedFrame<'a>(u16, &'a [u8; 16], u64, u64, &'a [u8], &'a [u8; 32]);

/// Creates an authenticated frame with a SHA3-256 integrity MAC.
pub fn create_frame(
    session_id: SessionId,
    sequence: u64,
    timestamp: u64,
    payload: Vec<u8>,
    integrity_key: &IntegrityKey,
) -> Result<AISFrame, SessionError> {
    let mut frame = AISFrame {
        version: AIS_SESSION_VERSION,
        session_id,
        sequence,
        timestamp,
        payload,
        integrity_mac: [0u8; 32],
    };
    frame.integrity_mac = compute_integrity_mac(&frame, integrity_key)?;
    Ok(frame)
}

/// Serializes a complete frame with deterministic CBOR field ordering.
pub fn serialize_frame(frame: &AISFrame) -> Result<Vec<u8>, SessionError> {
    let serialized = SerializedFrame(
        frame.version,
        frame.session_id.as_bytes(),
        frame.sequence,
        frame.timestamp,
        &frame.payload,
        &frame.integrity_mac,
    );

    let mut output = Vec::new();
    ciborium::ser::into_writer(&serialized, &mut output)
        .map_err(|_| SessionError::SerializationFailed)?;
    Ok(output)
}

/// Computes the SHA3-256 integrity MAC for a frame.
///
/// The MAC covers all frame fields except `integrity_mac`, plus the integrity
/// key supplied by the caller.
pub fn compute_integrity_mac(
    frame: &AISFrame,
    integrity_key: &IntegrityKey,
) -> Result<[u8; 32], SessionError> {
    let payload = FrameMacPayload(
        frame.version,
        frame.session_id.as_bytes(),
        frame.sequence,
        frame.timestamp,
        &frame.payload,
    );

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded)
        .map_err(|_| SessionError::SerializationFailed)?;
    encoded.extend_from_slice(integrity_key);

    Ok(sha3_256(&encoded))
}

/// Verifies the frame integrity MAC.
pub fn verify_frame_integrity(
    frame: &AISFrame,
    integrity_key: &IntegrityKey,
) -> Result<(), SessionError> {
    let expected = compute_integrity_mac(frame, integrity_key)?;
    if expected == frame.integrity_mac {
        Ok(())
    } else {
        Err(SessionError::IntegrityVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{generate_integrity_key, SessionId};

    #[test]
    fn frame_serialization_is_deterministic() {
        let key = generate_integrity_key();
        let session_id = SessionId::from_bytes([1u8; 16]);
        let frame = create_frame(session_id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        let first = serialize_frame(&frame).expect("frame should serialize");
        let second = serialize_frame(&frame).expect("frame should serialize");

        assert_eq!(first, second);
    }

    #[test]
    fn frame_integrity_verifies() {
        let key = generate_integrity_key();
        let session_id = SessionId::from_bytes([1u8; 16]);
        let frame = create_frame(session_id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        verify_frame_integrity(&frame, &key).expect("frame should verify");
    }

    #[test]
    fn frame_integrity_fails_for_changed_payload() {
        let key = generate_integrity_key();
        let session_id = SessionId::from_bytes([1u8; 16]);
        let mut frame = create_frame(session_id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");
        frame.payload = b"changed".to_vec();

        assert_eq!(
            verify_frame_integrity(&frame, &key),
            Err(SessionError::IntegrityVerificationFailed)
        );
    }
}
