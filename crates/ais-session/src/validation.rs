//! AIS session and frame validation.

use crate::error::SessionError;
use crate::frame::{verify_frame_integrity, AISFrame, IntegrityKey};
use crate::session::{Session, SessionState};

/// Validates that a session is active.
pub fn validate_session(session: &Session) -> Result<(), SessionError> {
    if session.state == SessionState::Active {
        Ok(())
    } else {
        Err(SessionError::SessionNotActive)
    }
}

/// Validates a frame against session state, session id, sequence, and MAC.
///
/// Sequence is accepted only after all earlier checks pass, so failed frames do
/// not advance replay protection state.
pub fn validate_frame(
    session: &mut Session,
    frame: &AISFrame,
    integrity_key: &IntegrityKey,
) -> Result<(), SessionError> {
    validate_session(session)?;

    if frame.session_id != session.id {
        return Err(SessionError::InvalidSessionId);
    }

    if frame.sequence != session.sequence_counter.expected() {
        return Err(SessionError::InvalidSequence);
    }

    verify_frame_integrity(frame, integrity_key)?;
    session.sequence_counter.accept(frame.sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::create_frame;
    use crate::session::{generate_integrity_key, Session, SessionId};

    fn active_session() -> (Session, IntegrityKey) {
        let mut session = Session::new(SessionId::from_bytes([1u8; 16]));
        session.activate();
        (session, generate_integrity_key())
    }

    #[test]
    fn active_session_accepts_valid_frame() {
        let (mut session, key) = active_session();
        let frame = create_frame(session.id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        validate_frame(&mut session, &frame, &key).expect("frame should validate");

        assert_eq!(session.sequence_counter.expected(), 1);
    }

    #[test]
    fn validation_rejects_replayed_frame() {
        let (mut session, key) = active_session();
        let frame = create_frame(session.id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        validate_frame(&mut session, &frame, &key).expect("frame should validate");

        assert_eq!(
            validate_frame(&mut session, &frame, &key),
            Err(SessionError::InvalidSequence)
        );
    }

    #[test]
    fn validation_rejects_future_sequence() {
        let (mut session, key) = active_session();
        let frame = create_frame(session.id, 2, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        assert_eq!(
            validate_frame(&mut session, &frame, &key),
            Err(SessionError::InvalidSequence)
        );
    }

    #[test]
    fn validation_rejects_terminated_session() {
        let (mut session, key) = active_session();
        session.terminate();
        let frame = create_frame(session.id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        assert_eq!(
            validate_frame(&mut session, &frame, &key),
            Err(SessionError::SessionNotActive)
        );
    }

    #[test]
    fn validation_rejects_wrong_session_id() {
        let (mut session, key) = active_session();
        let frame = create_frame(
            SessionId::from_bytes([2u8; 16]),
            0,
            1_700_000_000,
            b"payload".to_vec(),
            &key,
        )
        .expect("frame should be created");

        assert_eq!(
            validate_frame(&mut session, &frame, &key),
            Err(SessionError::InvalidSessionId)
        );
    }

    #[test]
    fn invalid_mac_does_not_advance_sequence() {
        let (mut session, key) = active_session();
        let wrong_key = [9u8; 32];
        let frame = create_frame(session.id, 0, 1_700_000_000, b"payload".to_vec(), &key)
            .expect("frame should be created");

        assert_eq!(
            validate_frame(&mut session, &frame, &wrong_key),
            Err(SessionError::IntegrityVerificationFailed)
        );
        assert_eq!(session.sequence_counter.expected(), 0);
    }
}
