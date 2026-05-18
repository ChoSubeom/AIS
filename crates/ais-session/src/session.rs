//! Session identifiers, state, nonces, and sequence counters.

use ais_crypto::secure_random_bytes;

use crate::error::SessionError;

/// Current AIS session frame version.
pub const AIS_SESSION_VERSION: u16 = 1;

/// Session identifier length in bytes.
pub const SESSION_ID_LENGTH: usize = 16;

/// Nonce length in bytes.
pub const NONCE_LENGTH: usize = 32;

/// Integrity key length in bytes.
pub const INTEGRITY_KEY_LENGTH: usize = 32;

/// Fixed-size AIS session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId {
    bytes: [u8; SESSION_ID_LENGTH],
}

impl SessionId {
    /// Generates a new session identifier using OS secure randomness.
    pub fn generate() -> Self {
        Self {
            bytes: secure_random_bytes::<SESSION_ID_LENGTH>(),
        }
    }

    /// Builds a session identifier from raw bytes.
    pub fn from_bytes(bytes: [u8; SESSION_ID_LENGTH]) -> Self {
        Self { bytes }
    }

    /// Returns the raw session identifier bytes.
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_LENGTH] {
        &self.bytes
    }
}

/// Explicit AIS session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session has been created but is not accepting frames yet.
    Created,
    /// Session is active and accepting frames.
    Active,
    /// Session has expired and must reject frames.
    Expired,
    /// Session has terminated and must reject frames.
    Terminated,
}

/// Monotonic session sequence counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceCounter {
    next_sequence: u64,
}

impl SequenceCounter {
    /// Creates a sequence counter starting at sequence `0`.
    pub fn new() -> Self {
        Self { next_sequence: 0 }
    }

    /// Returns the next expected sequence.
    pub fn expected(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the next outbound sequence and increments the counter.
    pub fn next_sequence(&mut self) -> Result<u64, SessionError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(SessionError::SequenceOverflow)?;
        Ok(sequence)
    }

    /// Accepts an inbound sequence if it matches the next expected value.
    pub fn accept(&mut self, sequence: u64) -> Result<(), SessionError> {
        if sequence != self.next_sequence {
            return Err(SessionError::InvalidSequence);
        }

        self.next_sequence()?;
        Ok(())
    }
}

impl Default for SequenceCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal single-session state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Session identifier.
    pub id: SessionId,
    /// Current session state.
    pub state: SessionState,
    /// Monotonic sequence counter.
    pub sequence_counter: SequenceCounter,
}

impl Session {
    /// Creates a new session in the `Created` state.
    pub fn new(id: SessionId) -> Self {
        Self {
            id,
            state: SessionState::Created,
            sequence_counter: SequenceCounter::new(),
        }
    }

    /// Marks the session as active.
    pub fn activate(&mut self) {
        self.state = SessionState::Active;
    }

    /// Marks the session as expired.
    pub fn expire(&mut self) {
        self.state = SessionState::Expired;
    }

    /// Marks the session as terminated.
    pub fn terminate(&mut self) {
        self.state = SessionState::Terminated;
    }
}

/// Generates a secure random nonce.
pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    secure_random_bytes::<NONCE_LENGTH>()
}

/// Generates a secure random integrity key for local tests or examples.
///
/// Real deployments should bind this key to a deterministic handshake result.
pub fn generate_integrity_key() -> [u8; INTEGRITY_KEY_LENGTH] {
    secure_random_bytes::<INTEGRITY_KEY_LENGTH>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_fixed_size() {
        let session_id = SessionId::generate();

        assert_eq!(session_id.as_bytes().len(), SESSION_ID_LENGTH);
    }

    #[test]
    fn nonce_is_fixed_size() {
        let nonce = generate_nonce();

        assert_eq!(nonce.len(), NONCE_LENGTH);
    }

    #[test]
    fn sequence_counter_is_monotonic() {
        let mut counter = SequenceCounter::new();

        assert_eq!(counter.next_sequence().expect("sequence should advance"), 0);
        assert_eq!(counter.next_sequence().expect("sequence should advance"), 1);
        assert_eq!(counter.expected(), 2);
    }

    #[test]
    fn sequence_counter_rejects_replay() {
        let mut counter = SequenceCounter::new();

        counter.accept(0).expect("first sequence should pass");

        assert_eq!(counter.accept(0), Err(SessionError::InvalidSequence));
    }

    #[test]
    fn sequence_counter_detects_overflow() {
        let mut counter = SequenceCounter {
            next_sequence: u64::MAX,
        };

        assert_eq!(counter.next_sequence(), Err(SessionError::SequenceOverflow));
    }
}
