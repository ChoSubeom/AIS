//! Append-only AIS audit chain.

use crate::entry::{verify_entry_hash, AuditEntry, AuditHash, EMPTY_AUDIT_HASH};
use crate::error::AuditError;

/// Minimal append-only audit chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditChain {
    entries: Vec<AuditEntry>,
}

impl AuditChain {
    /// Creates an empty audit chain.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends an entry if it links to the current chain head.
    ///
    /// The entry hash is verified before the entry is appended.
    pub fn append(&mut self, entry: AuditEntry) -> Result<(), AuditError> {
        verify_entry_hash(&entry)?;

        if entry.prev_hash != self.latest_hash() {
            return Err(AuditError::PreviousHashMismatch);
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Returns the current chain head hash.
    pub fn latest_hash(&self) -> AuditHash {
        self.entries
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or(EMPTY_AUDIT_HASH)
    }

    /// Returns audit entries in append order.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Validates the full audit chain deterministically.
    pub fn validate_chain(&self) -> Result<(), AuditError> {
        let mut expected_prev_hash = EMPTY_AUDIT_HASH;

        for entry in &self.entries {
            if entry.prev_hash != expected_prev_hash {
                return Err(AuditError::PreviousHashMismatch);
            }

            verify_entry_hash(entry)?;
            expected_prev_hash = entry.entry_hash;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{AuditEntry, ResponseStatus};
    use ais_crypto::sha3_256;

    fn entry(prev_hash: AuditHash, audit_id_byte: u8) -> AuditEntry {
        AuditEntry::new(
            [audit_id_byte; 16],
            1_700_000_000 + u64::from(audit_id_byte),
            [2u8; 16],
            sha3_256(&[audit_id_byte]),
            ResponseStatus::Ok,
            prev_hash,
        )
        .expect("entry should build")
    }

    #[test]
    fn empty_chain_latest_hash_is_zero() {
        let chain = AuditChain::new();

        assert_eq!(chain.latest_hash(), EMPTY_AUDIT_HASH);
    }

    #[test]
    fn append_updates_latest_hash() {
        let mut chain = AuditChain::new();
        let entry = entry(chain.latest_hash(), 1);
        let expected_hash = entry.entry_hash;

        chain.append(entry).expect("entry should append");

        assert_eq!(chain.latest_hash(), expected_hash);
    }

    #[test]
    fn append_rejects_wrong_previous_hash() {
        let mut chain = AuditChain::new();
        let entry = entry([9u8; 32], 1);

        assert_eq!(chain.append(entry), Err(AuditError::PreviousHashMismatch));
    }

    #[test]
    fn validate_chain_accepts_valid_chain() {
        let mut chain = AuditChain::new();
        let first = entry(chain.latest_hash(), 1);
        chain.append(first).expect("first entry should append");
        let second = entry(chain.latest_hash(), 2);
        chain.append(second).expect("second entry should append");

        chain.validate_chain().expect("chain should validate");
    }

    #[test]
    fn validate_chain_rejects_tampered_entry() {
        let mut chain = AuditChain::new();
        let first = entry(chain.latest_hash(), 1);
        chain.append(first).expect("first entry should append");
        chain.entries[0].response_status = ResponseStatus::InternalError;

        assert_eq!(chain.validate_chain(), Err(AuditError::EntryHashMismatch));
    }

    #[test]
    fn validate_chain_rejects_broken_link() {
        let mut chain = AuditChain::new();
        let first = entry(chain.latest_hash(), 1);
        chain.append(first).expect("first entry should append");
        let second = entry(chain.latest_hash(), 2);
        chain.append(second).expect("second entry should append");
        chain.entries[1].prev_hash = [8u8; 32];

        assert_eq!(
            chain.validate_chain(),
            Err(AuditError::PreviousHashMismatch)
        );
    }
}
