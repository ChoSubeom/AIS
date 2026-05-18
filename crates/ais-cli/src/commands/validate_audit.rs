//! `validate-audit` command implementation.

use ais_audit::{AuditChain, AuditEntry, ResponseStatus};
use serde::Deserialize;

use crate::cli::ValidateAuditArgs;
use crate::commands::sign_model::read_file;
use crate::error::CliError;

#[derive(Deserialize)]
struct StoredAuditEntry(Vec<u8>, u64, Vec<u8>, Vec<u8>, u8, Vec<u8>, Vec<u8>);

/// Runs the `validate-audit` command.
pub fn run(args: ValidateAuditArgs) -> Result<(), CliError> {
    let input = read_file(&args.input)?;
    let chain = decode_audit_chain(&input)?;

    chain.validate_chain()?;

    Ok(())
}

pub(crate) fn decode_audit_chain(bytes: &[u8]) -> Result<AuditChain, CliError> {
    let stored_entries: Vec<StoredAuditEntry> =
        ciborium::de::from_reader(bytes).map_err(|_| CliError::DeserializationFailed)?;
    let mut chain = AuditChain::new();

    for entry in stored_entries {
        chain.append(decode_entry(entry)?)?;
    }

    Ok(chain)
}

fn decode_entry(entry: StoredAuditEntry) -> Result<AuditEntry, CliError> {
    let StoredAuditEntry(
        audit_id,
        timestamp,
        session_id,
        request_hash,
        response_status,
        prev_hash,
        entry_hash,
    ) = entry;

    Ok(AuditEntry {
        audit_id: fixed_16(audit_id, "audit_id")?,
        timestamp,
        session_id: fixed_16(session_id, "session_id")?,
        request_hash: fixed_32(request_hash, "request_hash")?,
        response_status: decode_status(response_status)?,
        prev_hash: fixed_32(prev_hash, "prev_hash")?,
        entry_hash: fixed_32(entry_hash, "entry_hash")?,
    })
}

fn decode_status(code: u8) -> Result<ResponseStatus, CliError> {
    match code {
        0 => Ok(ResponseStatus::Ok),
        1 => Ok(ResponseStatus::AttestationFailed),
        2 => Ok(ResponseStatus::SessionExpired),
        3 => Ok(ResponseStatus::SequenceError),
        4 => Ok(ResponseStatus::InternalError),
        _ => Err(CliError::InvalidResponseStatus),
    }
}

fn fixed_16(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 16], CliError> {
    bytes
        .try_into()
        .map_err(|_| CliError::InvalidLength { field })
}

fn fixed_32(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 32], CliError> {
    bytes
        .try_into()
        .map_err(|_| CliError::InvalidLength { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ais_audit::{AuditEntry, EMPTY_AUDIT_HASH};
    use ais_crypto::sha3_256;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestStoredAuditEntry(Vec<u8>, u64, Vec<u8>, Vec<u8>, u8, Vec<u8>, Vec<u8>);

    #[test]
    fn valid_audit_chain_decodes() {
        let entry = AuditEntry::new(
            [1u8; 16],
            1_700_000_000,
            [2u8; 16],
            sha3_256(b"request"),
            ResponseStatus::Ok,
            EMPTY_AUDIT_HASH,
        )
        .expect("entry should build");
        let stored = vec![TestStoredAuditEntry(
            entry.audit_id.to_vec(),
            entry.timestamp,
            entry.session_id.to_vec(),
            entry.request_hash.to_vec(),
            0,
            entry.prev_hash.to_vec(),
            entry.entry_hash.to_vec(),
        )];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&stored, &mut bytes).expect("audit chain should encode");

        let chain = decode_audit_chain(&bytes).expect("audit chain should decode");

        assert_eq!(chain.entries().len(), 1);
    }

    #[test]
    fn tampered_audit_chain_fails_closed() {
        let mut entry = AuditEntry::new(
            [1u8; 16],
            1_700_000_000,
            [2u8; 16],
            sha3_256(b"request"),
            ResponseStatus::Ok,
            EMPTY_AUDIT_HASH,
        )
        .expect("entry should build");
        entry.timestamp += 1;
        let stored = vec![TestStoredAuditEntry(
            entry.audit_id.to_vec(),
            entry.timestamp,
            entry.session_id.to_vec(),
            entry.request_hash.to_vec(),
            0,
            entry.prev_hash.to_vec(),
            entry.entry_hash.to_vec(),
        )];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&stored, &mut bytes).expect("audit chain should encode");

        assert!(decode_audit_chain(&bytes).is_err());
    }
}
