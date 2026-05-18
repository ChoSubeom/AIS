fn main() -> Result<(), ais_audit::AuditError> {
    let mut chain = ais_audit::AuditChain::new();

    let entry = ais_audit::AuditEntry::new(
        ais_audit::generate_audit_id(),
        1_700_000_000,
        [1u8; 16],
        ais_crypto::sha3_256(b"request"),
        ais_audit::ResponseStatus::Ok,
        chain.latest_hash(),
    )?;

    chain.append(entry)?;
    chain.validate_chain()?;

    println!("audit chain validated");
    Ok(())
}
