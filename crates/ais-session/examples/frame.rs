fn main() -> Result<(), ais_session::SessionError> {
    let mut session = ais_session::Session::new(ais_session::SessionId::generate());
    session.activate();

    let integrity_key = ais_session::generate_integrity_key();
    let sequence = session.sequence_counter.expected();
    let frame = ais_session::create_frame(
        session.id,
        sequence,
        1_700_000_000,
        b"request payload".to_vec(),
        &integrity_key,
    )?;

    ais_session::validate_frame(&mut session, &frame, &integrity_key)?;

    println!("frame verified");
    Ok(())
}
