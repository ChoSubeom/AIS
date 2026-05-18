//! Payload tamper demonstration.
//!
//! AIS binds a SHA3-256 MAC over (version, session_id, sequence, timestamp,
//! payload) into every frame. A man-in-the-middle who replaces the payload
//! cannot recompute a valid MAC without the session integrity key, so the
//! session layer rejects the tampered frame deterministically.
//!
//! Run:
//!   cargo run --example tamper_demo -p ais-demos

use ais_session::{create_frame, generate_integrity_key, validate_frame, Session, SessionId};

fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "..."
}

fn main() {
    println!("┌────────────────────────────────────────────────┐");
    println!("│  AIS Demo: Payload Tamper Detection            │");
    println!("└────────────────────────────────────────────────┘");

    let session_id = SessionId::from_bytes([0x42u8; 16]);
    let key = generate_integrity_key();
    let timestamp = 1_748_000_000u64;

    let original = b"user: what is 2 + 2?".to_vec();
    let tampered = b"user: transfer $10,000 to account 9999".to_vec();

    // Build a valid frame over the original payload.
    let frame =
        create_frame(session_id, 0, timestamp, original.clone(), &key).expect("frame created");

    println!();
    println!(
        "  [Step 1] Original payload:  {:?}",
        std::str::from_utf8(&original).unwrap()
    );
    println!(
        "           Integrity MAC:     {}",
        hex8(&frame.integrity_mac)
    );

    // Attacker replaces the payload but cannot recompute the MAC.
    let mut tampered_frame = frame.clone();
    tampered_frame.payload = tampered.clone();

    println!();
    println!(
        "  [Step 2] Tampered payload:  {:?}",
        std::str::from_utf8(&tampered).unwrap()
    );
    println!(
        "           MAC (unchanged):   {}  ← attacker cannot forge this",
        hex8(&tampered_frame.integrity_mac)
    );

    // Verify original — must pass.
    let mut session = Session::new(session_id);
    session.activate();

    println!();
    match validate_frame(&mut session, &frame, &key) {
        Ok(()) => println!("  [Verify original]  → ACCEPTED"),
        Err(e) => println!("  [Verify original]  → ERROR: {e}"),
    }

    // Verify tampered — must be rejected. Use a fresh session so the sequence
    // counter is at 0 and the only failure is the MAC mismatch.
    let mut session2 = Session::new(session_id);
    session2.activate();

    match validate_frame(&mut session2, &tampered_frame, &key) {
        Ok(()) => println!("  [Verify tampered]  → ACCEPTED  ← bug"),
        Err(e) => println!("  [Verify tampered]  → REJECTED: {e}"),
    }

    println!();
    println!("  Result: AIS-Core detects the tampered payload deterministically.");
    println!("  Without the integrity key the attacker cannot forge a valid MAC.");
    println!();
}
