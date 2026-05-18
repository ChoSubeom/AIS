//! Replay attack demonstration.
//!
//! Without AIS there is no replay protection: a client can resubmit the same
//! request bytes and the server accepts it every time.
//!
//! With AIS every frame carries a monotonic sequence counter bound into the
//! SHA3-256 integrity MAC. The session layer rejects any frame whose sequence
//! has already been consumed, deterministically.
//!
//! Run:
//!   cargo run --example replay_attack_demo -p ais-demos

use ais_session::{create_frame, generate_integrity_key, validate_frame, Session, SessionId};

fn main() {
    println!("┌────────────────────────────────────────────────┐");
    println!("│  AIS Demo: Replay Attack Protection            │");
    println!("└────────────────────────────────────────────────┘");

    let request = b"POST /inference  {prompt: \"hello\"}";

    // ── Without AIS ──────────────────────────────────────────────────────────

    println!();
    println!("  WITHOUT AIS (no replay protection)");
    println!("  ───────────────────────────────────");
    println!(
        "  [Request 1]  payload = {:?}",
        std::str::from_utf8(request).unwrap()
    );
    println!("               result  = ACCEPTED");
    println!();

    // No state exists to detect the replay — the bytes go through unchanged.
    println!(
        "  [Replay]     payload = {:?}  (identical bytes)",
        std::str::from_utf8(request).unwrap()
    );
    println!("               result  = ACCEPTED  ← replay succeeds");

    // ── With AIS ─────────────────────────────────────────────────────────────

    println!();
    println!("  WITH AIS (monotonic sequence counter + MAC)");
    println!("  ────────────────────────────────────────────");

    let session_id = SessionId::from_bytes([0x41u8; 16]);
    let key = generate_integrity_key();
    let timestamp = 1_748_000_000u64;

    let mut session = Session::new(session_id);
    session.activate();

    // First request at sequence 0.
    let frame0 =
        create_frame(session_id, 0, timestamp, request.to_vec(), &key).expect("frame 0 created");

    match validate_frame(&mut session, &frame0, &key) {
        Ok(()) => println!("  [Request 1]  sequence=0, MAC ok → ACCEPTED"),
        Err(e) => println!("  [Request 1]  ERROR: {e}"),
    }

    // Replay: same frame, same sequence 0 — session has already consumed it.
    match validate_frame(&mut session, &frame0, &key) {
        Ok(()) => println!("  [Replay]     sequence=0         → ACCEPTED  ← bug"),
        Err(e) => println!("  [Replay]     sequence=0         → REJECTED: {e}"),
    }

    // Legitimate second request at sequence 1.
    let frame1 =
        create_frame(session_id, 1, timestamp, request.to_vec(), &key).expect("frame 1 created");

    match validate_frame(&mut session, &frame1, &key) {
        Ok(()) => println!("  [Request 2]  sequence=1, MAC ok → ACCEPTED"),
        Err(e) => println!("  [Request 2]  ERROR: {e}"),
    }

    println!();
    println!("  Result: AIS-Core rejects the replay deterministically.");
    println!("  No probabilistic classifier involved — pure sequence arithmetic.");
    println!();
}
