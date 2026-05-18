use std::path::{Path, PathBuf};
use std::process::Command;

use ais_audit::{AuditChain, AuditEntry, ResponseStatus, EMPTY_AUDIT_HASH};
use ais_crypto::sha3_256;
use ais_session::{create_frame, serialize_frame, validate_frame, AISFrame, Session, SessionId};
use serde::Serialize;

#[derive(Serialize)]
struct StoredAuditEntry(Vec<u8>, u64, Vec<u8>, Vec<u8>, u8, Vec<u8>, Vec<u8>);

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_ais-cli")
}

fn test_dir(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../target/ais-test-tmp");
    path.push(format!("{}-{}", name, std::process::id()));

    if path.exists() {
        std::fs::remove_dir_all(&path).expect("test dir should be removable");
    }
    std::fs::create_dir_all(&path).expect("test dir should be creatable");
    path
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("test file should be writable");
}

fn fixed_issuer_key() -> [u8; 32] {
    [7u8; 32]
}

fn run_success(args: &[&str]) {
    let output = Command::new(cli())
        .args(args)
        .output()
        .expect("ais-cli should run");

    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_failure(args: &[&str]) {
    let output = Command::new(cli())
        .args(args)
        .output()
        .expect("ais-cli should run");

    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sign_model(dir: &Path, model_bytes: &[u8]) -> (PathBuf, PathBuf, PathBuf) {
    let model = dir.join("model.gguf");
    let issuer = dir.join("issuer.key");
    let cert = dir.join("model.cert");

    write(&model, model_bytes);
    write(&issuer, &fixed_issuer_key());

    run_success(&[
        "sign-model",
        "--model",
        model.to_str().expect("model path should be utf-8"),
        "--issuer",
        issuer.to_str().expect("issuer path should be utf-8"),
        "--output",
        cert.to_str().expect("cert path should be utf-8"),
    ]);

    (model, issuer, cert)
}

fn audit_chain_bytes(entries: &[AuditEntry]) -> Vec<u8> {
    let stored: Vec<StoredAuditEntry> = entries
        .iter()
        .map(|entry| {
            StoredAuditEntry(
                entry.audit_id.to_vec(),
                entry.timestamp,
                entry.session_id.to_vec(),
                entry.request_hash.to_vec(),
                response_status_code(entry.response_status),
                entry.prev_hash.to_vec(),
                entry.entry_hash.to_vec(),
            )
        })
        .collect();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&stored, &mut bytes).expect("audit chain should encode");
    bytes
}

fn response_status_code(status: ResponseStatus) -> u8 {
    match status {
        ResponseStatus::Ok => 0,
        ResponseStatus::AttestationFailed => 1,
        ResponseStatus::SessionExpired => 2,
        ResponseStatus::SequenceError => 3,
        ResponseStatus::InternalError => 4,
    }
}

fn valid_audit_entries() -> Vec<AuditEntry> {
    let first = AuditEntry::new(
        [1u8; 16],
        1_700_000_000,
        [2u8; 16],
        sha3_256(b"request-1"),
        ResponseStatus::Ok,
        EMPTY_AUDIT_HASH,
    )
    .expect("entry should build");
    let second = AuditEntry::new(
        [3u8; 16],
        1_700_000_001,
        [2u8; 16],
        sha3_256(b"request-2"),
        ResponseStatus::InternalError,
        first.entry_hash,
    )
    .expect("entry should build");

    vec![first, second]
}

#[test]
fn end_to_end_model_sign_and_verify_succeeds() {
    let dir = test_dir("end-to-end-model");
    let (model, _, cert) = sign_model(&dir, b"deterministic model bytes");

    run_success(&[
        "verify-model",
        "--model",
        model.to_str().expect("model path should be utf-8"),
        "--cert",
        cert.to_str().expect("cert path should be utf-8"),
    ]);
}

#[test]
fn tampered_model_bytes_fail_closed() {
    let dir = test_dir("tampered-model");
    let (model, _, cert) = sign_model(&dir, b"deterministic model bytes");
    write(&model, b"modified model bytes");

    run_failure(&[
        "verify-model",
        "--model",
        model.to_str().expect("model path should be utf-8"),
        "--cert",
        cert.to_str().expect("cert path should be utf-8"),
    ]);
}

#[test]
fn modified_certificate_bytes_fail_closed() {
    let dir = test_dir("modified-cert");
    let (model, _, cert) = sign_model(&dir, b"deterministic model bytes");
    let mut cert_bytes = std::fs::read(&cert).expect("cert should be readable");
    cert_bytes[0] ^= 0x7f;
    write(&cert, &cert_bytes);

    run_failure(&[
        "verify-model",
        "--model",
        model.to_str().expect("model path should be utf-8"),
        "--cert",
        cert.to_str().expect("cert path should be utf-8"),
    ]);
}

#[test]
fn modified_signature_fails_closed() {
    let dir = test_dir("modified-signature");
    let (model, _, cert) = sign_model(&dir, b"deterministic model bytes");
    let mut cert_bytes = std::fs::read(&cert).expect("cert should be readable");
    let last = cert_bytes.len() - 1;
    cert_bytes[last] ^= 1;
    write(&cert, &cert_bytes);

    run_failure(&[
        "verify-model",
        "--model",
        model.to_str().expect("model path should be utf-8"),
        "--cert",
        cert.to_str().expect("cert path should be utf-8"),
    ]);
}

#[test]
fn modified_audit_entry_fails_closed() {
    let mut chain = AuditChain::new();
    let entry = AuditEntry::new(
        [1u8; 16],
        1_700_000_000,
        [2u8; 16],
        sha3_256(b"request"),
        ResponseStatus::Ok,
        chain.latest_hash(),
    )
    .expect("entry should build");
    chain.append(entry).expect("entry should append");
    let mut tampered = chain.entries()[0].clone();
    tampered.timestamp += 1;

    assert!(AuditChain::new().append(tampered).is_err());
}

#[test]
fn broken_audit_hash_chain_fails_closed() {
    let dir = test_dir("broken-audit-chain");
    let mut entries = valid_audit_entries();
    entries[1].prev_hash = [9u8; 32];
    let audit_log = dir.join("audit.log");
    write(&audit_log, &audit_chain_bytes(&entries));

    run_failure(&[
        "validate-audit",
        "--input",
        audit_log.to_str().expect("audit path should be utf-8"),
    ]);
}

#[test]
fn replayed_session_sequence_fails_closed() {
    let key = [4u8; 32];
    let mut session = Session::new(SessionId::from_bytes([1u8; 16]));
    session.activate();
    let frame = create_frame(session.id, 0, 1_700_000_000, b"payload".to_vec(), &key)
        .expect("frame should be created");

    validate_frame(&mut session, &frame, &key).expect("first frame should validate");

    assert!(validate_frame(&mut session, &frame, &key).is_err());
}

#[test]
fn invalid_mac_fails_closed() {
    let key = [4u8; 32];
    let wrong_key = [5u8; 32];
    let mut session = Session::new(SessionId::from_bytes([1u8; 16]));
    session.activate();
    let frame = create_frame(session.id, 0, 1_700_000_000, b"payload".to_vec(), &key)
        .expect("frame should be created");

    assert!(validate_frame(&mut session, &frame, &wrong_key).is_err());
}

#[test]
fn malformed_frame_fails_closed() {
    let key = [4u8; 32];
    let mut session = Session::new(SessionId::from_bytes([1u8; 16]));
    session.activate();
    let frame = AISFrame {
        version: ais_session::AIS_SESSION_VERSION,
        session_id: SessionId::from_bytes([9u8; 16]),
        sequence: 0,
        timestamp: 1_700_000_000,
        payload: b"payload".to_vec(),
        integrity_mac: [0u8; 32],
    };

    assert!(validate_frame(&mut session, &frame, &key).is_err());
}

#[test]
fn corrupted_cbor_fails_closed() {
    let dir = test_dir("corrupted-cbor");
    let audit_log = dir.join("audit.log");
    write(&audit_log, &[0xff, 0x00, 0x01]);

    run_failure(&[
        "validate-audit",
        "--input",
        audit_log.to_str().expect("audit path should be utf-8"),
    ]);
}

#[test]
fn identical_input_produces_identical_hash() {
    assert_eq!(sha3_256(b"same input"), sha3_256(b"same input"));
}

#[test]
fn identical_certificate_input_produces_identical_certificate_bytes() {
    let dir = test_dir("golden-cert");
    let model = dir.join("model.gguf");
    let issuer = dir.join("issuer.key");
    let first_cert = dir.join("first.cert");
    let second_cert = dir.join("second.cert");
    write(&model, b"deterministic model bytes");
    write(&issuer, &fixed_issuer_key());

    for output in [&first_cert, &second_cert] {
        run_success(&[
            "sign-model",
            "--model",
            model.to_str().expect("model path should be utf-8"),
            "--issuer",
            issuer.to_str().expect("issuer path should be utf-8"),
            "--output",
            output.to_str().expect("output path should be utf-8"),
        ]);
    }

    assert_eq!(
        std::fs::read(first_cert).expect("cert should be readable"),
        std::fs::read(second_cert).expect("cert should be readable")
    );
}

#[test]
fn identical_audit_entry_produces_identical_hash() {
    let first = AuditEntry::new(
        [1u8; 16],
        1_700_000_000,
        [2u8; 16],
        sha3_256(b"request"),
        ResponseStatus::Ok,
        EMPTY_AUDIT_HASH,
    )
    .expect("entry should build");
    let second = AuditEntry::new(
        [1u8; 16],
        1_700_000_000,
        [2u8; 16],
        sha3_256(b"request"),
        ResponseStatus::Ok,
        EMPTY_AUDIT_HASH,
    )
    .expect("entry should build");

    assert_eq!(first.entry_hash, second.entry_hash);
}

#[test]
fn deterministic_frame_serialization() {
    let key = [4u8; 32];
    let frame = create_frame(
        SessionId::from_bytes([1u8; 16]),
        0,
        1_700_000_000,
        b"payload".to_vec(),
        &key,
    )
    .expect("frame should be created");

    assert_eq!(
        serialize_frame(&frame).expect("frame should serialize"),
        serialize_frame(&frame).expect("frame should serialize")
    );
}

#[test]
fn cli_validate_audit_smoke_test() {
    let dir = test_dir("cli-validate-audit");
    let audit_log = dir.join("audit.log");
    write(&audit_log, &audit_chain_bytes(&valid_audit_entries()));

    run_success(&[
        "validate-audit",
        "--input",
        audit_log.to_str().expect("audit path should be utf-8"),
    ]);
}
