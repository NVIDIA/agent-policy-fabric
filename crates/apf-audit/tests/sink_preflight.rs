// SPDX-License-Identifier: Apache-2.0
//! Preflight — a misconfigured audit path must fail at startup, not at the
//! first event a fail-closed producer tries to write.

use apf_audit::{
    AuditEvent, AuditSink, CommonFields, Component, JsonlSink, Outcome, PolicyActivationEvent,
    TypedAuditEvent, generate_correlation_id,
};
use uuid::Uuid;

fn sample_event() -> AuditEvent {
    PolicyActivationEvent::new(Outcome::Success, "policy.bundle_loaded")
        .into_audit_event(&CommonFields::new_without_subject(
            generate_correlation_id(),
            "apf-audit:test",
            "none",
            Component::new("apf-audit", "0.1.0", "apf-audit:test"),
            "a".repeat(64),
            "apf-audit:test",
        ))
        .expect("sample event is valid")
}

fn scratch() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("apf-audit-preflight-{}", Uuid::new_v4().simple()))
}

#[test]
fn a_writable_path_passes_and_writes_no_record() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).expect("create");
    let path = dir.join("audit.jsonl");

    JsonlSink::new(&path)
        .preflight()
        .expect("a writable path must pass");

    let contents = std::fs::read_to_string(&path).unwrap_or_default();
    let empty = contents.is_empty();
    std::fs::remove_dir_all(&dir).ok();
    assert!(empty, "preflight must not write a record: {contents}");
}

#[test]
fn a_missing_parent_directory_is_created_rather_than_rejected() {
    // write_event calls create_dir_all, so preflight must agree.
    let dir = scratch();
    let path = dir.join("nested/deeper/audit.jsonl");

    JsonlSink::new(&path)
        .preflight()
        .expect("a creatable parent must pass");

    let created = path.parent().is_some_and(std::path::Path::is_dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(created, "preflight must create the parent directory");
}

#[cfg(unix)]
#[test]
fn an_unwritable_directory_fails_before_the_first_event() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch();
    std::fs::create_dir_all(&dir).expect("create");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("chmod");

    // Root ignores permission bits (CI runners), so this environment cannot
    // represent an unwritable directory. The invariant is untestable here,
    // not violated — probe rather than parse a uid.
    if std::fs::write(dir.join("probe"), b"").is_ok() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::remove_dir_all(&dir).ok();
        return;
    }

    let failed = JsonlSink::new(dir.join("audit.jsonl")).preflight().is_err();

    // Restore first so the directory can always be cleaned up.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    std::fs::remove_dir_all(&dir).ok();
    assert!(failed, "a read-only directory must fail preflight");
}

#[test]
fn a_path_that_is_a_directory_fails() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).expect("create");

    let failed = JsonlSink::new(&dir).preflight().is_err();

    std::fs::remove_dir_all(&dir).ok();
    assert!(failed, "a directory is not an appendable audit file");
}

/// A write-only log file is a normal hardening choice, and the fragment guard
/// wants read access. The guard must yield rather than lose the sink.
#[test]
#[cfg(unix)]
fn a_write_only_log_file_still_accepts_records() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch();
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = dir.join("audit.jsonl");
    std::fs::write(&path, b"").expect("create");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).expect("chmod");
    // Root ignores the mode bit, so the write-only file is still readable and
    // the degrade branch this exercises can't be reached — the premise cannot
    // be represented here. Skip rather than fail: any environment that lets the
    // probe read the file would let the sink read it too.
    if std::fs::File::open(&path).is_ok() {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
        std::fs::remove_dir_all(&dir).ok();
        eprintln!("skipped: environment cannot represent a write-only file");
        return;
    }

    let sink = JsonlSink::new(path.clone());
    sink.preflight()
        .expect("preflight accepts a write-only file");
    sink.write_event(&sample_event())
        .expect("a write-only file must still accept records");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
    let lines = std::fs::read_to_string(&path)
        .expect("read")
        .lines()
        .count();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(lines, 1);
}

/// A record following an unterminated line must land on its own line, or a
/// line-oriented collector drops both.
#[test]
fn a_truncated_line_is_terminated_before_the_next_record() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = dir.join("audit.jsonl");
    std::fs::write(&path, b"{\"partial\":").expect("write fragment");

    let sink = JsonlSink::new(path.clone());
    sink.write_event(&sample_event()).expect("record written");

    let written = std::fs::read_to_string(&path).expect("read");
    std::fs::remove_dir_all(&dir).ok();
    let lines: Vec<&str> = written.lines().collect();
    assert_eq!(lines.len(), 2, "the fragment must not absorb the record");
    assert!(
        serde_json::from_str::<AuditEvent>(lines[1]).is_ok(),
        "the new record must be its own parseable line"
    );
}
