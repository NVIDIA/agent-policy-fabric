// SPDX-License-Identifier: Apache-2.0
//! Preflight — a misconfigured audit path must fail at startup, not at the
//! first event a fail-closed producer tries to write.

use apf_audit::JsonlSink;
use uuid::Uuid;

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
