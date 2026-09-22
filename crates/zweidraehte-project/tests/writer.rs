//! Exercise the public ownership boundary, including independent OS processes.

use std::fs;
use std::path::Path;
use std::process::Command;
use zweidraehte_project::{KeyMaterialSource, KeyOrigin, ProjectStore, ProjectStoreError};

const SOURCE: &str = "# saved project\n";
const KEY: &str = "00112233445566778899AABBCCDDEEFF";

fn project() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("temporary project");
    let path = directory.path().join("project.knx");
    fs::write(&path, SOURCE).expect("authored source");
    (directory, path)
}

fn child(path: &Path, action: &str, locked: bool) {
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "writer_child", "--nocapture"])
        .env("ZWEIDRAEHTE_WRITER_TEST_PROJECT", path)
        .env("ZWEIDRAEHTE_WRITER_TEST_ACTION", action)
        .env("ZWEIDRAEHTE_WRITER_TEST_LOCKED", if locked { "yes" } else { "no" })
        .output()
        .expect("child process");
    assert!(
        output.status.success(),
        "{action}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn writer_child() {
    let Some(path) = std::env::var_os("ZWEIDRAEHTE_WRITER_TEST_PROJECT") else { return };
    // Inspection succeeds even while the other process owns the writer.
    let store = ProjectStore::open(std::path::PathBuf::from(path)).expect("read-only snapshot");
    let action = std::env::var("ZWEIDRAEHTE_WRITER_TEST_ACTION").expect("child action");
    let result = match action.as_str() {
        "initialize" => store.initialize().map(|_| ()),
        "keys" => store.into_writer().and_then(|mut writer| {
            writer.keys_mut().expect("initialized keys").put_device_tool_key("relay", KEY, KeyOrigin::Manual)?;
            Ok(())
        }),
        "source" => ProjectStore::write_authored(store.project_path(), Some(SOURCE), "# edited\n"),
        _ => panic!("unknown child action"),
    };
    if std::env::var("ZWEIDRAEHTE_WRITER_TEST_LOCKED").expect("child expectation") == "yes" {
        assert!(matches!(result, Err(ProjectStoreError::Locked)), "{result:?}");
    } else {
        result.expect("writer succeeds after exclusion is released");
    }
}

#[test]
fn initialization_credentials_and_source_share_cross_process_exclusion() {
    let (_directory, path) = project();
    let writer = ProjectStore::open(&path).expect("reader").into_writer().expect("initialization owner");
    child(&path, "initialize", true);
    assert!(!path.with_file_name("keys.toml").exists(), "failed initialization publishes no credentials");
    drop(writer);
    child(&path, "initialize", false);

    let mut writer = ProjectStore::open(&path).expect("reader").into_writer().expect("programming owner");
    writer.begin_mutation().expect("journal");
    for action in ["initialize", "keys", "source"] {
        child(&path, action, true);
    }
    assert!(writer.keys().expect("keys").list().expect("metadata").is_empty());
    assert_eq!(fs::read_to_string(&path).expect("source"), SOURCE);
    let snapshot = writer.into_store();
    child(&path, "keys", false);
    child(&path, "source", false);
    assert!(snapshot.keys().expect("snapshot keys").list().expect("metadata").is_empty());
}

#[test]
fn acquiring_a_writer_refreshes_keys_without_losing_another_edit() {
    let (_directory, path) = project();
    let stale = ProjectStore::open(&path).expect("reader").initialize().expect("initialize");
    child(&path, "keys", false);
    let mut writer = stale.into_writer().expect("refresh credentials");
    writer.keys_mut().expect("keys").put_device_tool_key("button", KEY, KeyOrigin::Manual).expect("second key");
    let reopened = ProjectStore::open(&path).expect("reader");
    assert_eq!(reopened.keys().expect("keys").list().expect("metadata").len(), 2);
}

#[cfg(unix)]
#[test]
fn permission_repair_requires_the_writer() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, path) = project();
    ProjectStore::open(&path).expect("reader").initialize().expect("initialize");
    let keys = path.with_file_name("keys.toml");
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o644)).expect("external permission change");
    let reader = ProjectStore::open(&path).expect("inspection");
    assert_eq!(fs::metadata(&keys).expect("metadata").permissions().mode() & 0o777, 0o644);
    let _writer = reader.into_writer().expect("writer repairs permissions");
    assert_eq!(fs::metadata(&keys).expect("metadata").permissions().mode() & 0o777, 0o600);
}

#[test]
fn partial_initialization_reports_published_keys_and_rejects_reinitialization() {
    let (_directory, path) = project();
    let mut writer = ProjectStore::open(&path).expect("reader").into_writer().expect("writer");
    let snapshot = path.parent().expect("project directory").join(".zweidraehte/snapshot.json");
    fs::create_dir(&snapshot).expect("block snapshot publication");
    assert!(matches!(writer.initialize(), Err(ProjectStoreError::EditAfterKeyCommit { .. })));
    let keys = fs::read(path.with_file_name("keys.toml")).expect("keys were published");
    assert!(matches!(writer.initialize(), Err(ProjectStoreError::State(_))));
    assert_eq!(fs::read(path.with_file_name("keys.toml")).expect("retained keys"), keys);

    fs::remove_dir(snapshot).expect("remove injected failure");
    writer.begin_recovery().expect("explicit recovery resumes partial initialization");
    writer.finish_recovery().expect("finish empty-project recovery");
    assert!(writer.secure_state_ready());
}

#[test]
fn stale_or_invalid_authored_edits_fail_before_credentials_change() {
    let (_directory, path) = project();
    ProjectStore::open(&path).expect("reader").initialize().expect("initialize");
    let before = fs::read(path.with_file_name("keys.toml")).expect("original keys");
    fs::write(&path, "# external edit\n").expect("external editor");
    let mut writer = ProjectStore::open(&path).expect("fresh reader").into_writer().expect("writer");
    let error = writer
        .update_authored_with_keys::<()>(SOURCE, "# proposed edit\n".into(), |_| {
            panic!("stale edits must not touch keys")
        })
        .expect_err("stale editor base");
    assert!(matches!(error, ProjectStoreError::AuthoredProjectChanged(_)));
    let error = writer
        .update_authored_with_keys::<()>("# external edit\n", "not project syntax".into(), |_| {
            panic!("invalid edits must not touch keys")
        })
        .expect_err("invalid replacement");
    assert!(matches!(error, ProjectStoreError::Parse(_)));
    assert_eq!(fs::read(path.with_file_name("keys.toml")).expect("unchanged keys"), before);
}

#[test]
fn multi_file_edits_publish_credentials_first_and_report_later_failure() {
    for interference in [false, true] {
        let (_directory, path) = project();
        let mut writer =
            ProjectStore::open(&path).expect("reader").initialize().expect("initialize").into_writer().expect("writer");
        let result = writer.update_authored_with_keys(SOURCE, "# proposed edit\n".into(), |keys| {
            keys.put_device_tool_key("button", KEY, KeyOrigin::Manual)?;
            assert_eq!(fs::read_to_string(&path).expect("source before publication"), SOURCE);
            if interference {
                // Model a text editor that ignores advisory exclusion.
                fs::write(&path, "# external edit\n").expect("external editor");
            }
            Ok(())
        });
        let reopened = ProjectStore::open(&path).expect("reader");
        assert_eq!(reopened.keys().expect("keys").list().expect("metadata").len(), 1);
        if interference {
            let error = result.expect_err("source changed after key publication");
            assert!(matches!(error, ProjectStoreError::EditAfterKeyCommit { source }
                if matches!(*source, ProjectStoreError::AuthoredProjectChanged(_))));
            assert_eq!(reopened.authored().source(), "# external edit\n");
        } else {
            result.expect("complete edit");
            assert_eq!(reopened.authored().source(), "# proposed edit\n");
        }
    }
}
