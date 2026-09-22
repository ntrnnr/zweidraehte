//! Filesystem boundary for authored project text, keys, and mutable state.
//!
//! A mutable session holds the project lock, appends factual events to the
//! write-ahead journal, and periodically compacts their replayed state into an
//! atomic snapshot. The state module defines those facts but performs no I/O.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use fs4::FileExt;
use thiserror::Error;

use super::key_store::{KeyStoreError, ProjectKeyStore, ProjectKeys};
use crate::state::{MutableProjectState, ProjectEvent};
use crate::syntax::{AuthoredProject, ParseError};

const STATE_DIRECTORY: &str = ".zweidraehte";
const SNAPSHOT_FILE: &str = "snapshot.json";
const JOURNAL_FILE: &str = "journal.jsonl";
const LOCK_FILE: &str = "project.lock";
const MAX_SEQUENCE: u64 = 0xFFFF_FFFF_FFFF;

#[derive(Debug, Error)]
pub enum ProjectStoreError {
    #[error("project I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("project syntax is invalid: {0}")]
    Parse(#[from] ParseError),
    #[error("project keys are invalid: {0}")]
    Keys(#[from] KeyStoreError),
    #[error("project state is invalid: {0}")]
    State(String),
    #[error("the project is already locked by another mutable session")]
    Locked,
    #[error("secure project state has not been initialized")]
    NotInitialized,
    #[error("keys.toml state_id does not match the mutable project state")]
    StateIdentityMismatch,
    #[error("{0} changed after it was opened; reload before writing")]
    AuthoredProjectChanged(PathBuf),
    #[error("credentials are committed, but the project edit is incomplete: {source}")]
    EditAfterKeyCommit {
        #[source]
        source: Box<ProjectStoreError>,
    },
    #[error("the 48-bit KNX sequence-number space is exhausted")]
    SequenceExhausted,
}

/// A read-only snapshot of the authored, secret, and durable project data.
///
/// Acquire [`Self::into_writer`] before changing credentials or durable state.
/// A reader cannot mutate keys:
///
/// ```compile_fail,E0599
/// use zweidraehte_project::ProjectStore;
/// fn edit_reader(mut project: ProjectStore) {
///     project.keys_mut();
/// }
/// ```
pub struct ProjectStore {
    root: PathBuf,
    project_path: PathBuf,
    authored: AuthoredProject,
    keys: Option<ProjectKeyStore>,
    state: Option<MutableProjectState>,
    state_identity_matches: bool,
}

impl ProjectStore {
    /// Atomically create or update the human-authored project source.
    /// Existing editors supply the exact source they opened; product-only
    /// drafts supply `None` and may only create a new file.
    pub fn write_authored(
        project_path: &Path,
        expected_source: Option<&str>,
        source: &str,
    ) -> Result<(), ProjectStoreError> {
        AuthoredProject::parse_at(source.to_string(), Some(project_path.to_path_buf()))?;
        let directory = project_path.parent().unwrap_or_else(|| Path::new(".")).join(STATE_DIRECTORY);
        fs::create_dir_all(&directory)?;
        let _lock = ProjectLock::acquire(directory.join(LOCK_FILE))?;
        Self::write_authored_source(project_path, expected_source, source)
    }

    fn write_authored_source(
        project_path: &Path,
        expected_source: Option<&str>,
        source: &str,
    ) -> Result<(), ProjectStoreError> {
        match (expected_source, fs::read_to_string(project_path)) {
            (Some(expected), Ok(current)) if current == expected => {}
            (Some(_), Ok(_)) | (None, Ok(_)) => {
                return Err(ProjectStoreError::AuthoredProjectChanged(project_path.to_path_buf()));
            }
            (Some(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProjectStoreError::AuthoredProjectChanged(project_path.to_path_buf()));
            }
            (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            (_, Err(error)) => return Err(error.into()),
        }
        atomic_text(project_path, source, ".project")
    }

    /// Files contributing authored intent, credentials and durable evidence.
    /// Observers can compare their contents around acquisition without copying
    /// the store's layout. This only lists paths; it neither creates files nor
    /// promises an atomic read. Missing sidecars are valid uninitialized input.
    pub fn input_files(project_path: &Path) -> impl Iterator<Item = PathBuf> {
        let root = project_path.parent().unwrap_or_else(|| Path::new("."));
        let state = root.join(STATE_DIRECTORY);
        [project_path.to_path_buf(), root.join("keys.toml"), state.join(SNAPSHOT_FILE), state.join(JOURNAL_FILE)]
            .into_iter()
    }

    /// Open without creating files. This is the path used by `check` and dry-run.
    pub fn open(project_path: impl Into<PathBuf>) -> Result<Self, ProjectStoreError> {
        let project_path = project_path.into();
        let root = project_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let source = fs::read_to_string(&project_path)?;
        let authored = AuthoredProject::parse_at(source, Some(project_path.clone()))?;
        let keys_path = root.join("keys.toml");
        let keys = keys_path.exists().then(|| ProjectKeyStore::open(keys_path)).transpose()?;
        let state = load_state(&root)?;
        let state_identity_matches = match (&keys, &state) {
            (Some(keys), Some(state)) => keys.state_id()? == state.state_id,
            (None, None) => true,
            _ => false,
        };
        Ok(Self { root, project_path, authored, keys, state, state_identity_matches })
    }

    /// Initialize keys and state explicitly. Merely opening or checking a
    /// project never calls this, which keeps dry-run side-effect free.
    pub fn initialize(self) -> Result<Self, ProjectStoreError> {
        let mut writer = self.into_writer()?;
        writer.initialize()?;
        Ok(writer.into_store())
    }

    /// Acquire exclusion, then reload durable inputs without changing the
    /// authored intent this snapshot represents. Even initialization uses the
    /// same lock path, before creating either credentials or state.
    pub fn into_writer(self) -> Result<ProjectWriter, ProjectStoreError> {
        fs::create_dir_all(self.state_directory())?;
        let lock = ProjectLock::acquire(self.state_directory().join(LOCK_FILE))?;
        let mut writer = ProjectWriter { store: self, journal: None, _lock: lock };
        writer.refresh()?;
        Ok(writer)
    }

    pub fn authored(&self) -> &AuthoredProject {
        &self.authored
    }

    pub fn keys(&self) -> Option<&ProjectKeyStore> {
        self.keys.as_ref()
    }

    pub fn state(&self) -> Option<&MutableProjectState> {
        self.state.as_ref()
    }

    /// Whether keys and mutable state have the same identity and recovery has
    /// completed. Secure sending adapters enforce this at reservation time.
    pub fn secure_state_ready(&self) -> bool {
        self.state_identity_matches
            && self.state.as_ref().is_some_and(|state| !state.recovery_required)
            && self.keys.is_some()
    }

    pub fn project_path(&self) -> &Path {
        &self.project_path
    }

    fn state_directory(&self) -> PathBuf {
        self.root.join(STATE_DIRECTORY)
    }

    fn snapshot_path(&self) -> PathBuf {
        self.root.join(STATE_DIRECTORY).join(SNAPSHOT_FILE)
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join(STATE_DIRECTORY).join(JOURNAL_FILE)
    }
}

/// Exclusive access to one freshly loaded project.
///
/// Borrowed key edits cannot escape this owner, and converting it back into a
/// snapshot closes its journal before releasing exclusion. This owner does not
/// compact on drop: persistence errors must be reported by explicit operations.
///
/// ```compile_fail,E0505
/// use zweidraehte_project::{KeyOrigin, ProjectWriter};
/// fn release_while_editing(mut writer: ProjectWriter) {
///     let mut keys = writer.keys_mut().expect("initialized project");
///     drop(writer);
///     keys.put_device_tool_key("relay", "00112233445566778899AABBCCDDEEFF", KeyOrigin::Manual);
/// }
/// ```
#[must_use = "retain the writer throughout the project mutation"]
pub struct ProjectWriter {
    store: ProjectStore,
    journal: Option<File>,
    // Release exclusion only after the journal and key document are dropped.
    _lock: ProjectLock,
}

impl std::fmt::Debug for ProjectWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ProjectWriter").field("project", &self.store.project_path()).finish_non_exhaustive()
    }
}

impl ProjectWriter {
    pub fn store(&self) -> &ProjectStore {
        &self.store
    }

    pub fn authored(&self) -> &AuthoredProject {
        self.store.authored()
    }

    pub fn keys(&self) -> Option<&ProjectKeyStore> {
        self.store.keys()
    }

    pub fn keys_mut(&mut self) -> Option<ProjectKeys<'_>> {
        self.store.keys.as_mut().map(ProjectKeys::new)
    }

    pub fn state(&self) -> Option<&MutableProjectState> {
        self.store.state()
    }

    pub fn project_path(&self) -> &Path {
        self.store.project_path()
    }

    pub fn secure_state_ready(&self) -> bool {
        self.store.secure_state_ready()
    }

    pub fn into_store(mut self) -> ProjectStore {
        self.journal = None;
        self.store
    }

    /// Reject an editor whose saved base changed before it acquired this writer.
    /// Recheck disk as well for editors which do not honor advisory exclusion.
    pub fn check_authored(&self, expected: &str) -> Result<(), ProjectStoreError> {
        if self.authored().source() != expected || fs::read_to_string(self.project_path())? != expected {
            return Err(ProjectStoreError::AuthoredProjectChanged(self.project_path().to_path_buf()));
        }
        Ok(())
    }

    /// Validate the saved base and replacement before writing credentials, then
    /// publish authored text under the same lock. There is no atomic rename
    /// spanning both files: a later failure retains the committed credentials.
    /// Key-file I/O errors can themselves follow publication; reopen before retry.
    pub fn update_authored_with_keys<T>(
        &mut self,
        expected: &str,
        source: String,
        edit: impl FnOnce(&mut ProjectKeys<'_>) -> Result<T, KeyStoreError>,
    ) -> Result<T, ProjectStoreError> {
        self.check_authored(expected)?;
        self.authored().reparse(source.clone())?;
        let mut keys = self.keys_mut().ok_or(ProjectStoreError::NotInitialized)?;
        let edited = edit(&mut keys);
        let committed = keys.committed();
        let after_keys = |source| {
            if committed { ProjectStoreError::EditAfterKeyCommit { source: Box::new(source) } } else { source }
        };
        let value = edited.map_err(|error| after_keys(ProjectStoreError::Keys(error)))?;
        self.update_authored(source).map_err(after_keys)?;
        Ok(value)
    }

    /// Initialize an empty project while retaining exclusion for further edits.
    /// Existing sidecars are refused. Failures after publishing credentials use
    /// [`ProjectStoreError::EditAfterKeyCommit`] and require explicit recovery.
    pub fn initialize(&mut self) -> Result<(), ProjectStoreError> {
        if self.store.keys.is_some() || self.store.state.is_some() {
            return Err(ProjectStoreError::State("project is already partially or fully initialized".into()));
        }
        let state_id = generate_state_id()?;
        fs::create_dir_all(self.store.state_directory())?;
        let keys = ProjectKeyStore::create(self.store.root.join("keys.toml"), &state_id)?;
        self.store.keys = Some(keys);
        self.store.state_identity_matches = false;
        // The key file has been published. Report subsequent state failures as
        // partial initialization, and keep this writer from initializing again.
        (|| -> Result<(), ProjectStoreError> {
            let state = MutableProjectState::new(state_id);
            atomic_json(&self.store.snapshot_path(), &state)?;
            let journal = OpenOptions::new().create_new(true).write(true).open(self.store.journal_path())?;
            journal.sync_all()?;
            sync_directory(&self.store.state_directory())?;
            self.store.state = Some(state);
            self.store.state_identity_matches = true;
            Ok(())
        })()
        .map_err(|source| ProjectStoreError::EditAfterKeyCommit { source: Box::new(source) })
    }

    /// Update authored text while retaining this store's existing writer lock.
    /// Source comparison still detects editors which do not honor our lock.
    pub fn update_authored(&mut self, source: String) -> Result<(), ProjectStoreError> {
        let authored = self.store.authored.reparse(source.clone())?;
        ProjectStore::write_authored_source(&self.store.project_path, Some(self.store.authored.source()), &source)?;
        self.store.authored = authored;
        Ok(())
    }

    /// Open the journal after the caller has acquired and retained the lock.
    pub fn begin_mutation(&mut self) -> Result<(), ProjectStoreError> {
        self.refresh()?;
        let Some(state) = &self.store.state else { return Err(ProjectStoreError::NotInitialized) };
        let Some(keys) = &self.store.keys else { return Err(ProjectStoreError::NotInitialized) };
        if keys.state_id()? != state.state_id {
            return Err(ProjectStoreError::StateIdentityMismatch);
        }
        if state.recovery_required {
            return Err(ProjectStoreError::State("secure project state recovery has not completed".to_string()));
        }
        self.journal = Some(OpenOptions::new().create(true).append(true).open(self.store.journal_path())?);
        Ok(())
    }

    /// Enter an explicitly requested recovery session. Missing or mismatched
    /// mutable state is replaced with a blank state carrying the key file's
    /// identity; existing compatible observations are retained. In both cases
    /// the recovery marker blocks secure transmission until `finish_recovery`.
    pub fn begin_recovery(&mut self) -> Result<(), ProjectStoreError> {
        self.refresh()?;
        let keys = self.store.keys.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
        let state_id = keys.state_id()?;
        if !self.store.state_identity_matches || self.store.state.is_none() {
            let mut state = MutableProjectState::new(state_id);
            state.recovery_required = true;
            atomic_json(&self.store.snapshot_path(), &state)?;
            let journal = OpenOptions::new().create(true).write(true).truncate(true).open(self.store.journal_path())?;
            journal.sync_all()?;
            sync_directory(&self.store.state_directory())?;
            self.store.state = Some(state);
            self.store.state_identity_matches = true;
        }
        self.journal = Some(OpenOptions::new().create(true).append(true).open(self.store.journal_path())?);
        if !self.store.state.as_ref().is_some_and(|state| state.recovery_required) {
            self.append(ProjectEvent::BeginRecovery)?;
        }
        Ok(())
    }

    // Loading and locking are separate because inspection must remain read-only.
    // Another operation may finish between them. Reload durable evidence under
    // exclusion, but reject changed authored intent rather than retarget a plan.
    fn refresh(&mut self) -> Result<(), ProjectStoreError> {
        let current = ProjectStore::open(self.store.project_path.clone())?;
        if current.authored.source() != self.store.authored.source() {
            return Err(ProjectStoreError::AuthoredProjectChanged(self.store.project_path.clone()));
        }
        if let Some(keys) = &current.keys {
            keys.protect()?;
        }
        self.store = current;
        self.journal = None;
        Ok(())
    }

    pub fn finish_recovery(&mut self) -> Result<(), ProjectStoreError> {
        if !self.store.state.as_ref().is_some_and(|state| state.recovery_required) {
            return Err(ProjectStoreError::State("project is not in state recovery".into()));
        }
        self.append(ProjectEvent::CompleteRecovery)
    }

    /// Reserve one value from the single client counter. The successor is
    /// appended and fsynced before this function returns the usable value.
    pub fn reserve_client_sequence(&mut self) -> Result<u64, ProjectStoreError> {
        if !self.secure_state_ready() {
            return Err(ProjectStoreError::State(
                "secure sending is blocked until project state recovery completes".to_string(),
            ));
        }
        let state = self.store.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
        if state.client_next >= MAX_SEQUENCE {
            return Err(ProjectStoreError::SequenceExhausted);
        }
        let current = state.client_next;
        self.append(ProjectEvent::AdvanceClient { next: current + 1 })?;
        Ok(current)
    }

    /// Reserve during an explicit state-recovery session.
    ///
    /// Recovery first performs `S-A_Sync`, which advances the client floor
    /// to the receiver's authenticated expectation. It then needs secure
    /// management telegrams to read PID 59 and SIAT. This narrower entry
    /// point permits those reads without enabling normal secure group sends;
    /// the client adapter keeps the two call paths separate.
    pub fn reserve_recovery_management_sequence(&mut self) -> Result<u64, ProjectStoreError> {
        if !self.store.state_identity_matches || self.store.keys.is_none() {
            return Err(ProjectStoreError::StateIdentityMismatch);
        }
        let state = self.store.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
        if !state.recovery_required {
            return self.reserve_client_sequence();
        }
        if state.client_next >= MAX_SEQUENCE {
            return Err(ProjectStoreError::SequenceExhausted);
        }
        let current = state.client_next;
        self.append(ProjectEvent::AdvanceClient { next: current + 1 })?;
        Ok(current)
    }

    /// Sync responses and imports may move the floor forward, never back.
    pub fn advance_client_sequence(&mut self, remote_next: u64) -> Result<u64, ProjectStoreError> {
        if remote_next > MAX_SEQUENCE {
            return Err(ProjectStoreError::SequenceExhausted);
        }
        let local = self.store.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?.client_next;
        let next = local.max(remote_next);
        if next != local {
            self.append(ProjectEvent::AdvanceClient { next })?;
        }
        Ok(next)
    }

    /// Persist an authenticated incoming observation before the caller
    /// delivers the plaintext to an application.
    pub fn record(&mut self, event: ProjectEvent) -> Result<(), ProjectStoreError> {
        self.append(event)
    }

    pub fn compact(&mut self) -> Result<(), ProjectStoreError> {
        let state = self.store.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
        atomic_json(&self.store.snapshot_path(), state)?;
        let journal = OpenOptions::new().write(true).truncate(true).open(self.store.journal_path())?;
        journal.sync_all()?;
        sync_directory(&self.store.state_directory())?;
        self.journal = Some(OpenOptions::new().append(true).open(self.store.journal_path())?);
        Ok(())
    }

    fn append(&mut self, event: ProjectEvent) -> Result<(), ProjectStoreError> {
        self.store
            .state
            .as_ref()
            .ok_or(ProjectStoreError::NotInitialized)?
            .validate_event(&event)
            .map_err(ProjectStoreError::State)?;
        let journal = self.journal.as_mut().ok_or(ProjectStoreError::NotInitialized)?;
        serde_json::to_writer(&mut *journal, &event).map_err(|error| ProjectStoreError::State(error.to_string()))?;
        journal.write_all(b"\n")?;
        journal.sync_data()?;
        self.store.state.as_mut().ok_or(ProjectStoreError::NotInitialized)?.apply(&event);
        Ok(())
    }
}

/// Advisory project lock retained for the whole mutable session.
struct ProjectLock {
    file: File,
}

impl ProjectLock {
    fn acquire(path: PathBuf) -> Result<Self, ProjectStoreError> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
        FileExt::try_lock(&file).map_err(|_| ProjectStoreError::Locked)?;
        Ok(Self { file })
    }
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn load_state(root: &Path) -> Result<Option<MutableProjectState>, ProjectStoreError> {
    let state_directory = root.join(STATE_DIRECTORY);
    let snapshot_path = state_directory.join(SNAPSHOT_FILE);
    let journal_path = state_directory.join(JOURNAL_FILE);
    if !snapshot_path.exists() && !journal_path.exists() {
        return Ok(None);
    }
    if !snapshot_path.exists() {
        return Err(ProjectStoreError::State(format!("{} is missing", snapshot_path.display())));
    }
    let mut state: MutableProjectState = serde_json::from_reader(BufReader::new(File::open(&snapshot_path)?))
        .map_err(|error| ProjectStoreError::State(format!("{}: {error}", snapshot_path.display())))?;
    if state.version != 2 {
        return Err(ProjectStoreError::State(format!("unsupported state version {}", state.version)));
    }
    for (device, evidence) in &state.deployments {
        state
            .validate_event(&ProjectEvent::RecordCommissioningOutcome {
                device: device.clone(),
                outcome: crate::state::CommissioningOutcome::Programmed {
                    established: evidence.manifest.clone(),
                    commissioning: None,
                    fully_verified: false,
                },
            })
            .map_err(ProjectStoreError::State)?;
    }
    if journal_path.exists() {
        for (index, line) in BufReader::new(File::open(&journal_path)?).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event = serde_json::from_str::<ProjectEvent>(&line).map_err(|error| {
                ProjectStoreError::State(format!("{} line {}: {error}", journal_path.display(), index + 1))
            })?;
            state.validate_event(&event).map_err(ProjectStoreError::State)?;
            state.apply(&event);
        }
    }
    Ok(Some(state))
}

fn atomic_json(path: &Path, state: &MutableProjectState) -> Result<(), ProjectStoreError> {
    let parent = path.parent().ok_or_else(|| ProjectStoreError::State(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(parent)?;
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).map_err(|error| ProjectStoreError::State(format!("OS random source: {error}")))?;
    let temporary = parent.join(format!(".snapshot.{:016x}.tmp", u64::from_le_bytes(suffix)));
    let mut file = OpenOptions::new().create_new(true).write(true).open(&temporary)?;
    serde_json::to_writer_pretty(&mut file, state).map_err(|error| ProjectStoreError::State(error.to_string()))?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    sync_directory(parent)?;
    Ok(())
}

fn atomic_text(path: &Path, contents: &str, prefix: &str) -> Result<(), ProjectStoreError> {
    let parent = path.parent().ok_or_else(|| ProjectStoreError::State(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(parent)?;
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).map_err(|error| ProjectStoreError::State(format!("OS random source: {error}")))?;
    let temporary = parent.join(format!("{prefix}.{:016x}.tmp", u64::from_le_bytes(suffix)));
    let mut file = OpenOptions::new().create_new(true).write(true).open(&temporary)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn generate_state_id() -> Result<String, ProjectStoreError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|error| ProjectStoreError::State(format!("OS random source: {error}")))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SenderIdentity;
    use std::collections::BTreeMap;

    fn legacy_programmed(commitment: u8) -> serde_json::Value {
        serde_json::json!({
            "event": "record_commissioning_outcome", "device": "button",
            "outcome": {"kind": "programmed", "fully_verified": true,
                "established": {"sections": {"group_communication": {
                    "semantic:credential:group-key:group:floor:room:7": vec![commitment; 32],
                    "memory:1234": vec![8; 32]
                }}},
                "commissioning": {"version": 1, "obsolete_image_shape": true}
            }
        })
    }

    #[test]
    fn snapshot_and_journal_only_migration_preserve_credentials_and_sequence_floors() {
        for in_snapshot in [false, true] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let state_directory = directory.path().join(STATE_DIRECTORY);
            fs::create_dir(&state_directory).expect("state directory");
            let mut state = MutableProjectState::new("existing-state".into());
            state.client_next = 500;
            state.sender_floors.insert(SenderIdentity::ManagedSerial("serial:one".into()), 400);
            state.devices.insert("serial:one".into(), crate::state::DeviceSequenceObservation {
                outgoing_next: 300,
                siat_last_valid: BTreeMap::from([(SenderIdentity::UnmanagedAddress("1.1.1".into()), 200)]),
            });
            let mut snapshot = serde_json::to_value(&state).expect("snapshot serializes");
            let old = legacy_programmed(13);
            let mut journal = Vec::new();
            if in_snapshot {
                snapshot["deployments"] = serde_json::json!({"button": {
                    "manifest": old["outcome"]["established"],
                    "commissioning": old["outcome"]["commissioning"]
                }});
            } else {
                journal.push(serde_json::json!({"event": "record_commissioning_outcome", "device": "button",
                    "outcome": {"kind": "unloaded", "preserve_network_configuration": true, "serial": null}}));
                journal.push(old);
            }
            journal.push(serde_json::json!({"event": "record_commissioning_outcome", "device": "button",
                "outcome": {"kind": "indeterminate", "sections": ["group_communication"]}}));
            journal.push(serde_json::json!({"event": "advance_client", "next": 550}));
            fs::write(state_directory.join(SNAPSHOT_FILE), serde_json::to_vec(&snapshot).expect("snapshot bytes"))
                .expect("snapshot writes");
            fs::write(
                state_directory.join(JOURNAL_FILE),
                journal.iter().map(|event| event.to_string()).collect::<Vec<_>>().join("\n"),
            )
            .expect("journal writes");

            let migrated = load_state(directory.path()).expect("legacy state loads").expect("state exists");
            assert_eq!(migrated.state_id, state.state_id);
            assert_eq!(migrated.client_next, 550);
            assert_eq!(migrated.sender_floors, state.sender_floors);
            assert_eq!(migrated.devices, state.devices);
            let deployed = &migrated.deployments["button"];
            assert!(deployed.manifest.sections.is_empty());
            assert!(deployed.commissioning.is_none());
            assert!(!deployed.application_unloaded);
            assert_eq!(deployed.manifest.credentials[0].commitment, [13; 32]);
            assert_eq!(deployed.manifest.credentials[0].identity(), "group-key:group:floor:room:7");

            // Compaction persists the migrated proof rather than depending on
            // the legacy journal surviving another successful full download.
            atomic_json(&state_directory.join(SNAPSHOT_FILE), &migrated).expect("migration compacts");
            fs::write(state_directory.join(JOURNAL_FILE), "").expect("journal clears");
            assert_eq!(load_state(directory.path()).expect("current state loads"), Some(migrated));
        }
    }

    #[test]
    fn conflicting_group_key_history_cannot_be_silently_overwritten() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state_directory = directory.path().join(STATE_DIRECTORY);
        fs::create_dir(&state_directory).expect("state directory");
        atomic_json(&state_directory.join(SNAPSHOT_FILE), &MutableProjectState::new("state".into()))
            .expect("snapshot writes");
        let journal = format!("{}\n{}\n", legacy_programmed(1), legacy_programmed(2));
        fs::write(state_directory.join(JOURNAL_FILE), journal).expect("journal writes");
        let error = load_state(directory.path()).expect_err("conflicting evidence fails closed").to_string();
        assert!(error.contains("conflicting deployed group-key"), "{error}");
    }

    #[test]
    fn uncertain_key_exposure_survives_journal_replay_and_compaction() {
        use crate::keys::{KeyId, KeyKind, KeyScope};
        use crate::state::{CommissioningOutcome, CredentialCommitment, DeviceDeploymentEvidence, ProgrammingSection};

        let directory = tempfile::tempdir().expect("temporary directory");
        let state_directory = directory.path().join(STATE_DIRECTORY);
        fs::create_dir(&state_directory).expect("state directory");
        let mut initial = MutableProjectState::new("state".into());
        let mut deployment = DeviceDeploymentEvidence { application_unloaded: true, ..Default::default() };
        deployment.manifest.insert(ProgrammingSection::GroupCommunication, [1; 32]);
        deployment.manifest.insert(ProgrammingSection::Address, [2; 32]);
        initial.deployments.insert("relay".into(), deployment);
        atomic_json(&state_directory.join(SNAPSHOT_FILE), &initial).expect("snapshot writes");

        let proof = CredentialCommitment {
            id: KeyId { kind: KeyKind::GroupKey, scope: KeyScope::Group("floor:room".into()) },
            epoch: None,
            commitment: [7; 32],
        };
        let event = ProjectEvent::RecordCommissioningOutcome {
            device: "relay".into(),
            outcome: CommissioningOutcome::Indeterminate {
                sections: vec![ProgrammingSection::GroupCommunication],
                exposed_group_keys: vec![proof.clone()],
            },
        };
        fs::write(state_directory.join(JOURNAL_FILE), serde_json::to_vec(&event).expect("event serializes"))
            .expect("journal writes");
        let replayed = load_state(directory.path()).expect("journal replays").expect("state exists");
        let deployment = &replayed.deployments["relay"];
        assert_eq!(deployment.manifest.credentials, vec![proof]);
        assert!(!deployment.manifest.sections.contains_key(&ProgrammingSection::GroupCommunication));
        assert_eq!(deployment.manifest.section(ProgrammingSection::Address), Some(&[2; 32]));
        assert!(!deployment.application_unloaded, "uncertain programming retires the unload fact");

        atomic_json(&state_directory.join(SNAPSHOT_FILE), &replayed).expect("snapshot compacts");
        fs::write(state_directory.join(JOURNAL_FILE), "").expect("journal clears");
        assert_eq!(load_state(directory.path()).expect("snapshot loads"), Some(replayed));

        // A journal cannot bypass the validation used by a live writer.
        let mut invalid = serde_json::to_value(event).expect("event serializes");
        invalid["outcome"]["exposed_group_keys"][0]["id"]["kind"] = "tool_key".into();
        fs::write(state_directory.join(JOURNAL_FILE), invalid.to_string()).expect("journal writes");
        assert!(load_state(directory.path()).is_err());
    }

    const PROJECT: &str = concat!(
        "ga test = 1/0/1\nnet test : 1.001 { security plain }\n",
        "area 1 a { line 1 l { medium tp1 device d { ",
        "product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" ",
        "catalog_item \"M-00FA_H-1_P-1_CI-1\" address 1.1.1 object 0 { on test } } } }\n",
    );

    #[test]
    fn reserve_is_durable_before_it_is_returned() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let mut store = store.into_writer().expect("lock acquired");
        store.begin_mutation().expect("mutation begins");
        assert_eq!(store.reserve_client_sequence().expect("sequence reserves"), 1);
        drop(store);

        let reopened = ProjectStore::open(project_path).expect("project reopens");
        assert_eq!(reopened.state().expect("state exists").client_next, 2);
    }

    #[test]
    fn sync_never_lowers_the_client_floor() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let mut store = store.into_writer().expect("lock acquired");
        store.begin_mutation().expect("mutation begins");
        assert_eq!(store.advance_client_sequence(42).expect("floor advances"), 42);
        assert_eq!(store.advance_client_sequence(7).expect("lower floor ignored"), 42);
    }

    #[test]
    fn sequence_reservation_stops_at_the_48_bit_wire_limit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let mut store = store.into_writer().expect("lock acquired");
        store.begin_mutation().expect("mutation begins");
        store.advance_client_sequence(MAX_SEQUENCE - 1).expect("maximum usable value is accepted");
        assert_eq!(store.reserve_client_sequence().expect("last value reserves"), MAX_SEQUENCE - 1);
        assert!(matches!(store.reserve_client_sequence(), Err(ProjectStoreError::SequenceExhausted)));
        assert!(matches!(store.advance_client_sequence(MAX_SEQUENCE + 1), Err(ProjectStoreError::SequenceExhausted)));
    }

    #[test]
    fn locking_rejects_a_second_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let _first = store.into_writer().expect("first lock acquired");
        assert!(matches!(
            ProjectStore::open(&project_path).expect("reader").into_writer(),
            Err(ProjectStoreError::Locked)
        ));
    }

    #[test]
    fn mismatched_state_opens_for_diagnostics_but_cannot_send() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        drop(store);
        let keys_path = directory.path().join("keys.toml");
        let keys = fs::read_to_string(&keys_path).expect("keys read");
        fs::write(&keys_path, keys.replace("state_id = \"", "state_id = \"different-")).expect("keys identity changes");

        let store = ProjectStore::open(&project_path).expect("mismatch remains inspectable");
        assert!(!store.secure_state_ready());
        let mut store = store.into_writer().expect("existing state can lock");
        assert!(matches!(store.begin_mutation(), Err(ProjectStoreError::StateIdentityMismatch)));
    }

    #[test]
    fn explicit_recovery_rebinds_state_and_keeps_sending_blocked_until_complete() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        drop(store);
        fs::remove_file(directory.path().join(STATE_DIRECTORY).join(SNAPSHOT_FILE)).expect("snapshot is lost");
        fs::remove_file(directory.path().join(STATE_DIRECTORY).join(JOURNAL_FILE)).expect("journal is lost");

        let store = ProjectStore::open(&project_path).expect("missing state remains recoverable");
        let mut store = store.into_writer().expect("recovery locks");
        store.begin_recovery().expect("recovery begins");
        assert!(store.reserve_client_sequence().is_err());
        store.advance_client_sequence(500).expect("operator floor advances");
        store.finish_recovery().expect("recovery completes");
        assert!(store.secure_state_ready());
        assert_eq!(store.reserve_client_sequence().expect("sending resumes"), 500);
    }

    #[test]
    fn recovery_allows_management_reservations_but_not_normal_sends() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let mut store = store.into_writer().expect("lock acquired");
        store.begin_recovery().expect("recovery begins");
        store.advance_client_sequence(40).expect("sync floor advances");

        assert!(store.reserve_client_sequence().is_err());
        assert_eq!(store.reserve_recovery_management_sequence().expect("management reserves"), 40);
        assert_eq!(store.state().expect("state exists").client_next, 41);
    }

    #[test]
    fn authored_writes_are_optimistic_and_product_drafts_do_not_overwrite() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        ProjectStore::write_authored(&project_path, None, PROJECT).expect("new project writes");
        assert!(ProjectStore::write_authored(&project_path, None, PROJECT).is_err());

        let changed = PROJECT.replace("address 1.1.1", "address 1.1.2");
        ProjectStore::write_authored(&project_path, Some(PROJECT), &changed).expect("matching edit writes");
        assert!(ProjectStore::write_authored(&project_path, Some(PROJECT), PROJECT).is_err());
        assert_eq!(fs::read_to_string(project_path).expect("project reads"), changed);
    }

    #[test]
    fn authored_updates_share_writer_exclusion_and_still_check_source() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        ProjectStore::write_authored(&path, None, PROJECT).expect("new project writes");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let mut store = store.into_writer().expect("writer acquired");
        store.begin_mutation().expect("writer begins");
        let changed = PROJECT.replace("address 1.1.1", "address 1.1.2");
        assert!(matches!(ProjectStore::write_authored(&path, Some(PROJECT), &changed), Err(ProjectStoreError::Locked)));
        store.update_authored(changed.clone()).expect("owner updates source");
        assert_eq!(store.authored().source(), changed);

        // A plain text editor need not honor advisory locks.
        fs::write(&path, PROJECT).expect("external edit");
        assert!(matches!(store.update_authored(changed), Err(ProjectStoreError::AuthoredProjectChanged(_))));
        assert_eq!(fs::read_to_string(&path).expect("source"), PROJECT);
    }

    #[test]
    fn beginning_a_writer_refreshes_durable_state_but_rejects_changed_intent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        fs::write(&path, PROJECT).expect("source");
        let mut first = ProjectStore::open(&path).expect("project opens");
        first = first.initialize().expect("state initializes");
        let stale = ProjectStore::open(&path).expect("inspection snapshot");
        let mut first = first.into_writer().expect("first writer");
        first.begin_mutation().expect("first begins");
        first.advance_client_sequence(500).expect("first advances floor");
        first.compact().expect("first compacts");
        let first = first.into_store();

        let mut stale = stale.into_writer().expect("next writer");
        stale.begin_mutation().expect("refresh snapshot under writer");
        assert_eq!(stale.reserve_client_sequence().expect("reserve latest floor"), 500);
        drop(stale);
        fs::write(&path, PROJECT.replace("address 1.1.1", "address 1.1.2")).expect("retarget project");
        assert!(matches!(first.into_writer(), Err(ProjectStoreError::AuthoredProjectChanged(_))));
    }
}
