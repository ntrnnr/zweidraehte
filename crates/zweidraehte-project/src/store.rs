use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use fs4::FileExt;
use thiserror::Error;

use crate::keys::{KeyStoreError, ProjectKeyStore};
use crate::model::AuthoredProject;
use crate::parser::ParseError;
use crate::state::{MutableProjectState, ProjectEvent};

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
    #[error("the 48-bit KNX sequence-number space is exhausted")]
    SequenceExhausted,
}

/// The authored, secret, and mutable parts of one project directory.
pub struct ProjectStore {
    root: PathBuf,
    project_path: PathBuf,
    authored: AuthoredProject,
    keys: Option<ProjectKeyStore>,
    state: Option<MutableProjectState>,
    state_identity_matches: bool,
    journal: Option<File>,
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
        AuthoredProject::parse_at(source.to_string(), project_path.to_path_buf())?;
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

    /// Open without creating files. This is the path used by `check` and dry-run.
    pub fn open(project_path: impl Into<PathBuf>) -> Result<Self, ProjectStoreError> {
        let project_path = project_path.into();
        let root = project_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let source = fs::read_to_string(&project_path)?;
        let authored = AuthoredProject::parse_at(source, project_path.clone())?;
        let keys_path = root.join("keys.toml");
        let keys = keys_path.exists().then(|| ProjectKeyStore::open(keys_path)).transpose()?;
        let state = load_state(&root)?;
        let state_identity_matches = match (&keys, &state) {
            (Some(keys), Some(state)) => keys.state_id()? == state.state_id,
            (None, None) => true,
            _ => false,
        };
        Ok(Self { root, project_path, authored, keys, state, state_identity_matches, journal: None })
    }

    /// Initialize keys and state explicitly. Merely opening or checking a
    /// project never calls this, which keeps dry-run side-effect free.
    pub fn initialize(&mut self) -> Result<(), ProjectStoreError> {
        if self.keys.is_some() || self.state.is_some() {
            return Err(ProjectStoreError::State("project is already partially or fully initialized".into()));
        }
        let state_id = generate_state_id()?;
        fs::create_dir_all(self.state_directory())?;
        let keys = ProjectKeyStore::create(self.root.join("keys.toml"), &state_id)?;
        let state = MutableProjectState::new(state_id);
        atomic_json(&self.snapshot_path(), &state)?;
        let journal = OpenOptions::new().create_new(true).write(true).open(self.journal_path())?;
        journal.sync_all()?;
        sync_directory(&self.state_directory())?;
        self.keys = Some(keys);
        self.state = Some(state);
        self.state_identity_matches = true;
        Ok(())
    }

    pub fn authored(&self) -> &AuthoredProject {
        &self.authored
    }

    pub fn keys(&self) -> Option<&ProjectKeyStore> {
        self.keys.as_ref()
    }

    pub fn keys_mut(&mut self) -> Option<&mut ProjectKeyStore> {
        self.keys.as_mut()
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

    pub fn acquire_lock(&self) -> Result<ProjectLock, ProjectStoreError> {
        let state_directory = self.state_directory();
        if !state_directory.exists() {
            return Err(ProjectStoreError::NotInitialized);
        }
        let path = state_directory.join(LOCK_FILE);
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        FileExt::try_lock(&file).map_err(|_| ProjectStoreError::Locked)?;
        Ok(ProjectLock { file })
    }

    /// Recovery is the only operation allowed to create the state directory
    /// when `keys.toml` survived but the mutable state did not.
    pub fn acquire_recovery_lock(&self) -> Result<ProjectLock, ProjectStoreError> {
        fs::create_dir_all(self.state_directory())?;
        let path = self.state_directory().join(LOCK_FILE);
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        FileExt::try_lock(&file).map_err(|_| ProjectStoreError::Locked)?;
        Ok(ProjectLock { file })
    }

    /// Open the journal after the caller has acquired and retained the lock.
    pub fn begin_mutation(&mut self, _lock: &ProjectLock) -> Result<(), ProjectStoreError> {
        let Some(state) = &self.state else { return Err(ProjectStoreError::NotInitialized) };
        let Some(keys) = &self.keys else { return Err(ProjectStoreError::NotInitialized) };
        if keys.state_id()? != state.state_id {
            return Err(ProjectStoreError::StateIdentityMismatch);
        }
        if state.recovery_required {
            return Err(ProjectStoreError::State("secure project state recovery has not completed".to_string()));
        }
        self.journal = Some(OpenOptions::new().create(true).append(true).open(self.journal_path())?);
        Ok(())
    }

    /// Enter an explicitly requested recovery session. Missing or mismatched
    /// mutable state is replaced with a blank state carrying the key file's
    /// identity; existing compatible observations are retained. In both cases
    /// the recovery marker blocks secure transmission until `finish_recovery`.
    pub fn begin_recovery(&mut self, _lock: &ProjectLock) -> Result<(), ProjectStoreError> {
        let keys = self.keys.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
        let state_id = keys.state_id()?;
        if !self.state_identity_matches || self.state.is_none() {
            let mut state = MutableProjectState::new(state_id);
            state.recovery_required = true;
            atomic_json(&self.snapshot_path(), &state)?;
            let journal = OpenOptions::new().create(true).write(true).truncate(true).open(self.journal_path())?;
            journal.sync_all()?;
            sync_directory(&self.state_directory())?;
            self.state = Some(state);
            self.state_identity_matches = true;
        }
        self.journal = Some(OpenOptions::new().create(true).append(true).open(self.journal_path())?);
        if !self.state.as_ref().is_some_and(|state| state.recovery_required) {
            self.append(ProjectEvent::BeginRecovery)?;
        }
        Ok(())
    }

    pub fn finish_recovery(&mut self) -> Result<(), ProjectStoreError> {
        if !self.state.as_ref().is_some_and(|state| state.recovery_required) {
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
        let state = self.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
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
        if !self.state_identity_matches || self.keys.is_none() {
            return Err(ProjectStoreError::StateIdentityMismatch);
        }
        let state = self.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
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
        let local = self.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?.client_next;
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
        let state = self.state.as_ref().ok_or(ProjectStoreError::NotInitialized)?;
        atomic_json(&self.snapshot_path(), state)?;
        let journal = OpenOptions::new().write(true).truncate(true).open(self.journal_path())?;
        journal.sync_all()?;
        sync_directory(&self.state_directory())?;
        self.journal = Some(OpenOptions::new().append(true).open(self.journal_path())?);
        Ok(())
    }

    fn append(&mut self, event: ProjectEvent) -> Result<(), ProjectStoreError> {
        let journal = self.journal.as_mut().ok_or(ProjectStoreError::NotInitialized)?;
        serde_json::to_writer(&mut *journal, &event).map_err(|error| ProjectStoreError::State(error.to_string()))?;
        journal.write_all(b"\n")?;
        journal.sync_data()?;
        self.state.as_mut().ok_or(ProjectStoreError::NotInitialized)?.apply(&event);
        Ok(())
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

/// Advisory project lock retained for the whole mutable bus session.
pub struct ProjectLock {
    file: File,
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
    if state.version != 1 {
        return Err(ProjectStoreError::State(format!("unsupported state version {}", state.version)));
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

    const PROJECT: &str = "ga test = 1/0/1\nnet test : 1.001 { security plain }\narea 1 a { line 1 l { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 object 0 { on test } } } }\n";

    #[test]
    fn reserve_is_durable_before_it_is_returned() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store.initialize().expect("state initializes");
        let lock = store.acquire_lock().expect("lock acquired");
        store.begin_mutation(&lock).expect("mutation begins");
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
        store.initialize().expect("state initializes");
        let lock = store.acquire_lock().expect("lock acquired");
        store.begin_mutation(&lock).expect("mutation begins");
        assert_eq!(store.advance_client_sequence(42).expect("floor advances"), 42);
        assert_eq!(store.advance_client_sequence(7).expect("lower floor ignored"), 42);
    }

    #[test]
    fn sequence_reservation_stops_at_the_48_bit_wire_limit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store.initialize().expect("state initializes");
        let lock = store.acquire_lock().expect("lock acquired");
        store.begin_mutation(&lock).expect("mutation begins");
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
        store.initialize().expect("state initializes");
        let _first = store.acquire_lock().expect("first lock acquired");
        assert!(matches!(store.acquire_lock(), Err(ProjectStoreError::Locked)));
    }

    #[test]
    fn mismatched_state_opens_for_diagnostics_but_cannot_send() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store.initialize().expect("state initializes");
        drop(store);
        let keys_path = directory.path().join("keys.toml");
        let keys = fs::read_to_string(&keys_path).expect("keys read");
        fs::write(&keys_path, keys.replace("state_id = \"", "state_id = \"different-")).expect("keys identity changes");

        let mut store = ProjectStore::open(&project_path).expect("mismatch remains inspectable");
        assert!(!store.secure_state_ready());
        let lock = store.acquire_lock().expect("existing state can lock");
        assert!(matches!(store.begin_mutation(&lock), Err(ProjectStoreError::StateIdentityMismatch)));
    }

    #[test]
    fn explicit_recovery_rebinds_state_and_keeps_sending_blocked_until_complete() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store.initialize().expect("state initializes");
        drop(store);
        fs::remove_file(directory.path().join(STATE_DIRECTORY).join(SNAPSHOT_FILE)).expect("snapshot is lost");
        fs::remove_file(directory.path().join(STATE_DIRECTORY).join(JOURNAL_FILE)).expect("journal is lost");

        let mut store = ProjectStore::open(&project_path).expect("missing state remains recoverable");
        let lock = store.acquire_recovery_lock().expect("recovery locks");
        store.begin_recovery(&lock).expect("recovery begins");
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
        store.initialize().expect("state initializes");
        let lock = store.acquire_recovery_lock().expect("lock acquired");
        store.begin_recovery(&lock).expect("recovery begins");
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
}
