//! Acquire one coherent set of status inputs before evaluating it.
//!
//! These revisions are ephemeral equality tokens, never deployment evidence.
//! Content checks bracket acquisition and evaluation; changes return an explicit
//! error instead of attaching a stable-looking revision to mixed file contents.

use super::inputs::{CatalogAcquisition, ProductInputs, ProjectResourceCache};
use super::revision::FileRevision;
use super::{BatchSelection, ProgrammingView, ProjectMasterData, ProjectPlanner, ProjectProduct};
use crate::commissioning::{CommissioningIntent, DownloadMode};
use crate::configuration::ErrorDetail;
use crate::project::error::{Error, Result};
use crate::security::Keyring;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zweidraehte_project::{AuthoredProject, ProjectDeviceId, ProjectStore};

/// Identifies the actual immutable inputs, including credentials and evidence.
/// Only a digest is retained; neither source text nor key bytes are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRevision([u8; 32]);

/// A computed scope belongs to exactly one revision. Missing rows are unknown.
/// Callers cannot edit the view independently of its input revision:
/// ```compile_fail,E0596
/// use zweidraehte_client::project::ProgrammingSnapshot;
/// fn discard_rows(snapshot: &mut ProgrammingSnapshot) {
///     snapshot.view().statuses.clear(); // The snapshot lends only an immutable view.
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProgrammingSnapshot {
    revision: StatusRevision,
    scope: BTreeSet<ProjectDeviceId>,
    view: ProgrammingView,
    files: Option<std::sync::Arc<FileRevision>>,
}

impl ProgrammingSnapshot {
    pub fn revision(&self) -> StatusRevision {
        self.revision
    }
    pub fn scope(&self) -> &BTreeSet<ProjectDeviceId> {
        &self.scope
    }
    pub fn view(&self) -> &ProgrammingView {
        &self.view
    }

    /// Recheck file-backed results when receiving a delayed worker response.
    /// This reads only input files; it does not reload products or compile.
    /// Borrowed-input snapshots have no file guard; their caller tracks changes.
    pub fn verify_current(&self) -> Result<()> {
        self.files.as_ref().map_or(Ok(()), |files| files.verify(|| Error::StatusInputsChanged))
    }

    /// A different revision replaces the entire view. There is deliberately no
    /// reuse of apparently unrelated rows across revisions without proof.
    pub fn merge(&mut self, newer: Self) {
        if self.revision != newer.revision {
            *self = newer;
            return;
        }
        for id in &newer.scope {
            self.view.manifests.remove(id);
            self.view.statuses.remove(id);
            self.view.requirements.remove(id);
            self.view.impact.affected.remove(id);
            self.view.impact.selected.remove(id);
        }
        self.scope.extend(newer.scope);
        self.files = newer.files;
        self.view.manifests.extend(newer.view.manifests);
        self.view.statuses.extend(newer.view.statuses);
        self.view.requirements.extend(newer.view.requirements);
        self.view.impact.affected.extend(newer.view.impact.affected);
        self.view.impact.selected.extend(newer.view.impact.selected);
    }
}

/// File acquisition options. `draft` pairs unsaved intent with its exact saved
/// base, so an external edit cannot be mistaken for the draft's durable input.
#[derive(Debug)]
#[non_exhaustive]
pub struct ProjectStatusRequest<'a> {
    pub project_path: &'a Path,
    pub draft: Option<(&'a AuthoredProject, &'a str)>,
    pub scope: Option<&'a BTreeSet<ProjectDeviceId>>,
    pub master_data: Option<&'a Path>,
    /// If the keyring loader reads a file, name it here for consistency checks.
    pub keyring_path: Option<&'a Path>,
}

impl<'a> ProjectStatusRequest<'a> {
    /// The saved project at `project_path`, every device, and no extra files.
    pub fn new(project_path: &'a Path) -> Self {
        Self { project_path, draft: None, scope: None, master_data: None, keyring_path: None }
    }
}

/// Parsed immutable packages survive refreshes, keyed by store and exact leaf.
/// Cloning this cache shares product documents and catalogues, not editor state.
#[derive(Debug, Clone, Default)]
pub struct ProjectStatusCache {
    resources: ProjectResourceCache,
}

/// Owned inputs also support check/planning without a second loading policy.
pub struct ProjectStatusInputs {
    store: ProjectStore,
    authored: AuthoredProject,
    resources: ProductInputs,
    keyring: Option<Keyring>,
    scope: BTreeSet<ProjectDeviceId>,
    files: FileRevision,
}

impl std::fmt::Debug for ProjectStatusInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectStatusInputs")
            .field("project", &self.store.project_path())
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ProjectStatusCache {
    /// Load/decrypt once between content checks, reusing parsed packages from
    /// earlier loads. The loader may instead return a caller-owned immutable
    /// keyring; passwords and CLI policy stay outside. Changed inputs return
    /// `StatusInputsChanged`; callers may request a retry.
    pub fn load(
        &mut self,
        request: ProjectStatusRequest<'_>,
        load_keyring: impl FnOnce() -> Result<Option<Keyring>>,
        progress: impl FnMut(&ProjectDeviceId, usize, usize),
    ) -> Result<ProjectStatusInputs> {
        let mut files = FileRevision::capture(
            ProjectStore::input_files(request.project_path).chain(request.keyring_path.map(Path::to_path_buf)),
        )?;
        let store = ProjectStore::open(request.project_path)?;
        let authored = match request.draft {
            Some((draft, expected)) if store.authored().source() == expected => draft.clone(),
            Some(_) => return Err(Error::StatusInputsChanged),
            None => store.authored().clone(),
        };
        let keyring = load_keyring()?;
        let scope = request.scope.cloned().unwrap_or_else(|| {
            authored.devices.values().filter(|device| device.active).map(|device| device.id.clone()).collect()
        });
        let product_scope = super::product_scope(
            &authored,
            &scope.iter().cloned().collect::<Vec<_>>(),
            BatchSelection::Selected,
            CommissioningIntent::Download(DownloadMode::Automatic),
        );
        let resources = self.resources.load(
            &authored,
            &product_scope,
            request.master_data,
            CatalogAcquisition::Automatic,
            &mut files,
            progress,
        )?;
        files.verify(|| Error::StatusInputsChanged)?;
        Ok(ProjectStatusInputs { store, authored, resources, keyring, scope, files })
    }
}

impl ProjectStatusInputs {
    /// The captured durable store. Its authored source is the saved base;
    /// `planner()` and `snapshot()` evaluate the supplied draft when present.
    pub fn store(&self) -> &ProjectStore {
        &self.store
    }
    pub fn products(&self) -> &BTreeMap<ProjectDeviceId, ProjectProduct> {
        &self.resources.products
    }
    pub fn master_data(&self) -> &ProjectMasterData {
        &self.resources.master_data
    }
    pub fn planner(&self) -> ProjectPlanner<'_> {
        ProjectPlanner::for_store(&self.authored, &self.store, &self.resources.products, self.keyring.as_ref())
            .with_master_data(&self.resources.master_data)
    }

    pub fn snapshot(&self) -> Result<ProgrammingSnapshot> {
        let mut snapshot = self.planner().programming_snapshot_for(&self.scope)?;
        self.verify_unchanged()?;
        // File identity also covers store metadata not exposed by a borrowed
        // key source (for example the keys/state pairing), and exact draft base.
        let mut hash = RevisionHasher::default();
        hash.part(&snapshot.revision.0);
        for (path, digest) in &self.files.0 {
            hash.part(path.as_os_str().as_encoded_bytes());
            hash.json(digest)?;
        }
        snapshot.revision = StatusRevision(hash.0.finalize().into());
        snapshot.files = Some(std::sync::Arc::new(self.files.clone()));
        Ok(snapshot)
    }

    /// Check again after another operation using these captured inputs, e.g. a
    /// CLI check compiling full procedures rather than just status manifests.
    pub fn verify_unchanged(&self) -> Result<()> {
        self.files.verify(|| Error::StatusInputsChanged)
    }
}

impl ProjectPlanner<'_> {
    /// Evaluate explicit borrowed inputs without filesystem discovery. Their
    /// revision covers the complete supplied input universe, independent of the
    /// requested output scope, allowing safe partial merges for that revision.
    pub fn programming_snapshot_for(&self, scope: &BTreeSet<ProjectDeviceId>) -> Result<ProgrammingSnapshot> {
        let mut hash = RevisionHasher::default();
        // AuthoredProject's model is editable independently of its source. Its
        // deterministic Debug includes both, preventing direct model edits from
        // reusing a token. This token is local to this build, never serialized as
        // the versioned product/image fingerprints used for durable evidence.
        hash.part(format!("{:?}", self.project).as_bytes());
        hash.json(&self.state)?;
        for (id, product) in self.products {
            hash.part(id.as_str().as_bytes());
            hash.json(product.document())?;
            hash.json(&product.product().programming_identity())?;
            let catalog = self.master_data.cloned().unwrap_or_default().for_product(product.product())?;
            hash.part(&catalog.fingerprint());
        }
        if let Some(keys) = self.keys {
            // Include embedded serials as well as epochs/fingerprints: labels
            // can supply identity even if their secret bytes remain unchanged.
            let mut metadata = keys.list()?;
            metadata.sort_by(|a, b| (&a.id, a.epoch).cmp(&(&b.id, b.epoch)));
            for metadata in metadata {
                hash.part(format!("{metadata:?}").as_bytes());
                if metadata.state == zweidraehte_project::KeyState::Active {
                    let record = keys.read(&metadata.id, metadata.epoch)?;
                    hash.json(&record.as_ref().map(|record| record.embedded_serial))?;
                }
            }
        }
        if let Some(keyring) = self.keyring {
            hash.keyring(keyring);
        }
        let view = self.programming_view_for(scope)?;
        Ok(ProgrammingSnapshot {
            revision: StatusRevision(hash.0.finalize().into()),
            scope: scope.clone(),
            view,
            files: None,
        })
    }
}

#[derive(Default)]
struct RevisionHasher(Sha256);
impl RevisionHasher {
    fn part(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
    }
    fn json(&mut self, value: &impl serde::Serialize) -> Result<()> {
        let canonical = serde_json::to_value(value)
            .map_err(|error| Error::ProductData(ErrorDetail::new(format!("serialize status inputs: {error}"))))?;
        self.part(canonical.to_string().as_bytes());
        Ok(())
    }
    fn keyring(&mut self, keyring: &Keyring) {
        // Debug is redacted and covers the public topology/identity fields.
        // Feed credentials directly into the hasher without formatting them.
        self.part(format!("{keyring:?}").as_bytes());
        for (address, key) in keyring.group_keys() {
            self.part(&address.to_be_bytes());
            self.part(key);
        }
        for device in &keyring.devices {
            for key in [device.tool_key(), device.fdsk()].into_iter().flatten() {
                self.part(key);
            }
            for value in [device.management_password(), device.authentication()].into_iter().flatten() {
                self.part(value.as_bytes());
            }
        }
        for interface in &keyring.interfaces {
            for value in [interface.password(), interface.authentication()].into_iter().flatten() {
                self.part(value.as_bytes());
            }
        }
        if let Some(key) = keyring.backbone.as_ref().and_then(|backbone| backbone.key()) {
            self.part(key);
        }
    }
}

#[cfg(test)]
mod tests;
