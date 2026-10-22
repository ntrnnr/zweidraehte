//! Shared acquisition for read-only inspection and explicit programming setup.

use super::product::ProductCache;
use super::revision::{FileRevision, file_digest};
use super::{
    BatchSelection, ProgrammingBatchPlan, ProjectCommissioningSession, ProjectMasterData, ProjectPlanner,
    ProjectProduct, ProjectProgrammingInputs,
};
use crate::commissioning::{CommissioningIntent, TargetSelection};
use crate::project::error::{Error, Result};
use crate::security::Keyring;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zweidraehte_project::{AuthoredProject, KeyMaterialSource, NetId, ProjectDeviceId, ProjectStore};

/// Explicit file sources. A fallback catalog cannot replace a package's own
/// Master Data; keyring passwords and interaction belong to the caller.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProjectInputSources<'a> {
    pub master_data: Option<&'a Path>,
    /// Name the file read by the keyring loader so changes invalidate setup.
    pub keyring_path: Option<&'a Path>,
}

/// Selection and semantic intent, independent of frontend shortcut names.
#[derive(Debug, Clone, Copy)]
pub struct ProjectInputRequest<'a> {
    pub selected: &'a [ProjectDeviceId],
    pub selection: BatchSelection,
    pub intent: CommissioningIntent,
    pub sources: ProjectInputSources<'a>,
}

/// Setup needs contain identities, never credential bytes. Missing credentials
/// stop planning with a typed error; initialization, generated keys and physical
/// target acquisition can also be inspected before starting an operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectSetupRequirement {
    #[error("project keys and state are not initialized")]
    InitializeProject,
    #[error("project keys/state require explicit recovery before programming")]
    RecoverProject,
    #[error("Data Secure device `{device}` needs a serial from project.knx, its FDSK label, or the ETS keyring")]
    DeviceSerial { device: ProjectDeviceId },
    #[error("secure commissioning for `{device}` requires a tool key or FDSK")]
    ManagementCredential { device: ProjectDeviceId },
    #[error("net `{net}` requires secure group traffic but has no active group key")]
    GroupKey { net: NetId },
    #[error("IP Secure routing for `{device}` needs an active backbone key")]
    BackboneKey { device: ProjectDeviceId },
    #[error("IP Secure configuration for `{device}` needs a Device Authentication Code")]
    DeviceAuthenticationCode { device: ProjectDeviceId },
    #[error("IP Secure configuration for `{device}` needs the password hash for user {user}")]
    IpPasswordHash { device: ProjectDeviceId, user: std::num::NonZeroU8 },
    #[error("device `{device}` needs a generated Tool Key before bus access")]
    GenerateToolKey { device: ProjectDeviceId },
    #[error("device `{device}` requires physical programming mode or an explicit current address")]
    PhysicalTarget { device: ProjectDeviceId },
}

/// One immutable set of product documents and their selected Master Data.
#[derive(Debug)]
pub(super) struct ProductInputs {
    pub products: BTreeMap<ProjectDeviceId, ProjectProduct>,
    pub master_data: ProjectMasterData,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProjectResourceCache {
    products: ProductCache,
    master_data: Option<([u8; 32], ProjectMasterData)>,
}

#[derive(Clone, Copy)]
pub(super) enum CatalogAcquisition {
    Automatic,
    /// Raw management can use a known address without programming metadata.
    SuppliedOnly,
}

impl ProjectResourceCache {
    pub(super) fn load(
        &mut self,
        project: &AuthoredProject,
        scope: &BTreeSet<ProjectDeviceId>,
        master_data: Option<&Path>,
        acquisition: CatalogAcquisition,
        files: &mut FileRevision,
        progress: impl FnMut(&ProjectDeviceId, usize, usize),
    ) -> Result<ProductInputs> {
        let products = self.products.load(project, scope, progress)?;
        let needs_catalog = products.values().any(|product| product.product().master_data().is_none());
        // Watch an explicit installation catalog's bytes before reading. Only
        // products with an explicitly bound catalog leave it unused; automatic
        // sources retain their resolver.
        let selected = if let Some(path) = master_data.filter(|_| needs_catalog) {
            let digest = file_digest(path)?;
            files.0.insert(path.to_path_buf(), digest);
            match &self.master_data {
                Some((previous, selected)) if Some(*previous) == digest => selected.clone(),
                _ => {
                    let selected = ProjectMasterData::load_for(&products, Some(path))?;
                    self.master_data = digest.map(|digest| (digest, selected.clone()));
                    selected
                }
            }
        } else if matches!(acquisition, CatalogAcquisition::Automatic) {
            ProjectMasterData::load_for(&products, None)?
        } else {
            ProjectMasterData::default()
        };
        Ok(ProductInputs { products, master_data: selected })
    }
}

/// Owned inputs for one request. Acquisition and planning leave project files
/// untouched and acquire no writer. Automatic Master Data acquisition may fill
/// its external cache. Explicit initialization and session acquisition recheck
/// the captured files under exclusion before allowing a project mutation.
pub struct ProjectOperationInputs {
    store: ProjectStore,
    resources: ProductInputs,
    keyring: Option<Keyring>,
    selected: Vec<ProjectDeviceId>,
    selection: BatchSelection,
    intent: CommissioningIntent,
    scope: BTreeSet<ProjectDeviceId>,
    files: FileRevision,
}

impl std::fmt::Debug for ProjectOperationInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectOperationInputs")
            .field("project", &self.store.project_path())
            .field("selected", &self.selected)
            .field("selection", &self.selection)
            .field("intent", &self.intent)
            .finish_non_exhaustive()
    }
}

impl ProjectOperationInputs {
    /// Load the selected products and their secure peers without initializing
    /// project state. The caller supplies keyring decryption and its file path.
    /// Changed saved input returns [`Error::OperationInputsChanged`].
    pub fn load(
        store: ProjectStore,
        request: ProjectInputRequest<'_>,
        load_keyring: impl FnOnce() -> Result<Option<Keyring>>,
    ) -> Result<Self> {
        let mut files = FileRevision::capture(
            ProjectStore::input_files(store.project_path()).chain(request.sources.keyring_path.map(Path::to_path_buf)),
        )?;
        // The supplied snapshot can predate acquisition. Preserve its intended
        // source, but refresh durable evidence inside the consistency window.
        let current = ProjectStore::open(store.project_path())?;
        if current.authored().source() != store.authored().source() {
            return Err(Error::OperationInputsChanged);
        }
        let store = current;
        let keyring = load_keyring()?;
        let scope =
            ProjectPlanner::product_scope(store.authored(), request.selected, request.selection, request.intent);
        let resources = ProjectResourceCache::default().load(
            store.authored(),
            &scope,
            request.sources.master_data,
            CatalogAcquisition::Automatic,
            &mut files,
            |_, _, _| {},
        )?;
        files.verify(|| Error::OperationInputsChanged)?;
        Ok(Self {
            store,
            resources,
            keyring,
            selected: request.selected.to_vec(),
            selection: request.selection,
            intent: request.intent,
            scope,
            files,
        })
    }

    pub fn store(&self) -> &ProjectStore {
        &self.store
    }

    pub fn product_scope(&self) -> &BTreeSet<ProjectDeviceId> {
        &self.scope
    }

    pub fn programming_inputs(&self) -> ProjectProgrammingInputs<'_> {
        ProjectProgrammingInputs {
            products: &self.resources.products,
            master_data: &self.resources.master_data,
            keyring: self.keyring.as_ref(),
        }
    }

    /// Borrow the same inputs for additional inspection. Unlike [`Self::plan`],
    /// the borrowed planner performs no filesystem revision checks.
    pub fn planner(&self) -> ProjectPlanner<'_> {
        ProjectPlanner::new(
            self.store.authored(),
            self.store.state(),
            &self.resources.products,
            self.store.keys().map(|keys| keys as &dyn KeyMaterialSource),
            self.keyring.as_ref(),
        )
        .with_master_data(&self.resources.master_data)
    }

    /// Evaluate this request and recheck its files before returning the plan.
    pub fn plan(&self) -> Result<ProgrammingBatchPlan> {
        let plan = self.planner().plan_commissioning(&self.selected, self.selection, self.intent)?;
        self.verify_unchanged()?;
        Ok(plan)
    }

    pub fn state_requirement(&self) -> Option<ProjectSetupRequirement> {
        match (self.store.keys(), self.store.state()) {
            (None, None) => Some(ProjectSetupRequirement::InitializeProject),
            _ if !self.store.secure_state_ready() => Some(ProjectSetupRequirement::RecoverProject),
            _ => None,
        }
    }

    /// Inspect the configured plan, including any explicit target overrides.
    pub fn requirements(&self, plan: &ProgrammingBatchPlan) -> Vec<ProjectSetupRequirement> {
        let mut requirements: Vec<_> = self.state_requirement().into_iter().collect();
        for device in plan.devices() {
            if device.needs_tool_key_generation() {
                requirements.push(ProjectSetupRequirement::GenerateToolKey { device: device.id().clone() });
            }
            if matches!(device.commissioning().target, TargetSelection::ProgrammingButton(_)) {
                requirements.push(ProjectSetupRequirement::PhysicalTarget { device: device.id().clone() });
            }
        }
        requirements
    }

    /// Explicitly authorize empty-project initialization. Never performed by
    /// loading, planning, or opening a session.
    pub fn initialize(&mut self) -> Result<()> {
        let mut writer = ProjectStore::open(self.store.project_path())?.into_writer()?;
        self.verify_unchanged()?;
        writer.initialize()?;
        self.files.0.extend(FileRevision::capture(ProjectStore::input_files(writer.project_path()))?.0);
        self.store = writer.into_store();
        self.verify_unchanged()
    }

    /// Retain writer exclusion after checking setup and input revisions.
    /// Initialization and recovery remain explicit caller decisions.
    pub fn begin_session(&self) -> Result<ProjectCommissioningSession> {
        if let Some(requirement) = self.state_requirement() {
            return Err(requirement.into());
        }
        let writer = ProjectStore::open(self.store.project_path())?.into_writer()?;
        self.verify_unchanged()?;
        ProjectCommissioningSession::from_writer(writer)
    }

    pub fn verify_unchanged(&self) -> Result<()> {
        self.files.verify(|| Error::OperationInputsChanged)
    }
}

#[cfg(test)]
mod tests;
