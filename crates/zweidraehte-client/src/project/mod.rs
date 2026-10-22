//! Project evaluation and download planning.

use crate::commissioning::{AssociationTableEntrySize, ImageRequirement};
use crate::commissioning::{
    CommissioningIntent, CompileError, CompileOptions, CompiledProgram, DifferentialPolicy, DownloadMode,
    ProfileSelection, ProgramSections, ProgrammingInput, ProgrammingModePolling, ResolvedProfile, TargetSelection,
};
use crate::configuration::{GroupObjectProtection, MaterializedDevice, ResolvedKeyMaterial};
use crate::security::Keyring;
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_project::{
    AuthoredProject, COMMISSIONING_DEPLOYMENT_RECORD_VERSION, CommissioningAssociationEntrySize,
    CommissioningDeploymentRecord as ProjectCommissioningDeploymentRecord, CredentialCommitment,
    DeviceProgrammingStatus, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMetadata, KeyRecord, KeyScope,
    KeyStoreError, MembershipRole as ProjectMembershipRole, MutableProjectState, NetId,
    NetSecurityPolicy as ProjectSecurityPolicy, ProgrammingManifest, ProgrammingSection, ProjectDevice,
    ProjectDeviceId, SenderIdentity, format_serial,
};
use zweidraehte_proto::address::GroupAddress;

mod error;
pub use error::{Error, Result};

mod configuration;
mod inputs;
mod keyring;
mod keys;
mod management;
mod master_data;
mod operation;
mod programming;
mod revision;
mod status;
mod target;
pub use configuration::{product_configuration, product_object_flags};
pub use inputs::{ProjectInputRequest, ProjectInputSources, ProjectOperationInputs, ProjectSetupRequirement};
pub use keyring::{KeyringImportPlan, KeyringImportSummary};
pub use keys::resolve_project_key_material;
pub use management::{
    ManagementSources, MemoryReadOptions, ProjectDeviceSynchronization, ProjectManagementFailure,
    ProjectManagementResult, ProjectManagementTarget, ProjectMemoryReadReport, ProjectMemoryReadout,
    ProjectSynchronization, ProjectSynchronizationReport,
};
pub use operation::{ProjectFinalizationFailure, ProjectOperation};
pub use programming::{ProgrammingPolicy, ProjectProgramming};
pub use status::{ProgrammingSnapshot, ProjectStatusCache, ProjectStatusInputs, ProjectStatusRequest, StatusRevision};
pub use target::SerialAddressingSupport;

pub use master_data::ProjectMasterData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchSelection {
    /// Select the named devices. Naming an inactive device is an explicit
    /// override of its automatic-operation exclusion.
    Selected,
    /// Select every active authored device, regardless of deployment
    /// fingerprints. Address-only commissioning uses this because an
    /// application deployment record is not proof that the live IA still
    /// matches the project.
    All,
    /// Select every active device whose deployment evidence is stale.
    AllStale,
}

/// Product definitions which one commissioning selection can actually use.
///
/// A named plain-management operation needs only its named devices. An
/// application download also needs active peers on the same secured nets so
/// their effective object flags can populate SIAT and consumer invalidation.
/// Project-wide operations necessarily inspect every active device before
/// deciding their physical target set.
pub(super) fn product_scope(
    project: &AuthoredProject,
    selected: &[ProjectDeviceId],
    selection: BatchSelection,
    intent: CommissioningIntent,
) -> BTreeSet<ProjectDeviceId> {
    if selection != BatchSelection::Selected {
        return project.devices.values().filter(|device| device.active).map(|device| device.id.clone()).collect();
    }

    let mut scope = selected.iter().cloned().collect::<BTreeSet<_>>();
    if !intent.download_mode().is_some() {
        return scope;
    }

    let secured_nets = selected
        .iter()
        .filter_map(|id| project.devices.get(id))
        .flat_map(|device| device.objects.values())
        .flat_map(|object| object.memberships.iter())
        .filter(|membership| {
            project.effective_net_security(&membership.net).is_some_and(|policy| policy != ProjectSecurityPolicy::Plain)
        })
        .map(|membership| membership.net.clone())
        .collect::<BTreeSet<_>>();

    scope.extend(
        project
            .devices
            .values()
            .filter(|device| device.active)
            .filter(|device| {
                device
                    .objects
                    .values()
                    .any(|object| object.memberships.iter().any(|membership| secured_nets.contains(&membership.net)))
            })
            .map(|device| device.id.clone()),
    );
    scope
}

/// Point at which a project batch stopped.
///
/// The distinction matters after device mutation: a caller must not retry a
/// physically completed operation merely because its durable project-state
/// update failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectBatchFailureStage {
    /// Planning, cancellation or live preflight stopped before this target's mutation.
    Preparation,
    /// The Commissioner itself did not return a successful device report.
    Commissioning,
    /// The device completed, but its success evidence was not fully journaled.
    SuccessPersistence,
    /// Bus shutdown, authored serial reconciliation or state compaction failed.
    Finalization,
}

impl core::fmt::Display for ProjectBatchFailureStage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preparation => formatter.write_str("preparation"),
            Self::Commissioning => formatter.write_str("commissioning"),
            Self::SuccessPersistence => formatter.write_str("success persistence"),
            Self::Finalization => formatter.write_str("finalization"),
        }
    }
}

/// Exact changed sections generated by comparing compiler artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgrammingImpact {
    pub selected: BTreeSet<ProjectDeviceId>,
    pub affected: BTreeMap<ProjectDeviceId, BTreeSet<ProgrammingSection>>,
}

impl ProgrammingImpact {
    pub fn closure(&self) -> BTreeSet<ProjectDeviceId> {
        self.affected.keys().cloned().collect()
    }

    pub fn requires_other_devices(&self) -> bool {
        self.affected.keys().any(|device| !self.selected.contains(device))
    }
}

/// Ephemeral exact view for one immutable project/product/key/state revision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgrammingView {
    pub manifests: BTreeMap<ProjectDeviceId, ProgrammingManifest>,
    /// Devices whose exact image still needs observed target capabilities.
    pub requirements: BTreeMap<ProjectDeviceId, Vec<ImageRequirement>>,
    pub statuses: BTreeMap<ProjectDeviceId, DeviceProgrammingStatus>,
    pub impact: ProgrammingImpact,
}

/// Evaluated identity and scope cannot be replaced without replanning.
///
/// ```compile_fail
/// use zweidraehte_client::project::PlannedProjectDevice;
/// fn replace_identity(device: &mut PlannedProjectDevice) {
///     device.id = zweidraehte_project::ProjectDeviceId("other".into());
/// }
/// ```
#[derive(Clone)]
pub struct PlannedProjectDevice {
    id: ProjectDeviceId,
    /// Immutable post-evaluation input used by preview and live
    /// commissioning alike.
    device: crate::configuration::MaterializedDevice,
    commissioning: ProjectDeviceCommissioningOptions,
    /// Original semantic scope; automatic address reuse may narrow execution.
    evaluated_intent: CommissioningIntent,
    target_override: Option<TargetSelection>,
    serial_addressing: SerialAddressingSupport,
    supports_data_secure: bool,
    data_secure_enabled: bool,
    desired_manifest: ProgrammingManifest,
    /// These facts are supplied during live discovery before compiling the image.
    image_requirements: Vec<ImageRequirement>,
    /// Durable status at planning time. It decides whether an automatic
    /// partial operation also needs physical address assignment.
    status: DeviceProgrammingStatus,
    /// Smallest semantic application section set justified by the last
    /// successful deployment. The exact profile compiler may widen this to a
    /// supported superset or to a full download.
    automatic_sections: ProgramSections,
    /// Public identities connecting compiler-bound GKT rows to durable keys.
    net_ids: BTreeMap<GroupAddress, String>,
    /// Exact non-secret image and stamp evidence from the previous generic
    /// commissioning operation, when one completed successfully.
    previous_commissioning: Option<ProjectCommissioningDeploymentRecord>,
    warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProjectPlanPreviewError {
    #[error(transparent)]
    Configuration(#[from] Error),
    #[error(transparent)]
    Compilation(#[from] CompileError),
}

impl PlannedProjectDevice {
    pub fn id(&self) -> &ProjectDeviceId {
        &self.id
    }
    pub fn device(&self) -> &MaterializedDevice {
        &self.device
    }
    pub fn commissioning(&self) -> &ProjectDeviceCommissioningOptions {
        &self.commissioning
    }
    pub fn supports_data_secure(&self) -> bool {
        self.supports_data_secure
    }
    pub fn data_secure_enabled(&self) -> bool {
        self.data_secure_enabled
    }
    pub fn desired_manifest(&self) -> &ProgrammingManifest {
        &self.desired_manifest
    }
    pub fn image_requirements(&self) -> &[ImageRequirement] {
        &self.image_requirements
    }
    pub fn status(&self) -> DeviceProgrammingStatus {
        self.status
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn needs_tool_key_generation(&self) -> bool {
        self.device.key_material().needs_tool_key_generation()
    }

    pub fn serial_addressing(&self) -> SerialAddressingSupport {
        self.serial_addressing
    }

    pub fn serial_target(&self) -> Option<[u8; 6]> {
        self.serial_addressing.serial_target(self.serial_number())
    }

    pub fn serial_number(&self) -> Option<[u8; 6]> {
        self.device.key_material().serial_number()
    }

    /// Typed semantic section set requested by automatic commissioning.
    ///
    /// The project planner derives this once from durable section status;
    /// frontends must not reconstruct it from UI-specific shortcut names.
    pub fn automatic_program_sections(&self) -> ProgramSections {
        self.automatic_sections
    }

    /// Last successfully established application security mode, if recorded.
    /// Live preparation still revalidates this evidence before execution.
    pub fn observed_data_security(&self) -> crate::commissioning::ObservedDataSecurity {
        match self.previous_commissioning.as_ref().and_then(|record| record.data_security_enabled) {
            Some(true) => crate::commissioning::ObservedDataSecurity::Enabled,
            Some(false) => crate::commissioning::ObservedDataSecurity::Disabled,
            None => crate::commissioning::ObservedDataSecurity::Unknown,
        }
    }

    /// Options for `intent` at `target`. An automatic download receives the
    /// planner's section set; every other intent must carry none.
    pub(crate) fn compile_options(&self, intent: CommissioningIntent, target: TargetSelection) -> CompileOptions {
        let mut options = CompileOptions::new(target);
        options.automatic_sections =
            (intent.download_mode() == Some(DownloadMode::Automatic)).then(|| self.automatic_program_sections());
        options
    }

    /// Compile the same IP-Secure-aware, non-secret plan used by prepared
    /// commissioning without exposing the private credential payload.
    ///
    /// The target is assumed at the device's own address, reached with the
    /// credential [`ProgrammingFacts::offline_from`] selects, in the last
    /// recorded application security mode.
    ///
    /// `profile` must be resolved for this device, for example with
    /// `self.device().resolve_profile(..)`.
    ///
    /// [`ProgrammingFacts::offline_from`]: crate::commissioning::ProgrammingFacts::offline_from
    pub fn compile_preview(
        &self,
        profile: &ResolvedProfile,
        intent: CommissioningIntent,
    ) -> core::result::Result<CompiledProgram, ProjectPlanPreviewError> {
        let options = self.compile_options(intent, TargetSelection::ExistingAddress(self.device.individual_address()));
        let facts = crate::commissioning::ProgrammingFacts {
            data_security: self.observed_data_security(),
            ..crate::commissioning::ProgrammingFacts::offline_from(&self.device)
        };
        self.compile_preview_with(profile, intent, options, facts)
    }

    /// [`Self::compile_preview`] with caller-supplied options and facts, for
    /// adapters that observed the target or need translated messages.
    pub fn compile_preview_with(
        &self,
        profile: &ResolvedProfile,
        intent: CommissioningIntent,
        options: CompileOptions,
        facts: crate::commissioning::ProgrammingFacts,
    ) -> core::result::Result<CompiledProgram, ProjectPlanPreviewError> {
        let input = crate::commissioning::ProgrammingInput::new(self.device.clone(), intent, options).with_facts(facts);
        Ok(input.compile(profile)?)
    }
}

pub struct ProgrammingBatchPlan {
    impact: ProgrammingImpact,
    devices: Vec<PlannedProjectDevice>,
    siat_senders: Vec<ManagedSiatSender>,
    policy: ProgrammingPolicy,
    skip_current: bool,
}

impl ProgrammingBatchPlan {
    /// Apply access and transfer policy to the already evaluated intent, and
    /// derive the safest unambiguous target for each planned device: its
    /// serial number when known, otherwise programming-button discovery for
    /// address assignment or its existing address. Explicit
    /// [`set_target`](Self::set_target) choices survive.
    ///
    /// Changing semantic intent requires a new `plan_commissioning` call.
    pub(crate) fn set_policy(&mut self, policy: ProgrammingPolicy) {
        let ProgrammingPolicy { allow_plaintext, differential: differential_policy, .. } = policy;
        self.policy = policy;
        for planned in &mut self.devices {
            let mut intent = match planned.evaluated_intent {
                CommissioningIntent::AssignAddressAndDownload(mode @ DownloadMode::Automatic)
                | CommissioningIntent::AssignAddressAndDownload(mode @ DownloadMode::Partial(_))
                    if planned.status.individual_address =>
                {
                    CommissioningIntent::Download(mode)
                }
                intent => intent,
            };
            let serial_number = planned.serial_target();
            let target = if intent.mutates_address() {
                serial_number.map_or_else(
                    || TargetSelection::ProgrammingButton(ProgrammingModePolling::default()),
                    TargetSelection::SerialNumber,
                )
            } else {
                serial_number.map_or_else(
                    || TargetSelection::ExistingAddress(planned.device.individual_address()),
                    TargetSelection::SerialNumber,
                )
            };
            let target = planned.target_override.clone().unwrap_or(target);
            if matches!(planned.target_override, Some(TargetSelection::ProgrammingButton(_))) {
                intent = planned.evaluated_intent;
            }
            planned.commissioning =
                ProjectDeviceCommissioningOptions { intent, target, allow_plaintext, differential_policy };
        }
    }

    pub fn device(&self, id: &ProjectDeviceId) -> Option<&PlannedProjectDevice> {
        self.devices.iter().find(|device| device.id == *id)
    }

    pub fn devices(&self) -> &[PlannedProjectDevice] {
        &self.devices
    }
    pub fn impact(&self) -> &ProgrammingImpact {
        &self.impact
    }
    pub fn policy(&self) -> ProgrammingPolicy {
        self.policy
    }

    /// Override physical target acquisition without changing evaluated scope.
    pub(crate) fn set_target(&mut self, id: &ProjectDeviceId, target: TargetSelection) -> Result<()> {
        let device = self
            .devices
            .iter_mut()
            .find(|device| device.id == *id)
            .ok_or_else(|| Error::DeviceConfiguration(format!("device `{id}` is not in the evaluated plan")))?;
        // An explicit physical-button choice reinstates address assignment only
        // when it was part of the evaluated scope. It cannot add application work.
        if matches!(target, TargetSelection::ProgrammingButton(_)) {
            device.commissioning.intent = device.evaluated_intent;
        }
        device.commissioning.target = target;
        device.target_override = Some(device.commissioning.target.clone());
        Ok(())
    }
}

struct ManagedSiatSender {
    device: ProjectDeviceId,
    address: zweidraehte_proto::address::IndividualAddress,
    query: bool,
    zero_sequence_policy: ZeroSiatSequencePolicy,
    /// Unknown senders outside the programmed set are not otherwise part of
    /// batch preflight, so retain the credentials needed for their sync.
    probe_key_material: Option<ResolvedKeyMaterial>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZeroSiatSequencePolicy {
    /// No durable project evidence says that this device has ever emitted a
    /// secure telegram. Its factory sequence base is therefore still usable.
    Untouched,
    /// Existing or incomplete evidence makes zero an unsafe assumption.
    RequireSynchronization,
}

impl ZeroSiatSequencePolicy {
    fn fallback_reason(self) -> Option<&'static str> {
        match self {
            Self::Untouched => Some("the device has no prior commissioning or sequence evidence"),
            Self::RequireSynchronization => None,
        }
    }
}

/// A short-lived, read-only project snapshot. Drop it before changing state.
pub struct ProjectPlanner<'a> {
    project: &'a AuthoredProject,
    state: Option<&'a MutableProjectState>,
    products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>,
    keys: Option<&'a dyn KeyMaterialSource>,
    keyring: Option<&'a Keyring>,
    master_data: Option<&'a ProjectMasterData>,
}

impl<'a> ProjectPlanner<'a> {
    /// Plan `project` with its loaded `products` and nothing else: no durable
    /// state, no project keys, no imported keyring, and only Master Data bound
    /// into the product packages. Add each source that exists.
    ///
    /// ```
    /// # use std::collections::BTreeMap;
    /// # use zweidraehte_client::project::{ProjectPlanner, ProjectProduct};
    /// # use zweidraehte_client::security::Keyring;
    /// # use zweidraehte_project::{AuthoredProject, KeyMaterialSource, MutableProjectState, ProjectDeviceId};
    /// fn installation_planner<'a>(
    ///     project: &'a AuthoredProject,
    ///     products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>,
    ///     state: &'a MutableProjectState,
    ///     project_keys: &'a dyn KeyMaterialSource,
    ///     ets_keyring: &'a Keyring,
    /// ) -> ProjectPlanner<'a> {
    ///     ProjectPlanner::new(project, products).with_state(state).with_keys(project_keys).with_keyring(ets_keyring)
    /// }
    /// ```
    pub fn new(project: &'a AuthoredProject, products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>) -> Self {
        Self { project, state: None, products, keys: None, keyring: None, master_data: None }
    }

    /// The planner for a project store's durable state and keys, as every
    /// store-backed input acquisition builds it.
    pub(super) fn for_store(
        project: &'a AuthoredProject,
        store: &'a zweidraehte_project::ProjectStore,
        products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>,
        keyring: Option<&'a Keyring>,
    ) -> Self {
        Self {
            state: store.state(),
            keys: store.keys().map(|keys| keys as &dyn KeyMaterialSource),
            keyring,
            ..Self::new(project, products)
        }
    }

    /// Durable programming state: deployments and observed sequence numbers.
    pub fn with_state(mut self, state: &'a MutableProjectState) -> Self {
        self.state = Some(state);
        self
    }

    /// The project's own key store.
    pub fn with_keys(mut self, keys: &'a dyn KeyMaterialSource) -> Self {
        self.keys = Some(keys);
        self
    }

    /// An imported ETS keyring, consulted after the project's own keys.
    pub fn with_keyring(mut self, keyring: &'a Keyring) -> Self {
        self.keyring = Some(keyring);
        self
    }

    /// Compile unbound products against this selected installation document.
    /// Without it, only products whose package bound Master Data are usable.
    pub fn with_master_data(mut self, master_data: &'a ProjectMasterData) -> Self {
        self.master_data = Some(master_data);
        self
    }
}

impl ProjectPlanner<'_> {
    pub fn programming_statuses(&self) -> Result<BTreeMap<ProjectDeviceId, DeviceProgrammingStatus>> {
        Ok(self.programming_view()?.statuses)
    }

    pub fn programming_view(&self) -> Result<ProgrammingView> {
        let devices =
            self.project.devices.values().filter(|device| device.active).map(|device| device.id.clone()).collect();
        self.programming_view_for(&devices)
    }

    pub fn programming_view_for(&self, devices: &BTreeSet<ProjectDeviceId>) -> Result<ProgrammingView> {
        let intent = CommissioningIntent::Download(DownloadMode::Automatic);
        let scope =
            product_scope(self.project, &devices.iter().cloned().collect::<Vec<_>>(), BatchSelection::Selected, intent);
        let mut evaluated = self.evaluate(&scope, intent)?;
        evaluated.retain(|id, _| devices.contains(id));
        Ok(ProgrammingView::from_evaluated(self.project, self.state, &evaluated, &[]))
    }

    /// Plan one typed commissioning intent without expanding the physical
    /// target set. Only download intents lower application tables and SIAT;
    /// address assignment and unload remain independent of unrelated project
    /// security data.
    pub fn plan_commissioning(
        &self,
        selected: &[ProjectDeviceId],
        selection: BatchSelection,
        intent: CommissioningIntent,
    ) -> Result<ProgrammingBatchPlan> {
        let project = self.project;
        let state = self.state;
        let includes_application = intent.download_mode().is_some();

        for id in selected {
            if !project.devices.contains_key(id) {
                return Err(Error::DeviceConfiguration(format!("project has no device `{id}`")));
            }
        }

        // Product parsing follows the same scope as the physical operation.
        // Secure application downloads retain the peer closure whose product
        // defaults are required for SIAT; unrelated active products must not
        // veto or delay a named operation.
        let included = product_scope(project, selected, selection, intent);

        let mut evaluated = self.evaluate(&included, intent)?;
        let selected = match selection {
            BatchSelection::All => project
                .devices
                .values()
                .filter(|device| device.active)
                .map(|device| device.id.clone())
                .collect::<Vec<_>>(),
            BatchSelection::AllStale => {
                evaluated.iter().filter(|(_, device)| !device.status.is_complete()).map(|(id, _)| id.clone()).collect()
            }
            BatchSelection::Selected => selected.to_vec(),
        };
        let closure: BTreeSet<_> = selected.iter().cloned().collect();
        let impact = ProgrammingView::from_evaluated(project, state, &evaluated, &selected).impact;
        let mut planned = Vec::with_capacity(closure.len());
        for id in &closure {
            let device = evaluated.remove(id).expect("selected device was evaluated");
            if includes_application {
                reject_deployed_group_key_change(state, device.device.key_material(), &device.net_ids)?;
            }
            planned.push(device);
        }

        // Build this list from project data before talking to any device.
        // Every secure link is required, but only a zero `LastValidSeqNr` is
        // queried during image creation; existing nonzero rows are retained.
        let (required_senders, unknown_senders) = classify_siat_senders(
            planned
                .iter()
                .filter_map(|device| device.device.key_material().application_security())
                .map(|security| security.siat()),
        );
        let mut siat_senders = Vec::new();

        for (id, authored) in &project.devices {
            if !required_senders.contains(&authored.address) {
                continue;
            }

            let query = unknown_senders.contains(&authored.address);
            let Some(serial) = authored.serial else {
                if query {
                    return Err(Error::MissingSenderInput { device: id.0.clone(), address: authored.address });
                }
                continue;
            };
            let zero_sequence_policy = zero_siat_sequence_policy(state, id, &serial);
            let probe_key_material = if query && !closure.contains(id) {
                // Imported SIAT rows need not share an authored net. Evaluate
                // their management-only input explicitly; they remain read
                // dependencies and never enter the physical target set.
                if !evaluated.contains_key(id) {
                    if !self.products.contains_key(id) {
                        return Err(Error::MissingSenderInput { device: id.0.clone(), address: authored.address });
                    }
                    evaluated.extend(self.evaluate(&BTreeSet::from([id.clone()]), CommissioningIntent::AssignAddress)?);
                }
                Some(evaluated.get(id).expect("sender input was evaluated").device.key_material().clone())
            } else {
                None
            };

            siat_senders.push(ManagedSiatSender {
                device: id.clone(),
                address: authored.address,
                query,
                zero_sequence_policy,
                probe_key_material,
            });
        }

        let mut plan = ProgrammingBatchPlan {
            impact,
            devices: planned,
            siat_senders,
            policy: ProgrammingPolicy::default(),
            skip_current: selection == BatchSelection::AllStale
                && intent.download_mode() == Some(DownloadMode::Automatic),
        };
        plan.set_policy(ProgrammingPolicy::default());
        Ok(plan)
    }
}

/// A previous live read may know a higher replay floor than topology or an
/// imported keyring. Only rows which are still required may inherit that
/// value: Security IO downloads replace the complete SIAT, so carrying an
/// obsolete observation forward would silently keep a removed trust edge.
fn merge_retained_target_siat(
    rows: &mut BTreeMap<zweidraehte_proto::address::IndividualAddress, u64>,
    project: &AuthoredProject,
    target: &ProjectDevice,
    state: Option<&MutableProjectState>,
) {
    let Some(serial) = target.serial else { return };
    let serial = format_serial(&serial);
    let Some(observed) = state.and_then(|state| state.devices.get(&serial)) else { return };
    for (identity, &last_valid) in &observed.siat_last_valid {
        let address = match identity {
            zweidraehte_project::SenderIdentity::ManagedSerial(serial) => project
                .devices
                .values()
                .find(|device| device.serial.as_ref().is_some_and(|candidate| format_serial(candidate) == *serial))
                .map(|device| device.address),
            zweidraehte_project::SenderIdentity::UnmanagedAddress(address) => address.parse().ok(),
        };
        if let Some(address) = address
            && let Some(current) = rows.get_mut(&address)
        {
            *current = (*current).max(last_valid);
        }
    }
}

struct EmptyKeyMaterialSource;

impl KeyMaterialSource for EmptyKeyMaterialSource {
    fn list(&self) -> core::result::Result<Vec<KeyMetadata>, KeyStoreError> {
        Ok(Vec::new())
    }

    fn read(&self, _id: &KeyId, _epoch: Option<KeyEpoch>) -> core::result::Result<Option<KeyRecord>, KeyStoreError> {
        Ok(None)
    }
}

impl ProjectPlanner<'_> {
    /// Resolve one snapshot once. Views borrow the result; a batch takes its
    /// selected devices, retaining exactly the keys and geometry it previewed.
    fn evaluate(
        &self,
        included: &BTreeSet<ProjectDeviceId>,
        intent: CommissioningIntent,
    ) -> Result<BTreeMap<ProjectDeviceId, PlannedProjectDevice>> {
        let Self { project, state, products, keys, keyring, master_data } = *self;
        project.validate_download().map_err(|error| {
            Error::DeviceConfiguration(
                error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; "),
            )
        })?;
        let mut resolved = BTreeMap::new();
        for id in included {
            let product =
                products.get(id).ok_or_else(|| Error::DeviceConfiguration(format!("no product loaded for `{id}`")))?;
            resolved.insert(id.clone(), product.evaluate(project, &project.devices[id])?);
        }
        let empty = EmptyKeyMaterialSource;
        if resolved.is_empty() {
            return Ok(BTreeMap::new());
        }
        let keys = keys.unwrap_or(&empty);
        // Evaluation is pure with respect to Master Data acquisition. Packaged
        // documents remain usable without an installation document.
        let bound_only = ProjectMasterData::default();
        let master_data = master_data.unwrap_or(&bound_only);
        let includes_application = intent.download_mode().is_some();
        let senders = includes_application.then(|| derive_senders(project, &resolved, state));
        let mut evaluated = BTreeMap::new();
        for (id, lowered) in resolved {
            let authored = &project.devices[&id];
            let document = master_data.for_product(lowered.resolved.product())?;
            let serial_addressing = SerialAddressingSupport::for_product(lowered.resolved.product(), &document);
            let supports_data_secure = lowered.resolved.product().supports_data_secure();
            // Management-only operations need credentials, not unrelated group keys.
            let resolved = lowered.resolved;
            let management = (!includes_application).then(|| resolved.without_group_communication());
            let mut keys = resolve_project_key_material(
                management.as_ref().unwrap_or(&resolved),
                &id.0,
                &lowered.net_ids,
                &[],
                keys,
                keyring,
                authored.data_secure.is_enabled(),
            )?;
            let secured_addresses = keys
                .secured_groups()
                .iter()
                .filter(|(_, protection)| **protection != GroupObjectProtection::Plain)
                .map(|(address, _)| *address)
                .collect();
            let siat = senders.as_ref().map_or_else(Vec::new, |senders| {
                derive_target_siat(project, authored, senders, state, &secured_addresses)
            });
            if let Some(security) = keys.application_security_mut() {
                let mut rows: BTreeMap<_, _> = security.siat().iter().copied().collect();
                for inactive in project.devices.values().filter(|device| !device.active) {
                    rows.remove(&inactive.address);
                }
                for (address, last_valid) in siat {
                    rows.entry(address).and_modify(|old| *old = (*old).max(last_valid)).or_insert(last_valid);
                }
                merge_retained_target_siat(&mut rows, project, authored, state);
                security.replace_siat(rows.into_iter().collect());
            }
            if includes_application {
                keys::validate_application_security(&resolved, keys.application_security())?;
            }
            let device = resolved.into_keyed(keys).bind_master_data(document)?;
            let (mut desired_manifest, image_requirements) = if includes_application {
                let image = device.project_preview(&id, authored, state)?;
                let requirements = image.requirements().to_vec();
                (image.manifest, requirements)
            } else {
                Default::default()
            };
            desired_manifest.insert(
                ProgrammingSection::Address,
                zweidraehte_project::semantic_fingerprint("individual-address", "desired", authored.address.as_bytes()),
            );
            if includes_application {
                add_credential_commitments(&mut desired_manifest, device.key_material())?;
            }
            let status = if includes_application {
                status_with_requirements(&id, state, &desired_manifest, !image_requirements.is_empty())
            } else {
                DeviceProgrammingStatus::NONE
            };
            let automatic_sections = if includes_application && image_requirements.is_empty() {
                changed_program_sections(state.and_then(|state| state.deployment(&id.0)), &desired_manifest)
            } else {
                ProgramSections::all()
            };
            let previous_commissioning =
                state.and_then(|state| state.deployment(&id.0)).and_then(|deployment| deployment.commissioning.clone());
            evaluated.insert(id.clone(), PlannedProjectDevice {
                id,
                device,
                evaluated_intent: intent,
                target_override: None,
                serial_addressing,
                supports_data_secure,
                data_secure_enabled: authored.data_secure.is_enabled(),
                commissioning: ProjectDeviceCommissioningOptions {
                    intent,
                    target: TargetSelection::ExistingAddress(authored.address),
                    allow_plaintext: true,
                    differential_policy: DifferentialPolicy::FallBackToUndifferenced,
                },
                desired_manifest,
                image_requirements,
                status,
                automatic_sections,
                net_ids: lowered.net_ids,
                previous_commissioning,
                warnings: lowered.warnings,
            });
        }
        Ok(evaluated)
    }
}

impl ProgrammingView {
    fn from_evaluated(
        project: &AuthoredProject,
        state: Option<&MutableProjectState>,
        devices: &BTreeMap<ProjectDeviceId, PlannedProjectDevice>,
        selected: &[ProjectDeviceId],
    ) -> Self {
        let manifests = devices.iter().map(|(id, device)| (id.clone(), device.desired_manifest.clone())).collect();
        let requirements = devices
            .iter()
            .filter(|(_, device)| !device.image_requirements.is_empty())
            .map(|(id, device)| (id.clone(), device.image_requirements.clone()))
            .collect();
        let statuses = devices.iter().map(|(id, device)| (id.clone(), device.status)).collect();
        let impact = programming_impact(project, state, &manifests, selected, &requirements);
        Self { manifests, requirements, statuses, impact }
    }
}

impl MaterializedDevice {
    fn project_preview(
        &self,
        id: &ProjectDeviceId,
        authored: &ProjectDevice,
        state: Option<&MutableProjectState>,
    ) -> Result<crate::commissioning::ProgramImage> {
        let product = self.product();
        let product_mask = product
            .mask_version()
            .ok_or_else(|| Error::DeviceConfiguration(format!("product `{}` has no mask version", product.id())))?;
        let previous =
            state.and_then(|state| state.deployment(&id.0)).and_then(|evidence| evidence.commissioning.as_ref());
        let mut selection = ProfileSelection::discovered(product_mask.as_u16());
        if let Some(descriptor) = previous
            .filter(|record| record.mask.dd0 == product_mask.as_u16())
            .and_then(|record| record.mask.management_descriptor_01)
        {
            selection = selection.with_management_descriptor(descriptor);
        }
        let mut profile = self.resolve_profile(&selection).map_err(Error::Catalog)?;
        let observed_data_security = previous
            .filter(|record| recorded_profile_matches(&profile, record))
            .and_then(|record| record.data_security_enabled)
            .map_or(crate::commissioning::ObservedDataSecurity::Unknown, |enabled| {
                if enabled {
                    crate::commissioning::ObservedDataSecurity::Enabled
                } else {
                    crate::commissioning::ObservedDataSecurity::Disabled
                }
            });
        // Refine the profile with what the matching deployment observed on
        // this target. A record of another profile describes other hardware.
        if let Some(record) = previous.filter(|record| recorded_profile_matches(&profile, record)) {
            let compile_status =
                |error: CompileError| Error::DeviceConfiguration(format!("could not compile `{id}` status: {error}"));
            if let Some(size) = record.association_table_entry_size {
                profile = profile
                    .with_association_table_entry_size(match size {
                        CommissioningAssociationEntrySize::TwoBytes => AssociationTableEntrySize::TwoBytes,
                        CommissioningAssociationEntrySize::FourBytes => AssociationTableEntrySize::FourBytes,
                    })
                    .map_err(|error| compile_status(error.into()))?;
            }
            for observed in &record.observed_property_types {
                profile = profile
                    .with_observed_property_type(observed.object.clone(), observed.property_id, observed.pdt)
                    .map_err(compile_status)?;
            }
        }
        let input = ProgrammingInput::new(
            self.clone(),
            CommissioningIntent::Download(DownloadMode::Automatic),
            CompileOptions::new(TargetSelection::ExistingAddress(authored.address)),
        )
        .with_facts(crate::commissioning::ProgrammingFacts {
            data_security: observed_data_security,
            ..Default::default()
        });
        input
            .preview(&profile)
            .map_err(|error| Error::DeviceConfiguration(format!("could not compile `{id}` status: {error}")))
    }
}

fn recorded_profile_matches(profile: &ResolvedProfile, record: &ProjectCommissioningDeploymentRecord) -> bool {
    record.version == COMMISSIONING_DEPLOYMENT_RECORD_VERSION
        && record.mask.full_id == profile.mask().full_id
        && record.mask.dd0 == profile.mask().dd0
        && record.mask.management_descriptor_01 == profile.mask().management_descriptor_01
        && usize::try_from(record.variant.source_index).ok() == Some(profile.variant().source_index)
        && record.variant.legacy_version == profile.variant().legacy_version
        && record.variant.ets3_system_plugin == profile.variant().ets3_system_plugin
        && record.master_data_fingerprint == profile.master_data_fingerprint()
}

fn add_credential_commitments(manifest: &mut ProgrammingManifest, material: &ResolvedKeyMaterial) -> Result<()> {
    set_credential_commitments(manifest, credential_commitments(material))
}

fn credential_commitments(material: &ResolvedKeyMaterial) -> Vec<CredentialCommitment> {
    material.provenance().iter().filter_map(CredentialCommitment::from_metadata).collect()
}

fn set_credential_commitments(
    manifest: &mut ProgrammingManifest,
    credentials: Vec<CredentialCommitment>,
) -> Result<()> {
    manifest.credentials = credentials;
    manifest.credentials.sort_by(|a, b| a.id.cmp(&b.id));
    // Matching project and keyring sources can corroborate one credential.
    // Coalesce only identical proofs; conflicting versions still fail validation.
    manifest.credentials.dedup();
    manifest.validate().map_err(Error::DeviceConfiguration)?;
    let credentials = std::mem::take(&mut manifest.credentials);
    for proof in &credentials {
        manifest.mix(proof.section(), "credential", &proof.identity(), &proof.commitment);
    }
    manifest.credentials = credentials;
    Ok(())
}

fn status_with_requirements(
    id: &ProjectDeviceId,
    state: Option<&MutableProjectState>,
    desired: &ProgrammingManifest,
    pending: bool,
) -> DeviceProgrammingStatus {
    let status = device_programming_status(id, state, desired);
    if pending {
        DeviceProgrammingStatus { individual_address: status.individual_address, ..DeviceProgrammingStatus::NONE }
    } else {
        status
    }
}

fn device_programming_status(
    id: &ProjectDeviceId,
    state: Option<&MutableProjectState>,
    desired: &ProgrammingManifest,
) -> DeviceProgrammingStatus {
    let Some(state) = state else { return DeviceProgrammingStatus::NONE };
    if state.inconsistent_devices.contains(&id.0) {
        return DeviceProgrammingStatus::NONE;
    }
    let Some(deployed) = state.deployment(&id.0) else { return DeviceProgrammingStatus::NONE };
    let matches = |section| {
        desired.section(section).is_some_and(|artifacts| Some(artifacts) == deployed.manifest.section(section))
    };

    DeviceProgrammingStatus {
        individual_address: matches(ProgrammingSection::Address),
        application_program: matches(ProgrammingSection::ApplicationProgram1)
            && (desired.section(ProgrammingSection::ApplicationProgram2).is_none()
                || matches(ProgrammingSection::ApplicationProgram2)),
        parameters: matches(ProgrammingSection::Parameters),
        group_communication: matches(ProgrammingSection::GroupCommunication),
        medium_configuration: matches(ProgrammingSection::Configuration),
    }
}

fn changed_sections(
    deployed: Option<&zweidraehte_project::DeviceDeploymentEvidence>,
    desired: &ProgrammingManifest,
) -> BTreeSet<ProgrammingSection> {
    let mut changed = BTreeSet::new();
    for section in [
        ProgrammingSection::Address,
        ProgrammingSection::ApplicationProgram1,
        ProgrammingSection::Parameters,
        ProgrammingSection::GroupCommunication,
        ProgrammingSection::Configuration,
    ] {
        if desired.section(section) != deployed.and_then(|deployment| deployment.manifest.section(section)) {
            changed.insert(section);
        }
    }
    if desired.section(ProgrammingSection::ApplicationProgram2).is_some()
        && desired.section(ProgrammingSection::ApplicationProgram2)
            != deployed.and_then(|deployment| deployment.manifest.section(ProgrammingSection::ApplicationProgram2))
    {
        changed.insert(ProgrammingSection::ApplicationProgram2);
    }
    changed
}

fn changed_program_sections(
    deployed: Option<&zweidraehte_project::DeviceDeploymentEvidence>,
    desired: &ProgrammingManifest,
) -> ProgramSections {
    let changed = changed_sections(deployed, desired);
    let mut result = ProgramSections::empty();
    for section in changed {
        let program = match section {
            ProgrammingSection::Address => continue,
            ProgrammingSection::ApplicationProgram1 => ProgramSections::APPLICATION_PROGRAM_1,
            ProgrammingSection::ApplicationProgram2 => ProgramSections::APPLICATION_PROGRAM_2,
            ProgrammingSection::Parameters => ProgramSections::PARAMETERS,
            ProgrammingSection::GroupCommunication => ProgramSections::GROUP_COMMUNICATION,
            ProgrammingSection::Configuration => ProgramSections::CONFIGURATION,
        };
        result = result.union(program);
    }
    if result.is_empty() { ProgramSections::all() } else { result }
}

fn programming_impact(
    project: &AuthoredProject,
    state: Option<&MutableProjectState>,
    manifests: &BTreeMap<ProjectDeviceId, ProgrammingManifest>,
    selected: &[ProjectDeviceId],
    requirements: &BTreeMap<ProjectDeviceId, Vec<ImageRequirement>>,
) -> ProgrammingImpact {
    let selected = selected.iter().cloned().collect::<BTreeSet<_>>();
    let mut affected = BTreeMap::new();
    for (id, manifest) in manifests {
        if !project.devices[id].active {
            continue;
        }
        let mut changed = changed_sections(state.and_then(|state| state.deployment(&id.0)), manifest);
        if requirements.contains_key(id) {
            changed.extend([
                ProgrammingSection::ApplicationProgram1,
                ProgrammingSection::Parameters,
                ProgrammingSection::GroupCommunication,
                ProgrammingSection::Configuration,
            ]);
        }
        if !changed.is_empty() || selected.contains(id) {
            affected.insert(id.clone(), changed);
        }
    }
    ProgrammingImpact { selected, affected }
}

fn classify_siat_senders<'a>(
    tables: impl Iterator<Item = &'a [(zweidraehte_proto::address::IndividualAddress, u64)]>,
) -> (BTreeSet<zweidraehte_proto::address::IndividualAddress>, BTreeSet<zweidraehte_proto::address::IndividualAddress>)
{
    let mut required = BTreeSet::new();
    let mut unknown = BTreeSet::new();

    for table in tables {
        for &(address, last_valid) in table {
            required.insert(address);
            if last_valid == 0 {
                unknown.insert(address);
            }
        }
    }

    (required, unknown)
}

fn zero_siat_sequence_policy(
    state: Option<&MutableProjectState>,
    device: &ProjectDeviceId,
    serial: &[u8; 6],
) -> ZeroSiatSequencePolicy {
    let Some(state) = state else { return ZeroSiatSequencePolicy::RequireSynchronization };

    if state.recovery_required || state.inconsistent_devices.contains(&device.0) {
        return ZeroSiatSequencePolicy::RequireSynchronization;
    }

    let serial = format_serial(serial);
    let identity = SenderIdentity::ManagedSerial(serial.clone());
    let sequence_observed = state.devices.contains_key(&serial)
        || state.sender_floors.contains_key(&identity)
        || state.devices.values().any(|observation| observation.siat_last_valid.contains_key(&identity));

    // The explicit all-false status is written only by a successful complete
    // unload. Check newer observations first: the status describes one past
    // transition and must not permanently override later device activity.
    if sequence_observed {
        return ZeroSiatSequencePolicy::RequireSynchronization;
    }

    if state.deployments.contains_key(&device.0) {
        ZeroSiatSequencePolicy::RequireSynchronization
    } else {
        // Untouched and successfully fully-unloaded devices have the same
        // physical sequence baseline. The unload outcome clears every older
        // observation atomically, so absence is sufficient here.
        ZeroSiatSequencePolicy::Untouched
    }
}

fn accept_zero_siat_sequence(sender: &ManagedSiatSender, cause: &str) -> Result<()> {
    let Some(reason) = sender.zero_sequence_policy.fallback_reason() else {
        return Err(Error::DeviceConfiguration(format!(
            "could not establish the outgoing sequence for SIAT sender `{}` at {}: {cause}; durable project state does not prove that zero is safe",
            sender.device, sender.address
        )));
    };

    log::warn!(
        "could not establish the outgoing sequence for SIAT sender `{}` at {}; using zero because {reason}: {cause}",
        sender.device,
        sender.address
    );

    Ok(())
}

fn derive_senders(
    project: &AuthoredProject,
    lowered: &BTreeMap<ProjectDeviceId, EvaluatedProjectDevice>,
    state: Option<&MutableProjectState>,
) -> BTreeMap<NetId, BTreeMap<zweidraehte_proto::address::IndividualAddress, u64>> {
    let mut senders: BTreeMap<NetId, BTreeMap<_, u64>> = BTreeMap::new();
    for (id, device) in lowered {
        let authored = &project.devices[id];
        if !authored.active {
            continue;
        }

        // A retained deployment without Group Communication evidence is a
        // factual application unload (or an address/configuration-only
        // commissioning result). It must not remain an effective secure
        // sender merely because the authored topology still describes the
        // desired application. Fresh devices have no deployment entry and
        // remain in the desired installation so programming order does not
        // change the eventual SIAT.
        if !deployment_allows_siat_sender(id, state) {
            continue;
        }

        let flags: BTreeMap<_, _> =
            device.resolved.com_objects().iter().map(|object| (object.number, object.flags)).collect();
        for object in authored.objects.values() {
            let Some(flags) = flags.get(&object.com_object) else { continue };
            if !flags.communication_enable()
                || !(flags.transmission_enable() || flags.read_enable() || flags.read_on_init())
            {
                continue;
            }
            let Some(primary) =
                object.memberships.iter().find(|membership| membership.role == ProjectMembershipRole::Primary)
            else {
                continue;
            };
            let last_valid = authored
                .serial
                .and_then(|serial| {
                    let serial = format_serial(&serial);
                    state
                        .and_then(|state| state.devices.get(&serial))
                        .map(|observation| observation.outgoing_next.saturating_sub(1))
                })
                .unwrap_or(0);
            senders.entry(primary.net.clone()).or_default().insert(authored.address, last_valid);
        }
    }
    for sender in project.external_senders.values() {
        let identity = zweidraehte_project::SenderIdentity::UnmanagedAddress(sender.address.to_string());
        let last_valid = state.and_then(|state| state.sender_floors.get(&identity)).copied().unwrap_or(0);
        for net in &sender.nets {
            senders.entry(net.clone()).or_default().insert(sender.address, last_valid);
        }
    }
    senders
}

fn deployment_allows_siat_sender(id: &ProjectDeviceId, state: Option<&MutableProjectState>) -> bool {
    !state.and_then(|state| state.deployment(&id.0)).is_some_and(|deployment| deployment.application_unloaded)
}

fn derive_target_siat(
    project: &AuthoredProject,
    target: &ProjectDevice,
    senders: &BTreeMap<NetId, BTreeMap<zweidraehte_proto::address::IndividualAddress, u64>>,
    _state: Option<&MutableProjectState>,
    secured_addresses: &BTreeSet<GroupAddress>,
) -> Vec<(zweidraehte_proto::address::IndividualAddress, u64)> {
    let target_nets: BTreeSet<_> = target
        .objects
        .values()
        .flat_map(|object| object.memberships.iter().map(|membership| membership.net.clone()))
        .filter(|id| project.nets.get(id).is_some_and(|net| secured_addresses.contains(&net.address)))
        .collect();
    let mut rows: BTreeMap<zweidraehte_proto::address::IndividualAddress, u64> = BTreeMap::new();
    for net in target_nets {
        if let Some(net_senders) = senders.get(&net) {
            for (&address, &last_valid) in net_senders {
                rows.entry(address).and_modify(|old| *old = (*old).max(last_valid)).or_insert(last_valid);
            }
        }
    }
    rows.remove(&target.address);
    rows.into_iter().collect()
}

fn reject_deployed_group_key_change(
    state: Option<&MutableProjectState>,
    material: &ResolvedKeyMaterial,
    net_ids: &BTreeMap<GroupAddress, String>,
) -> Result<()> {
    let Some(state) = state else { return Ok(()) };
    for net_id in net_ids.values() {
        let current = material.provenance().iter().find(|metadata| {
            metadata.id.kind == KeyKind::GroupKey && metadata.id.scope == KeyScope::Group(net_id.clone())
        });
        let Some(current) = current else { continue };
        let current = CredentialCommitment::from_metadata(current).expect("group keys have deployed commitments");
        let changed = state.deployments.values().any(|deployment| {
            deployment.manifest.credentials.iter().any(|old| old.id == current.id && old != &current)
        });
        if changed {
            return Err(Error::DeviceConfiguration(format!(
                "active deployed group key for net `{net_id}` changed; key rotation is not implemented"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

pub(crate) mod persistence;
mod product;
mod sequence;
mod session;

pub use persistence::{KeyringExport, build_project_keyring};
pub use product::{EvaluatedProjectDevice, ProjectProduct};
pub use sequence::ProjectSeqStore;
pub(crate) use session::ProjectProgrammingInputs;
pub use session::{
    PreparedProjectSecurity, ProjectBatchFailure, ProjectBatchReport, ProjectCommissioningSession,
    ProjectDeviceCommissioningOptions, ProjectDeviceCommissioningReport,
};
