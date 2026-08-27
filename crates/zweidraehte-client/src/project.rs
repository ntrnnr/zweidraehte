//! Product-aware lowering of authored project devices.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zweidraehte_ets_files::runtime::Device;
use zweidraehte_ets_files::runtime::configuration::{
    ObjectFlagOverrides as ProductFlagOverrides, ObjectSetting, ParameterSetting, ProductConfiguration,
    ProductDptReference, ProductDptReferences, apply_configuration, effective_com_objects,
};
use zweidraehte_ets_files::runtime::model::ParameterValue as ProductParameterValue;
use zweidraehte_ets_files::schema::ApplicationProgram;
use zweidraehte_project::{
    AuthoredProject, DeploymentFingerprints, DeviceProgrammingStatus, ImpactReason, KeyId, KeyKind, KeyMaterialSource,
    KeyScope, McbSnapshot, MembershipRole as ProjectMembershipRole, MutableProjectState, NetId,
    NetSecurityPolicy as ProjectSecurityPolicy, ObjectPriority, ParamValue, ProjectDevice, ProjectDeviceId,
    ProjectEvent, ProjectImpact, ProjectKeyStore, ProjectLock, ProjectStore, SecretBytes, SenderIdentity,
};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::com_object::ComObjectType;
use zweidraehte_proto::messages::knx::Priority;

use crate::download::{
    DeviceConfiguration, DeviceIdentity, DownloadScope, GroupObjectProtection, MembershipRole, NetSecurityPolicy,
    ObjectMembership, ProductData, ResolvedProject, resolve_product_configuration,
};
use crate::error::{Error, Result};
use crate::security::format_serial;
use crate::security::{Keyring, KeyringDevice, ResolvedKeyMaterial, resolve_project_key_material};
use crate::{DeviceProgrammer, KnxBus, PreparedProgramming, ProgrammingOptions, ProgrammingRequest, ProgrammingScope};

#[derive(Debug, Clone)]
pub struct LoweredProjectDevice {
    pub id: ProjectDeviceId,
    pub resolved: ResolvedProject,
    /// Protocol address to logical net identity, used to select group keys.
    pub net_ids: BTreeMap<GroupAddress, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProjectProduct {
    pub program: ApplicationProgram,
    pub product: ProductData,
}

impl ProjectProduct {
    pub fn load(path: &Path, catalog_product: Option<&str>, application_program: Option<&str>) -> Result<Self> {
        let loaded =
            zweidraehte_ets_files::archive::load_program(path, zweidraehte_ets_files::archive::ProgramSelection {
                catalog_product,
                application_program,
            })?;
        let (program, _, _) = loaded.into_parts()?;
        let product = ProductData::from_program(&program)?;
        Ok(Self { program, product })
    }
}

pub fn load_project_products(store: &ProjectStore) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>> {
    store
        .authored()
        .devices
        .iter()
        .map(|(id, device)| {
            let path = store.authored().resolve_product_path(device).ok_or_else(|| {
                Error::DeviceConfiguration(format!("project device `{id}` has no resolvable product path"))
            })?;
            let product =
                ProjectProduct::load(&path, device.catalog_product.as_deref(), device.application_program.as_deref())?;
            Ok((id.clone(), product))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchSelection {
    Selected {
        include_affected: bool,
        force_single: bool,
    },
    /// Select every authored device, regardless of deployment fingerprints.
    /// Address-only commissioning uses this because an application deployment
    /// record is not proof that the live IA still matches the project.
    All,
    AllStale,
}

#[derive(Clone)]
pub struct PlannedProjectDevice {
    pub id: ProjectDeviceId,
    pub product: ProductData,
    pub configuration: crate::download::DeviceConfiguration,
    pub supports_data_secure: bool,
    pub data_secure_enabled: bool,
    pub key_material: ResolvedKeyMaterial,
    pub fingerprints: DeploymentFingerprints,
    /// Smallest semantic application scope justified by the last successful
    /// deployment. The mask compiler may widen this to a supported superset
    /// or to a full download.
    pub download_scope: DownloadScope,
    /// Device-generated CRC evidence from the previous successful download.
    pub previous_mcb: Vec<McbSnapshot>,
    /// Other project devices whose Security Individual Address Table names
    /// this device as a sender. Moving this IA makes their group-
    /// communication configuration stale.
    pub siat_consumers: Vec<ProjectDeviceId>,
    pub warnings: Vec<String>,
}

pub struct ProgrammingBatchPlan {
    pub impact: ProjectImpact,
    pub devices: Vec<PlannedProjectDevice>,
    siat_senders: Vec<ManagedSiatSender>,
}

struct ManagedSiatSender {
    address: zweidraehte_proto::address::IndividualAddress,
    query: bool,
    /// Unknown senders outside the affected closure are not otherwise part of
    /// batch preflight, so retain the credentials needed for their sync.
    probe_key_material: Option<ResolvedKeyMaterial>,
}

pub struct ProjectPlanRequest<'a> {
    pub project: &'a AuthoredProject,
    pub state: Option<&'a MutableProjectState>,
    pub selected: &'a [ProjectDeviceId],
    pub selection: BatchSelection,
    pub products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>,
    pub keys: &'a dyn KeyMaterialSource,
    pub keyring: Option<&'a Keyring>,
    pub scope: ProgrammingScope,
}

pub struct PreparedProjectDevice {
    planned: PlannedProjectDevice,
    programming: PreparedProgramming,
}

impl PreparedProjectDevice {
    pub fn id(&self) -> &ProjectDeviceId {
        &self.planned.id
    }

    pub fn planned(&self) -> &PlannedProjectDevice {
        &self.planned
    }

    pub fn programming(&self) -> &PreparedProgramming {
        &self.programming
    }
}

pub struct PreparedProjectBatch {
    impact: ProjectImpact,
    devices: Vec<PreparedProjectDevice>,
}

impl PreparedProjectBatch {
    pub fn impact(&self) -> &ProjectImpact {
        &self.impact
    }

    pub fn devices(&self) -> &[PreparedProjectDevice] {
        &self.devices
    }
}

#[derive(Debug)]
pub struct ProjectDeviceProgrammingReport {
    pub id: ProjectDeviceId,
    pub report: crate::ProgrammingReport,
}

#[derive(Debug, Default)]
pub struct ProjectBatchReport {
    pub devices: Vec<ProjectDeviceProgrammingReport>,
}

/// Owns the project lock and journal for one mutable bus session.
pub struct ProjectProgrammingSession {
    store: Arc<Mutex<ProjectStore>>,
    _lock: ProjectLock,
}

impl ProjectProgrammingSession {
    pub fn begin(mut store: ProjectStore) -> Result<Self> {
        let lock = store.acquire_lock()?;
        store.begin_mutation(&lock)?;
        Ok(Self { store: Arc::new(Mutex::new(store)), _lock: lock })
    }

    /// Open the same retained session in the explicitly requested recovery
    /// mode. Secure transmission remains blocked until
    /// [`finish_recovery`](Self::finish_recovery) records completion.
    pub fn begin_recovery(mut store: ProjectStore) -> Result<Self> {
        let lock = store.acquire_recovery_lock()?;
        store.begin_recovery(&lock)?;
        Ok(Self { store: Arc::new(Mutex::new(store)), _lock: lock })
    }

    pub fn shared_store(&self) -> Arc<Mutex<ProjectStore>> {
        Arc::clone(&self.store)
    }

    pub fn finish(self) -> Result<()> {
        self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?.compact()?;
        Ok(())
    }

    pub fn finish_recovery(self) -> Result<()> {
        let mut store = self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?;
        store.finish_recovery()?;
        store.compact()?;
        Ok(())
    }
}

/// Build the ETS keyring representation of a project's active security
/// material and forward-only device sequence observations.
///
/// Historical group-key epochs and the commissioning client's own sending
/// counter cannot be represented by the `.knxkeys` schema. The active epoch
/// for every logical net is exported; `client_next` remains authoritative in
/// the project state.
pub fn build_project_keyring(
    project: &AuthoredProject,
    state: &MutableProjectState,
    keys: &dyn KeyMaterialSource,
    project_name: impl Into<String>,
    created_by: impl Into<String>,
    created: impl Into<String>,
) -> Result<Keyring> {
    // A live SIAT read may be newer than the direct observation of its
    // sender. ETS has one sequence value per device, so export the greatest
    // last-valid value learned through any project-state path.
    let mut sender_last_valid = state.sender_floors.clone();
    for (serial, observation) in &state.devices {
        let identity = SenderIdentity::ManagedSerial(serial.clone());
        let direct = observation.outgoing_next.saturating_sub(1);
        sender_last_valid.entry(identity).and_modify(|old| *old = (*old).max(direct)).or_insert(direct);
        for (sender, &last_valid) in &observation.siat_last_valid {
            sender_last_valid
                .entry(sender.clone())
                .and_modify(|old| *old = (*old).max(last_valid))
                .or_insert(last_valid);
        }
    }

    let mut group_keys = BTreeMap::new();
    for net in project.nets.values() {
        let id = KeyId { scope: KeyScope::Group(net.id.0.clone()), kind: KeyKind::GroupKey };
        let Some(record) = keys.read(&id, None)? else { continue };
        let address = u16::from_be_bytes(net.address.0);
        let key = record.value.key16()?;
        if let Some(previous) = group_keys.insert(address, key)
            && previous != key
        {
            return Err(Error::DeviceConfiguration(format!(
                "multiple project nets assign different keys to group address {}",
                net.address
            )));
        }
    }

    let mut devices = Vec::new();
    let mut occupied_addresses = BTreeSet::new();
    for device in project.devices.values() {
        let scope = KeyScope::Device(device.id.0.clone());
        let fdsk = keys.read(&KeyId { scope: scope.clone(), kind: KeyKind::Fdsk }, None)?;
        let tool_key = keys.read(&KeyId { scope, kind: KeyKind::ToolKey }, None)?;
        let mut serial = device.serial;
        if let Some(embedded) = fdsk.as_ref().and_then(|record| record.embedded_serial) {
            if serial.is_some_and(|configured| configured != embedded) {
                return Err(Error::DeviceConfiguration(format!(
                    "device `{}` serial disagrees with its FDSK certificate",
                    device.id
                )));
            }
            serial = serial.or(Some(embedded));
        }
        let sequence_number = serial
            .as_ref()
            .and_then(|serial| sender_last_valid.get(&SenderIdentity::ManagedSerial(format_serial(serial))))
            .copied()
            .unwrap_or(0);
        let fdsk = fdsk.map(|record| record.value.key16()).transpose()?;
        let tool_key = tool_key.map(|record| record.value.key16()).transpose()?;

        // Plain, unobserved devices with no credentials add no information to
        // a security keyring. Data-Secure devices stay visible even while
        // incompletely provisioned so the export exposes that condition.
        if fdsk.is_none() && tool_key.is_none() && sequence_number == 0 && !device.data_secure.is_enabled() {
            continue;
        }
        if !occupied_addresses.insert(device.address) {
            return Err(Error::DeviceConfiguration(format!(
                "multiple keyring devices use individual address {}",
                device.address
            )));
        }
        devices.push(
            KeyringDevice::new(device.address)
                .with_tool_key(tool_key)
                .with_fdsk(fdsk)
                .with_serial(serial)
                .with_sequence_number(sequence_number),
        );
    }

    // Unmanaged secure senders have no project key slot, but their observed
    // last-valid number is useful to a later import and to SIAT derivation.
    for sender in project.external_senders.values() {
        let identity = SenderIdentity::UnmanagedAddress(sender.address.to_string());
        let sequence_number = sender_last_valid.get(&identity).copied().unwrap_or(0);
        if sequence_number == 0 {
            continue;
        }
        if !occupied_addresses.insert(sender.address) {
            return Err(Error::DeviceConfiguration(format!(
                "managed and external keyring devices share individual address {}",
                sender.address
            )));
        }
        devices.push(KeyringDevice::new(sender.address).with_sequence_number(sequence_number));
    }
    devices.sort_by_key(|device| u16::from_be_bytes(device.individual_address.0));

    Ok(Keyring::new(project_name.into(), created_by.into(), created.into())
        .with_group_keys(group_keys)
        .with_devices(devices))
}

/// Project-wide preflight and SIAT derivation above [`crate::DeviceProgrammer`].
#[derive(Debug, Default)]
pub struct ProjectProgrammer;

struct PlanningContext<'a> {
    project: &'a AuthoredProject,
    products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>,
    lowered: BTreeMap<ProjectDeviceId, LoweredProjectDevice>,
}

impl<'a> PlanningContext<'a> {
    fn new(project: &'a AuthoredProject, products: &'a BTreeMap<ProjectDeviceId, ProjectProduct>) -> Result<Self> {
        project.validate_download().map_err(|error| {
            Error::DeviceConfiguration(
                error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; "),
            )
        })?;
        let mut lowered = BTreeMap::new();
        for id in project.devices.keys() {
            let product =
                products.get(id).ok_or_else(|| Error::DeviceConfiguration(format!("no product loaded for `{id}`")))?;
            lowered.insert(
                id.clone(),
                lower_project_device(project, &project.devices[id], product.program.clone(), &product.product)?,
            );
        }
        Ok(Self { project, products, lowered })
    }

    fn fingerprints(
        &self,
        keys: Option<&dyn KeyMaterialSource>,
        keyring: Option<&Keyring>,
        include_security: bool,
    ) -> Result<BTreeMap<ProjectDeviceId, DeploymentFingerprints>> {
        let mut fingerprints = self
            .project
            .devices
            .keys()
            .map(|id| {
                let product = &self.products[id].product;
                let mut fingerprints = effective_fingerprints(self.project, id, &self.lowered[id], product);
                if include_security {
                    augment_key_fingerprint(self.project, id, &mut fingerprints, keys, keyring)?;
                }
                Ok((id.clone(), fingerprints))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        if include_security {
            augment_siat_fingerprints(self.project, &mut fingerprints, keyring);
        }
        Ok(fingerprints)
    }
}

impl ProjectProgrammer {
    pub fn new() -> Self {
        Self
    }

    /// Product- and key-aware fingerprints used by status and stale
    /// selection. This is deliberately bus-independent.
    pub fn deployment_fingerprints(
        &self,
        project: &AuthoredProject,
        products: &BTreeMap<ProjectDeviceId, ProjectProduct>,
        keys: Option<&dyn KeyMaterialSource>,
        keyring: Option<&Keyring>,
    ) -> Result<BTreeMap<ProjectDeviceId, DeploymentFingerprints>> {
        PlanningContext::new(project, products)?.fingerprints(keys, keyring, true)
    }

    /// Calculate the ETS-style Adr/Prg/Par/Grp/Cfg state for every project
    /// device from durable programming evidence and current desired values.
    pub fn programming_statuses(
        &self,
        project: &AuthoredProject,
        state: Option<&MutableProjectState>,
        products: &BTreeMap<ProjectDeviceId, ProjectProduct>,
        keys: Option<&dyn KeyMaterialSource>,
        keyring: Option<&Keyring>,
    ) -> Result<BTreeMap<ProjectDeviceId, DeviceProgrammingStatus>> {
        let fingerprints = self.deployment_fingerprints(project, products, keys, keyring)?;

        Ok(project
            .devices
            .keys()
            .map(|id| {
                let status = device_programming_status(id, state, &fingerprints[id]);
                (id.clone(), status)
            })
            .collect())
    }

    /// Plan only the key/configuration material needed by the selected live
    /// phase. Address commissioning deliberately does not require group keys
    /// or derive SIAT, because ETS treats those as application configuration.
    pub fn plan(&self, request: ProjectPlanRequest<'_>) -> Result<ProgrammingBatchPlan> {
        let ProjectPlanRequest { project, state, selected, selection, products, keys, keyring, scope } = request;
        // Lower every member before resolving credentials or mutating keys.
        // This makes a batch all-or-nothing through product validation and
        // mask-independent table checks.
        let context = PlanningContext::new(project, products)?;
        let fingerprints = context.fingerprints(Some(keys), keyring, scope.includes_application())?;
        let selected = match selection {
            BatchSelection::All => project.devices.keys().cloned().collect::<Vec<_>>(),
            BatchSelection::AllStale => affected_devices(project, state, &fingerprints),
            BatchSelection::Selected { .. } => selected.to_vec(),
        };
        for id in &selected {
            if !project.devices.contains_key(id) {
                return Err(Error::DeviceConfiguration(format!("project has no device `{id}`")));
            }
        }
        let impact = effective_impact(project, state, &selected, &fingerprints);
        let closure = match selection {
            BatchSelection::Selected { force_single: true, .. } => selected.iter().cloned().collect(),
            BatchSelection::Selected { include_affected: false, .. } if impact.requires_other_devices() => {
                let others = impact
                    .closure()
                    .difference(&impact.selected)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::DeviceConfiguration(format!(
                    "the requested load also affects {others}; use --affected or the explicit unsafe --force-single"
                )));
            }
            BatchSelection::All | BatchSelection::AllStale | BatchSelection::Selected { .. } => impact.closure(),
        };

        let senders = scope.includes_application().then(|| derive_senders(project, &context.lowered, state));
        let mut planned = Vec::new();
        for id in &closure {
            let lowered_device = &context.lowered[id];
            let authored_device = &project.devices[id];
            let product = &products[id].product;
            let management_configuration = if scope.includes_application() {
                None
            } else {
                let mut configuration = lowered_device.resolved.configuration.clone();
                configuration.object_memberships.clear();
                configuration.net_security.clear();
                Some(configuration)
            };
            let configuration = management_configuration.as_ref().unwrap_or(&lowered_device.resolved.configuration);
            let mut key_material = resolve_project_key_material(
                configuration,
                &id.0,
                &lowered_device.net_ids,
                &[],
                keys,
                keyring,
                authored_device.data_secure.is_enabled(),
            )?;
            let secured_addresses: BTreeSet<_> = key_material
                .secured_groups()
                .iter()
                .filter(|(_, protection)| **protection != crate::download::GroupObjectProtection::Plain)
                .map(|(address, _)| *address)
                .collect();
            let siat = senders.as_ref().map_or_else(Vec::new, |senders| {
                derive_target_siat(project, authored_device, senders, state, &secured_addresses)
            });
            // Resolve keyring sender lists after topology-derived rows, then
            // retain the complete table in the normal Security IO model.
            if let Some(security) = key_material.application_security_mut() {
                let mut rows: BTreeMap<zweidraehte_proto::address::IndividualAddress, u64> =
                    security.siat().iter().copied().collect();
                for (address, last_valid) in siat {
                    rows.entry(address).and_modify(|old| *old = (*old).max(last_valid)).or_insert(last_valid);
                }
                merge_retained_target_siat(&mut rows, project, authored_device, state);
                security.replace_siat(rows.into_iter().collect());
            }
            if scope.includes_application() {
                reject_deployed_group_key_change(state, &key_material, &lowered_device.net_ids)?;
            }
            let mut warnings = lowered_device.warnings.clone();
            if scope.includes_application() {
                for (&address, policy) in &lowered_device.resolved.configuration.net_security {
                    if *policy == NetSecurityPolicy::Automatic
                        && key_material.secured_groups().get(&address) == Some(&GroupObjectProtection::Plain)
                    {
                        let net = lowered_device.net_ids.get(&address).map_or("unknown", String::as_str);
                        warnings.push(format!(
                            "device `{id}`, net `{net}` uses automatic security but no group key resolved; group traffic will be plain"
                        ));
                    }
                }
            }
            let mut sender_nets = fingerprints[id].sender_nets.clone();
            if let Some(deployed) = state.and_then(|state| state.deployments.get(&id.0)) {
                sender_nets.extend(deployed.sender_nets.iter().cloned());
            }
            sender_nets.sort();
            sender_nets.dedup();

            planned.push(PlannedProjectDevice {
                id: id.clone(),
                product: product.clone(),
                configuration: lowered_device.resolved.configuration.clone(),
                supports_data_secure: product.supports_data_secure(),
                data_secure_enabled: authored_device.data_secure.is_enabled(),
                key_material,
                fingerprints: fingerprints[id].clone(),
                download_scope: if scope.includes_application() {
                    let status = device_programming_status(id, state, &fingerprints[id]);
                    deployment_download_scope(
                        &fingerprints[id],
                        state.and_then(|state| state.deployments.get(&id.0)),
                        status,
                    )
                } else {
                    DownloadScope::Full
                },
                previous_mcb: state.and_then(|state| state.deployment_mcb.get(&id.0)).cloned().unwrap_or_default(),
                siat_consumers: siat_consumers(project, &fingerprints, id, &sender_nets),
                warnings,
            });
        }

        planned.sort_by(|left, right| left.id.cmp(&right.id));

        // Build this list from project data before talking to any device.
        // Every secure link is required, but only a zero `LastValidSeqNr` is
        // queried during image creation; existing nonzero rows are retained.
        let (required_senders, unknown_senders) = classify_siat_senders(
            planned
                .iter()
                .filter_map(|device| device.key_material.application_security())
                .map(|security| security.siat()),
        );
        let mut siat_senders = Vec::new();

        for (id, authored) in &project.devices {
            if authored.serial.is_none() {
                continue;
            }

            if !required_senders.contains(&authored.address) {
                continue;
            }

            let query = unknown_senders.contains(&authored.address);
            let probe_key_material = if query && !closure.contains(id) {
                let lowered = &context.lowered[id];
                Some(resolve_project_key_material(
                    &lowered.resolved.configuration,
                    &id.0,
                    &lowered.net_ids,
                    &[],
                    keys,
                    keyring,
                    authored.data_secure.is_enabled(),
                )?)
            } else {
                None
            };

            siat_senders.push(ManagedSiatSender { address: authored.address, query, probe_key_material });
        }

        Ok(ProgrammingBatchPlan { impact, devices: planned, siat_senders })
    }

    /// Generate every missing tool key and persist it before a bus is opened.
    pub fn materialize_tool_keys(&self, plan: &mut ProgrammingBatchPlan, keys: &mut ProjectKeyStore) -> Result<usize> {
        let mut generated = 0;
        for device in &mut plan.devices {
            if !device.key_material.needs_tool_key_generation() {
                continue;
            }
            let key = keys.generate_tool_key(&device.id.0)?;
            device.key_material.install_generated_tool_key(key);
            generated += 1;
        }
        Ok(generated)
    }

    /// Read and compile the entire closure before its first configuration
    /// write. Live SIAT values raise required replay floors in each planned
    /// device's key material as part of this read-only pass.
    pub async fn prepare_batch(
        &self,
        bus: &KnxBus,
        mask_db: &crate::download::MaskDb,
        plan: ProgrammingBatchPlan,
        options: ProgrammingOptions,
    ) -> Result<PreparedProjectBatch> {
        let ProgrammingBatchPlan { impact, devices: planned_devices, siat_senders } = plan;
        let programmer = DeviceProgrammer::new();
        let mut devices = Vec::with_capacity(planned_devices.len());
        for device in planned_devices {
            let request = ProgrammingRequest::new(
                device.product.clone(),
                device.configuration.clone(),
                device.key_material.clone(),
            )
            .with_download_scope(device.download_scope)
            .with_previous_mcb(device.previous_mcb.clone())
            .with_options(options.clone());
            let prepared = programmer.prepare(bus, mask_db, request).await?;
            devices.push(PreparedProjectDevice { planned: device, programming: prepared });
        }

        // Resolve each zero SIAT row by opening the sender with its Tool Key
        // and running `S-A_Sync`. Do not read PID 59 here: that
        // property belongs to commissioning the sender, while this pass asks
        // what the sender will use on the wire now.
        //
        // The returned `SeqNrremote` is the sender's next sequence number.
        // Although 03/03/07 defines live receiver state as `SeqNrremote - 1`,
        // the project image carries the returned value unchanged in
        // `LastValidSeqNr`. Keep the representations distinct instead of
        // folding them into a vaguely named counter.
        let mut remote_next_sequences = BTreeMap::new();
        for sender in siat_senders.iter().filter(|sender| sender.query) {
            let key_material = match &sender.probe_key_material {
                Some(key_material) => key_material.clone(),
                None => devices
                    .iter()
                    .find(|device| device.planned.configuration.identity.desired_address == sender.address)
                    .map(|device| device.programming.key_material().clone())
                    .ok_or_else(|| {
                        Error::DeviceConfiguration(format!(
                            "managed SIAT sender {} has neither an affected device nor probe credentials",
                            sender.address
                        ))
                    })?,
            };

            // Query each sender independently. A failed sync leaves
            // that result at zero and image creation continues, so one offline
            // group member does not prevent programming the reachable devices.
            // This query specifically uses the installed Tool Key. Do not let
            // the general commissioning helper fall back to the FDSK: a new
            // device whose Tool Key is not installed simply leaves its row at
            // zero during this image-creation pass.
            let tool_key_material = key_material.with_fdsk(None);
            let queried = crate::connect_management_synchronized(bus, sender.address, &tool_key_material, false).await;
            let (connection, _) = match queried {
                Ok(opened) => opened,
                Err(error) => {
                    log::warn!("could not synchronize SIAT sender {}: {error}", sender.address);
                    continue;
                }
            };

            let remote_next_sequence = connection.last_security_sync_remote_sequence();
            if let Err(error) = connection.close().await {
                log::warn!("could not close SIAT sender {} after synchronization: {error}", sender.address);
            }

            if let Some(remote_next_sequence) = remote_next_sequence.filter(|sequence| *sequence != 0) {
                remote_next_sequences.insert(sender.address, remote_next_sequence);
            }
        }

        // Sync happens before the application images are finalized. Recompile
        // only devices whose previously-zero SIAT row received a value; all
        // later download stages then consume one coherent image.
        for device in &mut devices {
            device.programming.apply_authenticated_siat_sequences(mask_db, &remote_next_sequences)?;
            device.planned.key_material = device.programming.key_material().clone();
            if let Some(compiled) = device.programming.compiled() {
                device.planned.download_scope = compiled.scope();
            }
        }

        Ok(PreparedProjectBatch { impact, devices })
    }

    /// Execute an already prepared batch and journal its project-wide result.
    pub async fn execute_batch<F>(
        &self,
        session: &ProjectProgrammingSession,
        bus: &KnxBus,
        batch: PreparedProjectBatch,
        progress: &mut F,
    ) -> Result<ProjectBatchReport>
    where
        F: FnMut(&ProjectDeviceId, crate::ProgrammingEvent) + Send,
    {
        let closure: Vec<String> = batch.impact.closure().into_iter().map(|device| device.0).collect();
        let mut reports = Vec::with_capacity(batch.devices.len());
        let mut stale_siat_consumers = BTreeSet::new();
        let mut refreshed_group_communication = BTreeSet::new();

        for device in batch.devices {
            let PreparedProjectDevice { planned, programming } = device;
            let id = planned.id.clone();
            let mut device_progress = |event| progress(&id, event);
            match DeviceProgrammer::new().execute_with_progress(bus, programming, &mut device_progress).await {
                Ok(report) => {
                    if report.address_assignment.is_some_and(|assignment| assignment.changed) {
                        stale_siat_consumers.extend(planned.siat_consumers.iter().cloned());
                    }
                    if report.application_downloaded && report.download_scope.includes_group_communication() {
                        refreshed_group_communication.insert(id.clone());
                    }

                    record_success(&session.store, &planned, &report)?;
                    reports.push(ProjectDeviceProgrammingReport { id, report });
                }
                Err(source) => {
                    let state_error = record_batch_failure(&session.store, &closure);
                    return Err(Error::ProjectBatch {
                        device: id.0,
                        completed: reports.iter().map(|report| report.id.0.clone()).collect(),
                        source: Box::new(source),
                        state_error,
                    });
                }
            }
        }

        stale_siat_consumers.retain(|device| !refreshed_group_communication.contains(device));
        if !stale_siat_consumers.is_empty() {
            let mut store = session.store.lock().map_err(|_| Error::ProjectStorePoisoned)?;
            store.record(ProjectEvent::MarkGroupCommunicationStale {
                devices: stale_siat_consumers.into_iter().map(|device| device.0).collect(),
            })?;
        }

        Ok(ProjectBatchReport { devices: reports })
    }
}

fn record_batch_failure(shared: &Arc<Mutex<ProjectStore>>, closure: &[String]) -> Option<String> {
    shared
        .lock()
        .map_err(|_| Error::ProjectStorePoisoned)
        .and_then(|mut store| {
            store.record(ProjectEvent::MarkInconsistent { devices: closure.to_vec() }).map_err(Error::from)
        })
        .err()
        .map(|error| error.to_string())
}

fn record_success(
    shared: &Arc<Mutex<ProjectStore>>,
    planned: &PlannedProjectDevice,
    report: &crate::ProgrammingReport,
) -> Result<()> {
    let mut store = shared.lock().map_err(|_| Error::ProjectStorePoisoned)?;

    if report.application_downloaded {
        store.record(ProjectEvent::RecordDeployment {
            device: planned.id.0.clone(),
            fingerprints: planned.fingerprints.clone(),
            mcb: report.mcb_snapshots.clone(),
        })?;
    } else {
        store.record(ProjectEvent::RecordIndividualAddress {
            device: planned.id.0.clone(),
            identity: planned.fingerprints.identity.clone(),
            individual_address: planned.fingerprints.individual_address.clone(),
        })?;
    }

    if !report.application_downloaded {
        return Ok(());
    }

    for metadata in planned.key_material.provenance() {
        if let zweidraehte_project::KeyScope::Group(net) = &metadata.id.scope {
            let fingerprint = metadata.fingerprint.iter().map(|byte| format!("{byte:02x}")).collect();
            store.record(ProjectEvent::RecordGroupKey { net: net.clone(), fingerprint })?;
        }
    }
    Ok(())
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
            zweidraehte_project::SenderIdentity::UnmanagedAddress(address) => parse_individual_address(address),
        };
        if let Some(address) = address
            && let Some(current) = rows.get_mut(&address)
        {
            *current = (*current).max(last_valid);
        }
    }
}

fn effective_fingerprints(
    project: &AuthoredProject,
    id: &ProjectDeviceId,
    lowered: &LoweredProjectDevice,
    product: &ProductData,
) -> DeploymentFingerprints {
    let mut fingerprints = project.fingerprints(id).expect("caller iterates project devices");
    // Enabling or disabling the application's Security IO participation is
    // not merely a table-row change. Keep that transition on the complete
    // procedure; only changes within an already-secure configuration use the
    // group-communication path.
    fingerprints.application = digest(format!("{product:?}|{:?}", project.devices[id].data_secure));
    fingerprints.parameters = digest(format!("{:?}", project.devices[id].parameters));
    fingerprints.product_parameters = digest(format!(
        "{}|{}|{:?}",
        fingerprints.application, fingerprints.parameters, project.devices[id].data_secure
    ));
    fingerprints.object_flags = digest(format!("{:?}", lowered.resolved.configuration.objects));

    let flags: BTreeMap<_, _> =
        lowered.resolved.configuration.objects.iter().map(|object| (object.number, object.flags)).collect();
    fingerprints.sender_nets = project.devices[id]
        .objects
        .values()
        .filter_map(|object| {
            let flags = flags.get(&object.com_object)?;
            let sends = flags.communication_enable()
                && (flags.transmission_enable() || flags.read_enable() || flags.read_on_init());
            sends.then(|| {
                object
                    .memberships
                    .iter()
                    .find(|membership| membership.role == ProjectMembershipRole::Primary)
                    .map(|membership| membership.net.0.clone())
            })?
        })
        .collect();
    fingerprints.sender_nets.sort();
    fingerprints.sender_nets.dedup();
    fingerprints.siat_dependencies =
        digest(format!("{}|{}", fingerprints.secured_nets.join(","), fingerprints.sender_nets.join(",")));
    fingerprints
}

fn augment_key_fingerprint(
    project: &AuthoredProject,
    device: &ProjectDeviceId,
    fingerprints: &mut DeploymentFingerprints,
    keys: Option<&dyn KeyMaterialSource>,
    keyring: Option<&Keyring>,
) -> Result<()> {
    let mut material = Vec::new();
    let mut secured_nets = Vec::new();
    let mut protection_by_net = BTreeMap::new();
    let linked: BTreeSet<_> = project.devices[device]
        .objects
        .values()
        .flat_map(|object| object.memberships.iter().map(|membership| membership.net.clone()))
        .collect();
    for net_id in linked {
        let net = &project.nets[&net_id];
        let id = KeyId { scope: KeyScope::Group(net_id.0.clone()), kind: KeyKind::GroupKey };
        let project_key = keys.map(|keys| keys.read(&id, None)).transpose()?.flatten();
        let imported = keyring.and_then(|keyring| keyring.group_key(u16::from_be_bytes(net.address.0))).copied();
        let project_value = project_key.as_ref().map(|record| record.value.key16()).transpose()?;
        if let (Some(project_value), Some(imported)) = (project_value, imported)
            && project_value != imported
        {
            return Err(Error::DeviceConfiguration(format!("conflicting values for group key on net `{net_id}`")));
        }
        let has_key = project_value.is_some() || imported.is_some();
        let protection = match net.security {
            ProjectSecurityPolicy::Plain => GroupObjectProtection::Plain,
            ProjectSecurityPolicy::Automatic if has_key => GroupObjectProtection::AuthenticationConfidentiality,
            ProjectSecurityPolicy::Automatic => GroupObjectProtection::Plain,
            ProjectSecurityPolicy::Authentication if has_key => GroupObjectProtection::Authentication,
            ProjectSecurityPolicy::AuthenticationConfidentiality if has_key => {
                GroupObjectProtection::AuthenticationConfidentiality
            }
            ProjectSecurityPolicy::Authentication | ProjectSecurityPolicy::AuthenticationConfidentiality => {
                return Err(Error::DeviceConfiguration(format!(
                    "net `{net_id}` requires secure group traffic but has no active group key"
                )));
            }
        };
        let secured = protection != GroupObjectProtection::Plain;
        if secured {
            if !project.devices[device].data_secure.is_enabled() {
                return Err(Error::DeviceConfiguration(format!(
                    "device `{device}` has Data Secure disabled but net `{net_id}` resolves to secure"
                )));
            }
            if let Some(sender) = project
                .external_senders
                .values()
                .find(|sender| sender.nets.contains(&net_id) && !sender.data_secure.is_enabled())
            {
                return Err(Error::DeviceConfiguration(format!(
                    "external sender `{}` has Data Secure disabled but net `{net_id}` resolves to secure",
                    sender.id
                )));
            }
            secured_nets.push(net_id.0.clone());
        }
        protection_by_net.insert(net_id.clone(), protection);
        let key_fingerprint = project_key
            .as_ref()
            .map(|record| record.metadata.fingerprint)
            .or_else(|| imported.map(|key| SecretBytes::new(key).fingerprint()))
            .map(|fingerprint| fingerprint.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
            .unwrap_or_else(|| "missing".to_string());
        material.push(format!(
            "{}:{}:{}:{:?}:{secured}:{:?}:{key_fingerprint}",
            net_id,
            net.address,
            net.dpt,
            net.security,
            project_key.as_ref().and_then(|record| record.metadata.epoch)
        ));
    }
    for object in project.devices[device].objects.values() {
        let protections: BTreeSet<_> = object
            .memberships
            .iter()
            .filter_map(|membership| protection_by_net.get(&membership.net).copied())
            .collect();
        if protections.len() > 1 {
            return Err(Error::DeviceConfiguration(format!(
                "device `{device}`, communication object {} belongs to nets with incompatible resolved security policies",
                object.com_object
            )));
        }
    }
    secured_nets.sort();
    fingerprints.secured_nets = secured_nets;
    fingerprints.sender_nets.retain(|net| fingerprints.secured_nets.contains(net));
    fingerprints.net_security = digest(material.join("|"));
    Ok(())
}

/// Classify changes against the last successful deployment. A missing or
/// pre-differential snapshot intentionally takes the full path once; hashes
/// cannot tell whether an old combined value changed because of product code
/// or only a parameter.
fn deployment_download_scope(
    current: &DeploymentFingerprints,
    deployed: Option<&DeploymentFingerprints>,
    status: DeviceProgrammingStatus,
) -> DownloadScope {
    let Some(deployed) = deployed else { return DownloadScope::Full };
    if !status.individual_address
        || !status.application_program
        || !status.medium_configuration
        || deployed.application.is_empty()
        || deployed.parameters.is_empty()
        || current.application != deployed.application
    {
        return DownloadScope::Full;
    }

    let parameters = !status.parameters || current.parameters != deployed.parameters;
    let group = !status.group_communication
        || current.identity != deployed.identity
        || current.individual_address != deployed.individual_address
        || current.object_flags != deployed.object_flags
        || current.memberships != deployed.memberships
        || current.net_security != deployed.net_security
        || current.secured_nets != deployed.secured_nets
        || current.siat_dependencies != deployed.siat_dependencies
        || current.sender_nets != deployed.sender_nets;
    let scope = match (parameters, group) {
        (true, true) => DownloadScope::ParametersAndGroupCommunication,
        (true, false) => DownloadScope::Parameters,
        (false, true) => DownloadScope::GroupCommunication,
        // An explicit load of a current device remains a useful way to force
        // reinstallation. Project-wide stale selection filters this case out.
        (false, false) => DownloadScope::Full,
    };
    log::debug!("deployment changes select {scope:?}: parameters={parameters}, group_communication={group}");
    scope
}

/// SIAT is a complete table. Its deployment fingerprint therefore depends on
/// every effective sender address for every secured net consumed by the
/// target, including unmanaged senders which have no selectable project
/// device of their own.
fn augment_siat_fingerprints(
    project: &AuthoredProject,
    fingerprints: &mut BTreeMap<ProjectDeviceId, DeploymentFingerprints>,
    keyring: Option<&Keyring>,
) {
    let mut sender_nets: Vec<_> = fingerprints
        .iter()
        .flat_map(|(id, fingerprint)| {
            fingerprint.sender_nets.iter().map(move |net| (net.clone(), project.devices[id].address.to_string()))
        })
        .chain(
            project
                .external_senders
                .values()
                .flat_map(|sender| sender.nets.iter().map(move |net| (net.0.clone(), sender.address.to_string()))),
        )
        .collect();
    if let Some(keyring) = keyring {
        let nets_by_address: BTreeMap<_, Vec<_>> = project.nets.values().fold(BTreeMap::new(), |mut nets, net| {
            nets.entry(u16::from_be_bytes(net.address.0)).or_default().push(net.id.0.clone());
            nets
        });
        for interface in &keyring.interfaces {
            for (group, senders) in &interface.group_addresses {
                let Some(nets) = nets_by_address.get(group) else { continue };
                for net in nets {
                    sender_nets.extend(senders.iter().map(|sender| (net.clone(), sender.to_string())));
                }
            }
        }
    }
    sender_nets.sort();
    sender_nets.dedup();
    for (target, fingerprint) in fingerprints.iter_mut() {
        let secured: BTreeSet<_> = fingerprint.secured_nets.iter().cloned().collect();
        let target_address = project.devices[target].address.to_string();
        let mut dependencies: Vec<_> = sender_nets
            .iter()
            .filter(|(net, address)| secured.contains(net) && address != &target_address)
            .map(|(net, address)| format!("{net}:{address}"))
            .collect();
        dependencies.sort();
        dependencies.dedup();
        fingerprint.siat_dependencies = digest(dependencies.join("|"));
    }
}

fn effective_impact(
    project: &AuthoredProject,
    state: Option<&MutableProjectState>,
    selected: &[ProjectDeviceId],
    fingerprints: &BTreeMap<ProjectDeviceId, DeploymentFingerprints>,
) -> ProjectImpact {
    let selected: BTreeSet<_> = selected.iter().cloned().collect();
    let mut impact = ProjectImpact { selected: selected.clone(), affected: BTreeMap::new() };
    for id in &selected {
        impact.affected.entry(id.clone()).or_default().insert(ImpactReason::Selected);
        let current = &fingerprints[id];
        let deployed = state.and_then(|state| state.deployments.get(&id.0));
        let Some(deployed) = deployed else {
            add_consumers(project, &mut impact, &current.sender_nets, ImpactReason::SiatDependency);
            continue;
        };
        let mut dependency_nets = current.secured_nets.clone();
        dependency_nets.extend(deployed.secured_nets.iter().cloned());
        dependency_nets.sort();
        dependency_nets.dedup();
        if current.identity != deployed.identity
            || (!deployed.medium_configuration.is_empty()
                && current.medium_configuration != deployed.medium_configuration)
        {
            add_impact_reason(&mut impact, id, ImpactReason::Identity);
            add_consumers(project, &mut impact, &dependency_nets, ImpactReason::SiatDependency);
        }
        if current.product_parameters != deployed.product_parameters {
            add_impact_reason(&mut impact, id, ImpactReason::ProductOrParameters);
        }
        if current.object_flags != deployed.object_flags {
            add_impact_reason(&mut impact, id, ImpactReason::ObjectFlags);
            let mut sender_nets = current.sender_nets.clone();
            sender_nets.extend(deployed.sender_nets.iter().cloned());
            add_consumers(project, &mut impact, &sender_nets, ImpactReason::SiatDependency);
        }
        if current.memberships != deployed.memberships {
            add_impact_reason(&mut impact, id, ImpactReason::Memberships);
            add_consumers(project, &mut impact, &dependency_nets, ImpactReason::SiatDependency);
        }
        if current.net_security != deployed.net_security {
            add_impact_reason(&mut impact, id, ImpactReason::NetSecurity);
            add_consumers(project, &mut impact, &dependency_nets, ImpactReason::NetSecurity);
        }
        if current.siat_dependencies != deployed.siat_dependencies {
            add_impact_reason(&mut impact, id, ImpactReason::SiatDependency);
        }
    }

    // The dependency walk above is deliberately conservative because a
    // deployment snapshot retains hashes, not the former authored topology.
    // Its broad net relationship is only a candidate closure: a receiver
    // whose complete effective fingerprint still matches its last successful
    // deployment has nothing to download. Keeping such a device would turn
    // an otherwise-local partial update into an explicit full reinstall,
    // because an unchanged selected device intentionally uses the full path.
    impact.affected.retain(|id, _| {
        selected.contains(id)
            || is_stale_device(id, state, fingerprints.get(id).expect("impact only contains project devices"))
    });
    impact
}

fn affected_devices(
    project: &AuthoredProject,
    state: Option<&MutableProjectState>,
    fingerprints: &BTreeMap<ProjectDeviceId, DeploymentFingerprints>,
) -> Vec<ProjectDeviceId> {
    project.devices.keys().filter(|id| is_stale_device(id, state, &fingerprints[*id])).cloned().collect()
}

fn is_stale_device(
    id: &ProjectDeviceId,
    state: Option<&MutableProjectState>,
    fingerprint: &DeploymentFingerprints,
) -> bool {
    !device_programming_status(id, state, fingerprint).is_complete()
}

fn device_programming_status(
    id: &ProjectDeviceId,
    state: Option<&MutableProjectState>,
    current: &DeploymentFingerprints,
) -> DeviceProgrammingStatus {
    let Some(state) = state else { return DeviceProgrammingStatus::NONE };
    if state.inconsistent_devices.contains(&id.0) {
        return DeviceProgrammingStatus::NONE;
    }

    let Some(deployed) = state.deployments.get(&id.0) else { return DeviceProgrammingStatus::NONE };
    let evidence = state.programming_status(&id.0);
    let application_matches = !deployed.application.is_empty() && current.application == deployed.application;

    DeviceProgrammingStatus {
        individual_address: evidence.individual_address
            && !deployed.individual_address.is_empty()
            && current.identity == deployed.identity
            && current.individual_address == deployed.individual_address,
        application_program: evidence.application_program && application_matches,
        parameters: evidence.parameters
            && application_matches
            && !deployed.parameters.is_empty()
            && current.parameters == deployed.parameters,
        group_communication: evidence.group_communication
            && application_matches
            && current.object_flags == deployed.object_flags
            && current.memberships == deployed.memberships
            && current.net_security == deployed.net_security
            && current.secured_nets == deployed.secured_nets
            && current.siat_dependencies == deployed.siat_dependencies
            && current.sender_nets == deployed.sender_nets,
        medium_configuration: evidence.medium_configuration
            && (deployed.medium_configuration.is_empty()
                || current.medium_configuration == deployed.medium_configuration),
    }
}

fn add_consumers(project: &AuthoredProject, impact: &mut ProjectImpact, nets: &[String], reason: ImpactReason) {
    for device in project.devices.values() {
        if device
            .objects
            .values()
            .any(|object| object.memberships.iter().any(|membership| nets.contains(&membership.net.0)))
        {
            add_impact_reason(impact, &device.id, reason);
        }
    }
}

fn siat_consumers(
    project: &AuthoredProject,
    fingerprints: &BTreeMap<ProjectDeviceId, DeploymentFingerprints>,
    sender: &ProjectDeviceId,
    sender_nets: &[String],
) -> Vec<ProjectDeviceId> {
    project
        .devices
        .values()
        .filter(|device| &device.id != sender)
        .filter(|device| fingerprints[&device.id].secured_nets.iter().any(|net| sender_nets.contains(net)))
        .filter(|device| {
            device
                .objects
                .values()
                .any(|object| object.memberships.iter().any(|membership| sender_nets.contains(&membership.net.0)))
        })
        .map(|device| device.id.clone())
        .collect()
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

fn add_impact_reason(impact: &mut ProjectImpact, device: &ProjectDeviceId, reason: ImpactReason) {
    impact.affected.entry(device.clone()).or_default().insert(reason);
}

fn digest(value: String) -> String {
    Sha256::digest(value.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn derive_senders(
    project: &AuthoredProject,
    lowered: &BTreeMap<ProjectDeviceId, LoweredProjectDevice>,
    state: Option<&MutableProjectState>,
) -> BTreeMap<NetId, BTreeMap<zweidraehte_proto::address::IndividualAddress, u64>> {
    let mut senders: BTreeMap<NetId, BTreeMap<_, u64>> = BTreeMap::new();
    for (id, device) in lowered {
        let authored = &project.devices[id];
        let flags: BTreeMap<_, _> =
            device.resolved.configuration.objects.iter().map(|object| (object.number, object.flags)).collect();
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

fn derive_target_siat(
    project: &AuthoredProject,
    target: &ProjectDevice,
    senders: &BTreeMap<NetId, BTreeMap<zweidraehte_proto::address::IndividualAddress, u64>>,
    state: Option<&MutableProjectState>,
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
    if let Some(previous) = state
        .and_then(|state| state.deployments.get(&target.id.0))
        .and_then(|deployment| parse_individual_address(&deployment.individual_address))
    {
        rows.remove(&previous);
    }
    rows.into_iter().collect()
}

fn reject_deployed_group_key_change(
    state: Option<&MutableProjectState>,
    material: &ResolvedKeyMaterial,
    net_ids: &BTreeMap<GroupAddress, String>,
) -> Result<()> {
    let Some(state) = state else { return Ok(()) };
    for net_id in net_ids.values() {
        let Some(deployed) = state.deployed_group_keys.get(net_id) else { continue };
        // Resolution has already rejected different bytes supplied for this
        // net. Inspect its provenance rather than only the writable project
        // store so a changed keyring-only key cannot bypass the no-rotation
        // guard.
        let current = material.provenance().iter().find_map(|metadata| {
            (metadata.id.kind == KeyKind::GroupKey && metadata.id.scope == KeyScope::Group(net_id.clone()))
                .then(|| metadata.fingerprint.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
        });
        let Some(current) = current else { continue };
        if &current != deployed {
            return Err(Error::DeviceConfiguration(format!(
                "active deployed group key for net `{net_id}` changed; key rotation is not implemented"
            )));
        }
    }
    Ok(())
}

fn parse_individual_address(value: &str) -> Option<zweidraehte_proto::address::IndividualAddress> {
    let mut parts = value.split('.');
    let area = parts.next()?.parse::<u8>().ok()?;
    let line = parts.next()?.parse::<u8>().ok()?;
    let device = parts.next()?.parse::<u8>().ok()?;
    (parts.next().is_none() && area <= 15 && line <= 15)
        .then(|| zweidraehte_proto::address::IndividualAddress::new(area, line, device))
}

/// Apply project parameter/object overrides over product and visible-ref
/// values, then produce the existing format-neutral download model.
pub fn lower_project_device(
    project: &AuthoredProject,
    project_device: &ProjectDevice,
    program: ApplicationProgram,
    product: &ProductData,
) -> Result<LoweredProjectDevice> {
    validate_data_secure_capability(project_device, product)?;

    let mut object_memberships = Vec::new();
    let mut net_security = BTreeMap::new();
    let mut net_ids = BTreeMap::new();
    let mut objects = Vec::new();
    for object in project_device.objects.values() {
        objects.push(ObjectSetting { com_object: object.com_object, flags: project_flags(object.flags) });
        for membership in &object.memberships {
            let net = project
                .nets
                .get(&membership.net)
                .ok_or_else(|| Error::DeviceConfiguration(format!("unknown net `{}`", membership.net)))?;
            object_memberships.push(ObjectMembership {
                group_address: net.address,
                com_object: object.com_object,
                role: match membership.role {
                    ProjectMembershipRole::Primary => MembershipRole::Primary,
                    ProjectMembershipRole::Additional => MembershipRole::Additional,
                },
            });
            net_security.insert(net.address, match net.security {
                ProjectSecurityPolicy::Plain => NetSecurityPolicy::Plain,
                ProjectSecurityPolicy::Automatic => NetSecurityPolicy::Automatic,
                ProjectSecurityPolicy::Authentication => NetSecurityPolicy::Authentication,
                ProjectSecurityPolicy::AuthenticationConfidentiality => {
                    NetSecurityPolicy::AuthenticationConfidentiality
                }
            });
            net_ids.insert(net.address, membership.net.0.clone());
        }
    }
    let settings = ProductConfiguration {
        parameters: project_device
            .parameters
            .iter()
            .map(|parameter| ParameterSetting {
                id: parameter.id.clone(),
                value: match &parameter.value {
                    ParamValue::Integer(value) => ProductParameterValue::Integer(*value),
                    ParamValue::Float(value) => ProductParameterValue::Float(*value),
                    ParamValue::Text(value) => ProductParameterValue::Text(value.clone()),
                },
            })
            .collect(),
        objects,
    };

    let mut device = Device::new(program, None);
    apply_configuration(&mut device, &settings).map_err(|error| Error::DeviceConfiguration(error.to_string()))?;
    let effective = effective_com_objects(&device, &settings);
    let configuration = DeviceConfiguration {
        identity: DeviceIdentity { desired_address: project_device.address, serial_number: project_device.serial },
        data_secure_enabled: project_device.data_secure.is_enabled(),
        parameters: Vec::new(),
        object_memberships,
        objects: Vec::new(),
        net_security,
        max_apdu: project_device.max_apdu,
    };
    let resolved = resolve_product_configuration(&device, &settings, configuration, product)?;

    let mut warnings = Vec::new();
    for object in &effective {
        // Product objects omitted from the project have no authored links or
        // overrides. Their default T/R/I flags do not create a half-defined
        // association; they simply remain unlinked in the generated tables.
        let Some(authored) = project_device.objects.get(&object.number) else { continue };
        let primary_count = {
            authored.memberships.iter().filter(|membership| membership.role == ProjectMembershipRole::Primary).count()
        };
        if (object.transmit || object.read || object.read_on_init) && primary_count != 1 {
            return Err(Error::DeviceConfiguration(format!(
                "device `{}`, object {} has effective T/R/I traffic but no unique primary association",
                project_device.id, object.number
            )));
        }
        if object.read_on_init && !object.update {
            warnings.push(format!(
                "device `{}`, object {} enables read-on-init without update and cannot consume the response",
                project_device.id, object.number
            ));
        }
        if !object.communication
            && (object.read || object.write || object.transmit || object.update || object.read_on_init)
        {
            warnings.push(format!(
                "device `{}`, object {} has inert traffic flags because communication is disabled",
                project_device.id, object.number
            ));
        }

        let object_type = ComObjectType::from_ets_size_string(&object.object_size).ok_or_else(|| {
            Error::DeviceConfiguration(format!(
                "object {} has unknown object size `{}`",
                object.number, object.object_size
            ))
        })?;
        for membership in &authored.memberships {
            let net = &project.nets[&membership.net];
            check_dpt(&net.dpt, object.datapoint_type.as_deref(), object_type).map_err(|reason| {
                Error::DeviceConfiguration(format!(
                    "device `{}`, object {}, net `{}`: {reason}",
                    project_device.id, object.number, net.id
                ))
            })?;
        }
    }

    Ok(LoweredProjectDevice { id: project_device.id.clone(), resolved, net_ids, warnings })
}

fn validate_data_secure_capability(project_device: &ProjectDevice, product: &ProductData) -> Result<()> {
    if project_device.data_secure.is_enabled() && !product.supports_data_secure() {
        return Err(Error::DeviceConfiguration(format!(
            "device `{}` enables Data Secure, but product `{}` does not support it",
            project_device.id,
            product.id()
        )));
    }
    Ok(())
}

fn project_flags(flags: zweidraehte_project::ObjectFlagOverrides) -> ProductFlagOverrides {
    let priority = flags.priority.map(|priority| match priority {
        ObjectPriority::Low => Priority::Low,
        ObjectPriority::High => Priority::High,
        ObjectPriority::Alarm => Priority::Alarm,
        ObjectPriority::System => Priority::System,
    });
    ProductFlagOverrides {
        read: flags.read,
        write: flags.write,
        communication: flags.communication,
        transmit: flags.transmit,
        update: flags.update,
        read_on_init: flags.read_on_init,
        priority,
    }
}

fn check_dpt(net: &str, product: Option<&str>, object_type: ComObjectType) -> core::result::Result<(), String> {
    let net = canonical_dpt(net).ok_or_else(|| format!("invalid net DPT `{net}`"))?;
    if let Some(product) = product {
        let references =
            ProductDptReferences::parse(product).ok_or_else(|| format!("unknown product DPT `{product}`"))?;
        if !references.accepts(ProductDptReference { main: net.0, subtype: net.1 }) {
            return Err(format!("net DPT does not match effective product DPT `{product}`"));
        }
    }
    let expected_bits =
        dpt_payload_bits(net.0).ok_or_else(|| format!("payload size for DPT main type {} is not known", net.0))?;
    let actual_bits = match object_type {
        ComObjectType::Uint1 => 1,
        ComObjectType::Uint2 => 2,
        ComObjectType::Uint3 => 3,
        ComObjectType::Uint4 => 4,
        ComObjectType::Uint5 => 5,
        ComObjectType::Uint6 => 6,
        ComObjectType::Uint7 => 7,
        other => other.size_in_bytes().0 * 8,
    };
    if expected_bits != actual_bits {
        return Err(format!("DPT needs {expected_bits} bits but the effective object has {actual_bits}"));
    }
    Ok(())
}

fn canonical_dpt(value: &str) -> Option<(u16, Option<u16>)> {
    let (main, sub) = value.split_once('.')?;
    Some((main.parse().ok()?, Some(sub.parse().ok()?)))
}

fn dpt_payload_bits(main: u16) -> Option<usize> {
    Some(match main {
        1 => 1,
        2 => 2,
        3 => 4,
        4..=6 | 17 | 18 | 20 | 21 | 23 | 26 => 8,
        7..=9 | 22 => 16,
        10 | 11 | 30 | 232 => 24,
        12..=15 | 27 | 235 => 32,
        16 => 112,
        19 | 29 => 64,
        234 | 236 | 251 => 48,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::{DeviceConfiguration, DeviceIdentity, LoweredDeviceConfiguration, ProjectConfig};
    use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};

    #[test]
    fn dpt_compatibility_checks_subtype_and_payload() {
        assert!(check_dpt("1.001", Some("DPST-1-1"), ComObjectType::Uint1).is_ok());
        assert!(check_dpt("1.001", Some("DPT-1 DPST-1-1"), ComObjectType::Uint1).is_ok());
        assert!(check_dpt("1.002", Some("DPST-1-1"), ComObjectType::Uint1).is_err());
        assert!(check_dpt("1.002", Some("DPT-1 DPST-1-1"), ComObjectType::Uint1).is_err());
        assert!(check_dpt("1.002", Some("DPT-1"), ComObjectType::Uint1).is_ok());
        assert!(check_dpt("9.001", Some("DPT-9"), ComObjectType::Byte1).is_err());
    }

    #[test]
    fn dpt_without_product_annotation_still_checks_payload_size() {
        assert!(check_dpt("5.001", None, ComObjectType::Byte1).is_ok());
        assert!(check_dpt("5.001", None, ComObjectType::Byte2).is_err());
    }

    #[test]
    fn enabled_data_secure_requires_product_capability() {
        let source = "ga n = 1/0/1\nnet n : 1.001 { security plain }\narea 1 a { line 1 l { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 data_secure enabled } } }";
        let project = AuthoredProject::parse(source).expect("project parses");
        let id = ProjectDeviceId("d".into());
        let product = ProductData::default().with_fixture_id("plain-product");
        let error = validate_data_secure_capability(&project.devices[&id], &product)
            .expect_err("unsupported Data Secure is rejected");
        assert!(error.to_string().contains("does not support"));
    }

    const TOPOLOGY: &str = r#"ga primary = 1/0/1
ga additional = 1/0/2
net primary : 1.001 { security authentication_confidentiality }
net additional : 1.001 { security authentication_confidentiality }
area 1 a { line 1 l { medium tp1
device sender { product local:"sender.mtxml" address 1.1.1 serial "00FA:00000001" data_secure enabled object 0 { on primary also on additional } }
device receiver { product local:"receiver.mtxml" address 1.1.2 data_secure enabled object 0 { on primary } }
} }
"#;

    #[test]
    fn programming_session_holds_the_project_lock_until_finish() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        std::fs::write(&path, TOPOLOGY).expect("project fixture writes");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store.initialize().expect("project initializes");

        let session = ProjectProgrammingSession::begin(store).expect("session begins");
        let second = ProjectStore::open(&path).expect("second reader opens");
        assert!(matches!(second.acquire_lock(), Err(zweidraehte_project::ProjectStoreError::Locked)));

        session.finish().expect("session finishes");
        assert!(second.acquire_lock().is_ok(), "finishing releases the retained lock");
    }

    #[test]
    fn batch_failure_marks_the_complete_impact_closure() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        std::fs::write(&path, TOPOLOGY).expect("project fixture writes");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store.initialize().expect("project initializes");
        let session = ProjectProgrammingSession::begin(store).expect("session begins");
        let affected = vec!["sender".to_string(), "receiver".to_string()];

        assert_eq!(record_batch_failure(&session.store, &affected), None);
        let state = session.store.lock().expect("project store is not poisoned");
        let inconsistent = &state.state().expect("project has state").inconsistent_devices;
        assert!(inconsistent.iter().any(|device| device == "sender"));
        assert!(inconsistent.iter().any(|device| device == "receiver"));
        drop(state);
        session.finish().expect("session finishes");
    }

    #[test]
    fn sender_address_changes_invalidate_only_secure_siat_consumers() {
        let project = AuthoredProject::parse(TOPOLOGY).expect("topology parses");
        let sender = ProjectDeviceId("sender".into());
        let receiver = ProjectDeviceId("receiver".into());
        let mut fingerprints: BTreeMap<_, _> =
            project.devices.keys().map(|id| (id.clone(), project.fingerprints(id).expect("device exists"))).collect();
        fingerprints.get_mut(&receiver).expect("receiver exists").secured_nets = vec!["primary".into()];

        assert_eq!(siat_consumers(&project, &fingerprints, &sender, &["primary".into()]), vec![receiver]);
        assert!(siat_consumers(&project, &fingerprints, &sender, &["additional".into()]).is_empty());
    }

    #[test]
    fn project_keyring_exports_active_keys_certificates_and_last_valid_sequences() {
        let source =
            format!("external_sender visualisation {{ address 1.1.250 data_secure enabled on primary }}\n{TOPOLOGY}");
        let project = AuthoredProject::parse(source).expect("topology parses");
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut keys = ProjectKeyStore::create(directory.path().join("keys.toml"), "test").expect("key store creates");
        keys.put_device_fdsk("sender", "000102030405060708090A0B0C0D0E0F", crate::security::KeyOrigin::DeviceLabel)
            .expect("FDSK persists");
        keys.put_device_tool_key("sender", "101112131415161718191A1B1C1D1E1F", crate::security::KeyOrigin::Generated)
            .expect("tool key persists");
        keys.put_group_key(
            "primary",
            zweidraehte_project::KeyEpoch(1),
            "202122232425262728292A2B2C2D2E2F",
            crate::security::KeyOrigin::Manual,
            true,
        )
        .expect("group key persists");
        let mut state = MutableProjectState::new("test".into());
        state.devices.insert("00FA:00000001".into(), zweidraehte_project::DeviceSequenceObservation {
            outgoing_next: 124,
            siat_last_valid: BTreeMap::new(),
        });
        state.sender_floors.insert(SenderIdentity::UnmanagedAddress("1.1.250".into()), 456);
        state.devices.insert("00FA:00000002".into(), zweidraehte_project::DeviceSequenceObservation {
            outgoing_next: 0,
            siat_last_valid: BTreeMap::from([
                (SenderIdentity::ManagedSerial("00FA:00000001".into()), 789),
                (SenderIdentity::UnmanagedAddress("1.1.250".into()), 987),
            ]),
        });

        let keyring = build_project_keyring(&project, &state, &keys, "bench", "zweidraehte", "2026-08-25T12:34:56")
            .expect("project keyring builds");
        let xml = keyring.to_xml("secret").expect("keyring exports");
        let imported = Keyring::parse(&xml, "secret").expect("exported keyring imports");

        assert_eq!(
            imported.group_key(u16::from_be_bytes(project.nets[&NetId("primary".into())].address.0)),
            Some(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,])
        );
        let managed = imported
            .devices
            .iter()
            .find(|device| device.serial == Some([0x00, 0xFA, 0, 0, 0, 1]))
            .expect("managed device is present");
        assert_eq!(managed.sequence_number, 789);
        assert!(managed.fdsk().is_some());
        assert!(managed.tool_key().is_some());
        let external = imported
            .devices
            .iter()
            .find(|device| device.individual_address == crate::IndividualAddress::new(1, 1, 250))
            .expect("external sender is present");
        assert_eq!(external.sequence_number, 987);
    }

    fn lowered_sender(flags: u8) -> (AuthoredProject, BTreeMap<ProjectDeviceId, LoweredProjectDevice>) {
        let project = AuthoredProject::parse(TOPOLOGY).expect("topology parses");
        let sender = project.devices[&ProjectDeviceId("sender".into())].clone();
        let primary = project.nets[&NetId("primary".into())].address;
        let additional = project.nets[&NetId("additional".into())].address;
        let configuration = DeviceConfiguration {
            identity: DeviceIdentity { desired_address: sender.address, serial_number: sender.serial },
            data_secure_enabled: true,
            parameters: Vec::new(),
            object_memberships: vec![
                ObjectMembership { group_address: primary, com_object: 0, role: MembershipRole::Primary },
                ObjectMembership { group_address: additional, com_object: 0, role: MembershipRole::Additional },
            ],
            objects: vec![crate::download::ComObjectDef {
                number: 0,
                object_type: ComObjectType::Uint1,
                flags: ComObjectFlags::from_byte(flags),
            }],
            net_security: BTreeMap::new(),
            max_apdu: None,
        };
        let lowered = LoweredProjectDevice {
            id: sender.id.clone(),
            resolved: ResolvedProject {
                lowered: LoweredDeviceConfiguration::new(
                    ProjectConfig::new(sender.address),
                    configuration.objects.clone(),
                ),
                configuration,
            },
            net_ids: BTreeMap::new(),
            warnings: Vec::new(),
        };
        (project, BTreeMap::from([(sender.id, lowered)]))
    }

    #[test]
    fn sender_discovery_uses_c_with_t_r_or_i_on_the_primary_only() {
        for flag in [ComObjectFlags::TE_FLAG_MASK, ComObjectFlags::RE_FLAG_MASK, ComObjectFlags::ROI_FLAG_MASK] {
            let (project, lowered) = lowered_sender(ComObjectFlags::CE_FLAG_MASK | flag);
            let senders = derive_senders(&project, &lowered, None);
            assert!(
                senders[&NetId("primary".into())]
                    .contains_key(&project.devices[&ProjectDeviceId("sender".into())].address)
            );
            assert!(!senders.contains_key(&NetId("additional".into())));
        }
    }

    #[test]
    fn write_and_update_do_not_discover_a_sender() {
        let (project, lowered) =
            lowered_sender(ComObjectFlags::CE_FLAG_MASK | ComObjectFlags::WE_FLAG_MASK | ComObjectFlags::UE_FLAG_MASK);
        assert!(derive_senders(&project, &lowered, None).is_empty());
    }

    #[test]
    fn siat_uses_last_valid_and_excludes_the_target() {
        let (project, lowered) = lowered_sender(ComObjectFlags::CE_FLAG_MASK | ComObjectFlags::TE_FLAG_MASK);
        let mut state = MutableProjectState::new("state".into());
        state.devices.insert("00FA:00000001".into(), zweidraehte_project::DeviceSequenceObservation {
            outgoing_next: 123,
            siat_last_valid: BTreeMap::new(),
        });
        let senders = derive_senders(&project, &lowered, Some(&state));
        let receiver = &project.devices[&ProjectDeviceId("receiver".into())];
        let rows = derive_target_siat(
            &project,
            receiver,
            &senders,
            Some(&state),
            &BTreeSet::from([project.nets[&NetId("primary".into())].address]),
        );
        assert_eq!(rows, [(project.devices[&ProjectDeviceId("sender".into())].address, 122)]);
    }

    #[test]
    fn ets_queries_only_unknown_siat_senders() {
        let unknown = zweidraehte_proto::address::IndividualAddress::new(1, 1, 1);
        let known = zweidraehte_proto::address::IndividualAddress::new(1, 1, 2);
        let first = [(unknown, 0), (known, 42)];
        let second = [(known, 50)];

        let (required, to_query) = classify_siat_senders([first.as_slice(), second.as_slice()].into_iter());

        assert_eq!(required, BTreeSet::from([unknown, known]));
        assert_eq!(to_query, BTreeSet::from([unknown]));
    }

    #[test]
    fn retained_siat_only_advances_rows_still_required_by_the_project() {
        let project = AuthoredProject::parse(TOPOLOGY).expect("topology parses");
        let receiver = &project.devices[&ProjectDeviceId("receiver".into())];
        let sender = &project.devices[&ProjectDeviceId("sender".into())];
        let mut state = MutableProjectState::new("state".into());
        state.devices.insert(
            format_serial(&receiver.serial.unwrap_or([0; 6])),
            zweidraehte_project::DeviceSequenceObservation::default(),
        );
        // The fixture receiver has no serial. Give the helper a realistic
        // target while retaining the authored topology around it.
        let mut receiver = receiver.clone();
        receiver.serial = Some([0x00, 0xFA, 0, 0, 0, 2]);
        state.devices.insert(
            format_serial(receiver.serial.as_ref().expect("receiver has serial")),
            zweidraehte_project::DeviceSequenceObservation {
                outgoing_next: 1,
                siat_last_valid: BTreeMap::from([
                    (
                        zweidraehte_project::SenderIdentity::ManagedSerial(format_serial(
                            sender.serial.as_ref().expect("sender has serial"),
                        )),
                        500,
                    ),
                    (zweidraehte_project::SenderIdentity::UnmanagedAddress("1.1.99".into()), 900),
                ]),
            },
        );
        let mut rows = BTreeMap::from([(sender.address, 122)]);
        merge_retained_target_siat(&mut rows, &project, &receiver, Some(&state));

        assert_eq!(rows, BTreeMap::from([(sender.address, 500)]));
    }

    #[test]
    fn automatic_security_is_plain_without_a_resolved_key() {
        let source = TOPOLOGY.replace("authentication_confidentiality", "automatic");
        let project = AuthoredProject::parse(source).expect("topology parses");
        let id = ProjectDeviceId("receiver".into());
        let mut fingerprint = project.fingerprints(&id).expect("receiver exists");
        augment_key_fingerprint(&project, &id, &mut fingerprint, None, None).expect("security resolves");
        assert!(fingerprint.secured_nets.is_empty());
    }

    #[test]
    fn automatic_secure_net_rejects_a_plain_external_sender() {
        let source = TOPOLOGY.replace("authentication_confidentiality", "automatic").replace(
            "area 1 a",
            "external_sender legacy { address 1.1.250 data_secure disabled on primary }\narea 1 a",
        );
        let project = AuthoredProject::parse(source).expect("topology parses");
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut keys = ProjectKeyStore::create(directory.path().join("keys.toml"), "test").expect("key store creates");
        keys.put_group_key(
            "primary",
            zweidraehte_project::KeyEpoch(1),
            "00112233445566778899AABBCCDDEEFF",
            crate::security::KeyOrigin::Manual,
            true,
        )
        .expect("group key persists");
        let id = ProjectDeviceId("receiver".into());
        let mut fingerprint = project.fingerprints(&id).expect("receiver exists");
        let error = augment_key_fingerprint(&project, &id, &mut fingerprint, Some(&keys), None)
            .expect_err("automatic secure net rejects plain external sender");
        assert!(error.to_string().contains("external sender `legacy`"));
    }

    #[test]
    fn deployed_group_key_change_is_rejected_for_imported_material() {
        let net_ids = BTreeMap::from([(GroupAddress::from_three_level(1, 0, 1), "primary".to_string())]);
        let key = [0x42; 16];
        let metadata = crate::security::KeyMetadata {
            id: KeyId { scope: KeyScope::Group("primary".into()), kind: KeyKind::GroupKey },
            epoch: None,
            origin: crate::security::KeyOrigin::Imported,
            encoding: crate::security::KeyEncoding::Binary,
            state: crate::security::KeyState::Active,
            fingerprint: SecretBytes::new(key).fingerprint(),
        };
        let material = ResolvedKeyMaterial::new(None).with_provenance(vec![metadata.clone()]);
        let mut state = MutableProjectState::new("state".into());
        state.deployed_group_keys.insert("primary".into(), "00".repeat(32));

        let error = reject_deployed_group_key_change(Some(&state), &material, &net_ids)
            .expect_err("a changed imported key must require rotation");
        assert!(error.to_string().contains("key rotation is not implemented"));

        state
            .deployed_group_keys
            .insert("primary".into(), metadata.fingerprint.iter().map(|byte| format!("{byte:02x}")).collect());
        reject_deployed_group_key_change(Some(&state), &material, &net_ids).expect("matching imported key is stable");
    }

    #[test]
    fn external_sender_address_changes_receiver_siat_fingerprint() {
        fn fingerprints(project: &AuthoredProject) -> BTreeMap<ProjectDeviceId, DeploymentFingerprints> {
            let mut fingerprints: BTreeMap<_, _> = project
                .devices
                .keys()
                .map(|id| {
                    let mut fingerprint = project.fingerprints(id).expect("device exists");
                    fingerprint.secured_nets = vec!["primary".into()];
                    if id.0 == "sender" {
                        fingerprint.sender_nets = vec!["primary".into()];
                    }
                    (id.clone(), fingerprint)
                })
                .collect();
            augment_siat_fingerprints(project, &mut fingerprints, None);
            fingerprints
        }

        let authored =
            format!("external_sender visualisation {{ address 1.1.250 data_secure enabled on primary }}\n{TOPOLOGY}");
        let original = AuthoredProject::parse(&authored).expect("topology parses");
        let changed = AuthoredProject::parse(authored.replace("1.1.250", "1.1.251")).expect("topology parses");
        let receiver = ProjectDeviceId("receiver".into());
        assert_ne!(
            fingerprints(&original)[&receiver].siat_dependencies,
            fingerprints(&changed)[&receiver].siat_dependencies
        );
    }

    #[test]
    fn moving_a_secure_primary_association_marks_its_old_receivers_affected() {
        fn fingerprints(project: &AuthoredProject) -> BTreeMap<ProjectDeviceId, DeploymentFingerprints> {
            let mut fingerprints: BTreeMap<_, _> = project
                .devices
                .iter()
                .map(|(id, device)| {
                    let mut fingerprint = project.fingerprints(id).expect("device exists");
                    fingerprint.secured_nets = device
                        .objects
                        .values()
                        .flat_map(|object| object.memberships.iter().map(|membership| membership.net.0.clone()))
                        .collect();
                    fingerprint.secured_nets.sort();
                    fingerprint.secured_nets.dedup();
                    if id.0 == "sender" {
                        fingerprint.sender_nets = device
                            .objects
                            .values()
                            .flat_map(|object| &object.memberships)
                            .find(|membership| membership.role == ProjectMembershipRole::Primary)
                            .map(|membership| vec![membership.net.0.clone()])
                            .unwrap_or_default();
                    }
                    (id.clone(), fingerprint)
                })
                .collect();
            augment_siat_fingerprints(project, &mut fingerprints, None);
            fingerprints
        }

        let original = AuthoredProject::parse(TOPOLOGY).expect("topology parses");
        let changed =
            AuthoredProject::parse(TOPOLOGY.replace("on primary also on additional", "on additional also on primary"))
                .expect("changed topology parses");
        let original_fingerprints = fingerprints(&original);
        let changed_fingerprints = fingerprints(&changed);
        let mut state = MutableProjectState::new("state".into());
        for (id, fingerprint) in original_fingerprints {
            state.deployments.insert(id.0, fingerprint);
        }

        let affected = affected_devices(&changed, Some(&state), &changed_fingerprints);
        let receiver = ProjectDeviceId("receiver".into());
        assert!(affected.contains(&receiver), "the receiver must remove the obsolete sender SIAT row");
        assert_ne!(changed_fingerprints[&receiver].siat_dependencies, state.deployments[&receiver.0].siat_dependencies);

        let impact =
            effective_impact(&changed, Some(&state), &[ProjectDeviceId("sender".into())], &changed_fingerprints);
        assert!(impact.closure().contains(&receiver), "a stale SIAT receiver must remain in the affected closure");
    }

    #[test]
    fn unrelated_current_receivers_are_removed_from_the_affected_closure() {
        const PROJECT: &str = r#"ga secure = 1/0/1
ga plain_a = 1/0/2
ga plain_b = 1/0/3
net secure : 1.001 { security authentication_confidentiality }
net plain_a : 1.001 { security plain }
net plain_b : 1.001 { security plain }
area 1 a { line 1 l { medium tp1
device sender { product local:"sender.mtxml" address 1.1.1 data_secure enabled
    object 0 { on secure flags { communication true transmit true } }
    object 1 { on plain_a flags { communication true transmit true } }
}
device receiver { product local:"receiver.mtxml" address 1.1.2 data_secure enabled
    object 0 { on secure flags { communication true write true } }
}
} }
"#;
        let original = AuthoredProject::parse(PROJECT).expect("topology parses");
        let changed = AuthoredProject::parse(PROJECT.replace("object 1 { on plain_a", "object 1 { on plain_b"))
            .expect("changed topology parses");
        let original_fingerprints: BTreeMap<_, _> =
            original.devices.keys().map(|id| (id.clone(), original.fingerprints(id).expect("device exists"))).collect();
        let changed_fingerprints: BTreeMap<_, _> =
            changed.devices.keys().map(|id| (id.clone(), changed.fingerprints(id).expect("device exists"))).collect();
        let mut state = MutableProjectState::new("state".into());
        for (id, fingerprint) in original_fingerprints {
            state.deployments.insert(id.0, fingerprint);
        }

        let sender = ProjectDeviceId("sender".into());
        let impact = effective_impact(&changed, Some(&state), std::slice::from_ref(&sender), &changed_fingerprints);

        assert_eq!(impact.closure(), BTreeSet::from([sender]));
    }

    #[test]
    fn keyring_sender_membership_participates_in_the_siat_fingerprint() {
        fn fingerprints(
            project: &AuthoredProject,
            keyring: Option<&Keyring>,
        ) -> BTreeMap<ProjectDeviceId, DeploymentFingerprints> {
            let mut fingerprints: BTreeMap<_, _> = project
                .devices
                .keys()
                .map(|id| {
                    let mut fingerprint = project.fingerprints(id).expect("device exists");
                    fingerprint.secured_nets = vec!["primary".into()];
                    (id.clone(), fingerprint)
                })
                .collect();
            augment_siat_fingerprints(project, &mut fingerprints, keyring);
            fingerprints
        }

        let project = AuthoredProject::parse(TOPOLOGY).expect("topology parses");
        let receiver = ProjectDeviceId("receiver".into());
        let group = u16::from_be_bytes(project.nets[&NetId("primary".into())].address.0);
        let keyring = Keyring::new("test".into(), "test".into(), "test".into()).with_interfaces(vec![
            zweidraehte_ets_files::keyring::KeyringInterface::new(
                zweidraehte_ets_files::keyring::KeyringInterfaceType::Usb,
                crate::IndividualAddress::new(1, 1, 250),
            )
            .with_group_addresses(vec![(group, vec![crate::IndividualAddress::new(1, 1, 99)])]),
        ]);

        assert_ne!(
            fingerprints(&project, None)[&receiver].siat_dependencies,
            fingerprints(&project, Some(&keyring))[&receiver].siat_dependencies
        );
    }

    fn deployed_fingerprints() -> DeploymentFingerprints {
        DeploymentFingerprints {
            identity: "identity".into(),
            medium_configuration: "medium".into(),
            application: "application".into(),
            parameters: "parameters".into(),
            product_parameters: "legacy".into(),
            object_flags: "flags".into(),
            memberships: "memberships".into(),
            net_security: "security".into(),
            individual_address: "address".into(),
            secured_nets: vec!["net".into()],
            sender_nets: vec!["net".into()],
            siat_dependencies: "siat".into(),
        }
    }

    #[test]
    fn deployment_changes_select_the_minimal_semantic_scope() {
        let deployed = deployed_fingerprints();

        let mut parameters = deployed.clone();
        parameters.parameters = "changed".into();
        assert_eq!(
            deployment_download_scope(&parameters, Some(&deployed), DeviceProgrammingStatus::ALL),
            DownloadScope::Parameters
        );

        let mut group = deployed.clone();
        group.memberships = "changed".into();
        assert_eq!(
            deployment_download_scope(&group, Some(&deployed), DeviceProgrammingStatus::ALL),
            DownloadScope::GroupCommunication
        );

        let mut both = parameters;
        both.object_flags = "changed".into();
        assert_eq!(
            deployment_download_scope(&both, Some(&deployed), DeviceProgrammingStatus::ALL),
            DownloadScope::ParametersAndGroupCommunication
        );
    }

    #[test]
    fn uncertain_deployment_state_forces_the_full_flow() {
        let deployed = deployed_fingerprints();
        let mut changed_application = deployed.clone();
        changed_application.application = "changed".into();
        assert_eq!(
            deployment_download_scope(&changed_application, Some(&deployed), DeviceProgrammingStatus::ALL),
            DownloadScope::Full
        );
        assert_eq!(deployment_download_scope(&deployed, None, DeviceProgrammingStatus::ALL), DownloadScope::Full);
        assert_eq!(
            deployment_download_scope(&deployed, Some(&deployed), DeviceProgrammingStatus::NONE),
            DownloadScope::Full
        );

        let mut legacy = deployed.clone();
        legacy.application.clear();
        assert_eq!(
            deployment_download_scope(&deployed, Some(&legacy), DeviceProgrammingStatus::ALL),
            DownloadScope::Full
        );
    }

    #[test]
    fn unloaded_application_is_stale_even_when_fingerprints_match() {
        let id = ProjectDeviceId("relay".into());
        let fingerprints = deployed_fingerprints();
        let mut state = MutableProjectState::new("state".into());
        state.deployments.insert(id.0.clone(), fingerprints.clone());
        state.programming_statuses.insert(id.0.clone(), DeviceProgrammingStatus {
            individual_address: true,
            application_program: false,
            parameters: false,
            group_communication: false,
            medium_configuration: true,
        });

        let status = device_programming_status(&id, Some(&state), &fingerprints);

        assert!(is_stale_device(&id, Some(&state), &fingerprints));
        assert_eq!(deployment_download_scope(&fingerprints, Some(&fingerprints), status), DownloadScope::Full);
    }

    #[test]
    fn component_statuses_follow_their_deployment_dependencies() {
        let id = ProjectDeviceId("relay".into());
        let deployed = deployed_fingerprints();
        let mut state = MutableProjectState::new("state".into());
        state.deployments.insert(id.0.clone(), deployed.clone());

        let mut changed_address = deployed.clone();
        changed_address.identity = "other identity".into();
        let address_status = device_programming_status(&id, Some(&state), &changed_address);

        assert!(!address_status.individual_address);
        assert!(address_status.medium_configuration);

        let mut changed_medium = deployed.clone();
        changed_medium.medium_configuration = "other medium".into();
        let medium_status = device_programming_status(&id, Some(&state), &changed_medium);

        assert!(medium_status.individual_address);
        assert!(!medium_status.medium_configuration);

        let mut changed_application = deployed.clone();
        changed_application.application = "other application".into();
        let application_status = device_programming_status(&id, Some(&state), &changed_application);

        assert!(!application_status.application_program);
        assert!(!application_status.parameters);
        assert!(!application_status.group_communication);
    }
}
