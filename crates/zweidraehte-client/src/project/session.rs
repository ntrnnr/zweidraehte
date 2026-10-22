//! Batch preparation and execution under the project lock.

use crate::KnxBus;
use crate::commissioning::{
    Commissioner, CommissioningEvent, CommissioningIntent, CommissioningObserver, CommissioningVeto,
    DifferentialPolicy, ExecutionReport, ManagementAccessOptions, PreparationOptions, PreparedProgram,
    ProgrammingInput, TargetSelection,
};
use crate::configuration::ResolvedKeyMaterial;
use crate::project::error::{Error, Result};
use crate::security::{Keyring, SecurityStore};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use zweidraehte_project::{ProjectDeviceId, ProjectEvent, ProjectKeys, ProjectStore, ProjectWriter, SenderIdentity};

use super::keyring::KeyringImportPlan;
use super::revision::FileRevision;
use super::sequence::ProjectSeqStore;

use super::operation::ensure_not_cancelled;
use super::persistence::{
    commissioning_deployment_from_project, intent_with_baseline, record_programming_failure, record_success,
};
use super::{
    PlannedProjectDevice, ProgrammingBatchPlan, ProgrammingPolicy, ProjectBatchFailureStage, accept_zero_siat_sequence,
};
use crate::configuration::ErrorDetail;
/// Per-device policy which cannot be inferred from project topology alone.
#[derive(Clone)]
#[non_exhaustive]
pub struct ProjectDeviceCommissioningOptions {
    pub intent: CommissioningIntent,
    pub target: TargetSelection,
    pub allow_plaintext: bool,
    pub differential_policy: DifferentialPolicy,
}

impl ProjectDeviceCommissioningOptions {
    /// Secure-only access without a differential download.
    pub fn new(intent: CommissioningIntent, target: TargetSelection) -> Self {
        Self { intent, target, allow_plaintext: false, differential_policy: DifferentialPolicy::Disabled }
    }
}

/// One device's commissioning prepared against the live bus, retained with
/// the exact materialized input it was compiled from.
pub(crate) struct PreparedProjectDevice {
    planned: PlannedProjectDevice,
    commissioning: PreparedProgram,
}

impl PreparedProjectDevice {
    pub(crate) fn id(&self) -> &ProjectDeviceId {
        &self.planned.id
    }

    pub(crate) fn commissioning(&self) -> &PreparedProgram {
        &self.commissioning
    }
}

pub(crate) struct PreparedProjectBatch {
    devices: Vec<PreparedProjectDevice>,
    policy: ProgrammingPolicy,
}

impl PreparedProjectBatch {
    pub(crate) fn devices(&self) -> &[PreparedProjectDevice] {
        &self.devices
    }
}

/// Scopes a project observer to one device for the single-device commissioner.
struct DeviceObserver<'a, Observer: ?Sized> {
    device: &'a ProjectDeviceId,
    project: &'a mut Observer,
}

impl<Observer: CommissioningObserver<ProjectDeviceId> + ?Sized> CommissioningObserver for DeviceObserver<'_, Observer> {
    fn event(&mut self, _device: &(), event: CommissioningEvent) {
        self.project.event(self.device, event);
    }

    fn approve(&mut self, _device: &(), prepared: &PreparedProgram) -> core::result::Result<(), CommissioningVeto> {
        self.project.approve(self.device, prepared)
    }

    fn cancelled(&self) -> bool {
        self.project.cancelled()
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct ProjectDeviceCommissioningReport {
    pub id: ProjectDeviceId,
    pub report: ExecutionReport,
}

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ProjectBatchReport {
    pub devices: Vec<ProjectDeviceCommissioningReport>,
    /// Completed devices and failed targets with confirmed or uncertain physical effects.
    pub affected_devices: BTreeSet<ProjectDeviceId>,
    pub learned_targets: BTreeMap<ProjectDeviceId, crate::commissioning::LearnedTarget>,
    /// Serial changes successfully persisted to authored project text.
    pub serial_updates: BTreeMap<ProjectDeviceId, Option<[u8; 6]>>,
}

/// Owns the project lock and journal for one mutable bus session.
pub struct ProjectCommissioningSession {
    pub(super) store: Arc<LockedProjectStore>,
}

/// Sequence adapters and import plans share the same project writer.
pub(super) type LockedProjectStore = Mutex<ProjectWriter>;

/// Loaded credentials and the bus store sharing this session's exclusion.
#[non_exhaustive]
pub struct PreparedProjectSecurity {
    pub store: SecurityStore,
    pub keyring: Option<Keyring>,
}

impl ProjectCommissioningSession {
    pub fn begin(store: ProjectStore) -> Result<Self> {
        Self::from_writer(store.into_writer()?)
    }

    pub(super) fn from_writer(mut writer: ProjectWriter) -> Result<Self> {
        writer.begin_mutation()?;
        Ok(Self { store: Arc::new(Mutex::new(writer)) })
    }

    /// Open the same retained session in the explicitly requested recovery
    /// mode. Secure transmission remains blocked until
    /// [`finish_recovery`](Self::finish_recovery) records completion.
    pub fn begin_recovery(store: ProjectStore) -> Result<Self> {
        let mut writer = store.into_writer()?;
        writer.begin_recovery()?;
        Ok(Self { store: Arc::new(Mutex::new(writer)) })
    }

    /// Read current durable facts without exporting a guard across bus I/O.
    pub fn inspect<T>(&self, read: impl FnOnce(&ProjectStore) -> T) -> Result<T> {
        let store = self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?;
        Ok(read(store.store()))
    }

    /// A writable sequence capability keeps the project locked independently
    /// of this session's lifetime.
    pub fn sequence_store(&self) -> ProjectSeqStore {
        ProjectSeqStore::new(Arc::clone(&self.store))
    }

    pub fn prepare_security(&self, keyring: Option<Keyring>) -> Result<PreparedProjectSecurity> {
        Ok(PreparedProjectSecurity { store: self.security_store(keyring.as_ref())?, keyring })
    }

    /// Reconcile decrypted ETS credentials without writing them. The plan
    /// retains this writer even if the session is dropped during review.
    /// Reload durable inputs under exclusion and reject changes during planning.
    pub fn plan_keyring_import(&self, keyring: &Keyring) -> Result<KeyringImportPlan> {
        let mut store = self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?;
        let files = FileRevision::capture(ProjectStore::input_files(store.project_path()))?;
        store.begin_mutation()?;
        KeyringImportPlan::prepare(store.store(), keyring, Arc::clone(&self.store), files)
    }

    pub(super) fn security_store(&self, keyring: Option<&Keyring>) -> Result<SecurityStore> {
        let mut store = SecurityStore::with_store(Box::new(self.sequence_store()));
        if let Some(keyring) = keyring {
            store.import_keyring(keyring)?;
        }
        Ok(store)
    }

    pub(super) fn persist_serial(&self, device: &ProjectDeviceId, serial: Option<[u8; 6]>) -> Result<bool> {
        let mut store = self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?;
        let source = store.authored().render_device_serial_update(device, serial)?;
        if source == store.authored().source() {
            return Ok(false);
        }
        store.update_authored(source)?;
        Ok(true)
    }

    /// Persist generated keys under the same writer exclusion as programming.
    pub(crate) fn materialize_tool_keys(&self, plan: &mut ProgrammingBatchPlan) -> Result<usize> {
        let mut store = self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?;
        let mut keys = store.keys_mut().ok_or(zweidraehte_project::ProjectStoreError::NotInitialized)?;
        plan.materialize_tool_keys(&mut keys)
    }

    pub fn advance_client_sequence(&self, floor: u64) -> Result<u64> {
        Ok(self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?.advance_client_sequence(floor)?)
    }

    pub fn observe_device_outgoing(&self, serial: String, next: u64) -> Result<()> {
        Ok(self
            .store
            .lock()
            .map_err(|_| Error::ProjectStorePoisoned)?
            .record(ProjectEvent::ObserveDeviceOutgoing { serial, next })?)
    }

    pub fn observe_device_siat(&self, serial: String, sender: SenderIdentity, last_valid: u64) -> Result<()> {
        Ok(self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?.record(ProjectEvent::ObserveDeviceSiat {
            serial,
            sender,
            last_valid,
        })?)
    }

    /// Compact durable work; surviving sequence adapters retain exclusion.
    /// Shut down the bus explicitly before finishing when no writer should remain.
    pub fn finish(self) -> Result<()> {
        self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?.compact()?;
        Ok(())
    }

    /// Finish recovery and compact, retaining exclusion for surviving adapters.
    pub fn finish_recovery(self) -> Result<()> {
        let mut failures = Vec::new();
        if let Err(error) = self.complete_recovery() {
            failures.push(super::ProjectFinalizationFailure::Recovery(error));
        }
        if let Err(error) = self.finish() {
            failures.push(super::ProjectFinalizationFailure::Compact(error));
        }
        super::operation::finish_result(Ok(ProjectBatchReport::default()), failures).map(|_| ())
    }

    pub(super) fn complete_recovery(&self) -> Result<()> {
        self.store.lock().map_err(|_| Error::ProjectStorePoisoned)?.finish_recovery()?;
        Ok(())
    }
}

impl ProgrammingBatchPlan {
    /// Generate every missing tool key and persist it before a bus is opened.
    pub(crate) fn materialize_tool_keys(&mut self, keys: &mut ProjectKeys<'_>) -> Result<usize> {
        let mut generated = 0;
        for device in &mut self.devices {
            if !device.device.key_material().needs_tool_key_generation() {
                continue;
            }
            let key = keys.generate_tool_key(device.id.as_str())?;
            super::keys::install_generated_tool_key(device.device.key_material_mut(), &device.id, key);
            generated += 1;
        }
        Ok(generated)
    }

    /// Run complete read-only discovery and compilation while forwarding the
    /// generic events which make target polling visible and cancellable.
    pub(crate) async fn prepare(
        self,
        bus: &KnxBus,
        observer: &mut impl CommissioningObserver<ProjectDeviceId>,
    ) -> Result<PreparedProjectBatch> {
        let ProgrammingBatchPlan { devices: mut planned_devices, siat_senders, policy, .. } = self;

        // Missing or obsolete image history cannot authorize a partial run.
        // Resolve this before opening even the read-only sender connections.
        let mut deployments = BTreeMap::new();
        for planned in &mut planned_devices {
            let device_options = &mut planned.commissioning;
            let deployment = planned.previous_commissioning.as_ref().and_then(|record| {
                commissioning_deployment_from_project(record)
                    .map_err(|error| {
                        log::warn!("unusable commissioning baseline for `{}`: {error}", planned.id);
                    })
                    .ok()
            });
            device_options.intent =
                intent_with_baseline(device_options.intent, device_options.differential_policy, deployment.is_some())?;
            if device_options.differential_policy != DifferentialPolicy::Disabled {
                deployments.insert(planned.id.clone(), deployment);
            }
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
            ensure_not_cancelled(observer)?;
            let key_material = match &sender.probe_key_material {
                Some(key_material) => key_material.clone(),
                None => planned_devices
                    .iter()
                    .find(|device| device.device.individual_address() == sender.address)
                    .map(|device| device.device.key_material().clone())
                    .ok_or_else(|| {
                        Error::InvalidProject(ErrorDetail::new(format!(
                            "managed SIAT sender {} has neither an affected device nor probe credentials",
                            sender.address
                        )))
                    })?,
            };

            // Query each sender independently with the installed Tool Key. Do
            // not let the general commissioning helper fall back to the FDSK:
            // this pass is proving the sequence used by an already
            // commissioned sender, not bootstrapping its security.
            //
            // Zero is safe only when durable state proves that the device is
            // untouched or was completely unloaded. Once commissioning or
            // sequence evidence exists, an unavailable sender must stop
            // preparation instead of silently weakening every receiver's
            // replay floor.
            let queried = bus
                .connect_management_synchronized(sender.address, key_material.management_keys().tool_key_only(), false)
                .await;
            let (connection, _) = match queried {
                Ok(opened) => opened,
                Err(error) => {
                    accept_zero_siat_sequence(sender, &error.to_string())?;
                    continue;
                }
            };

            let remote_next_sequence = connection.last_security_sync_remote_sequence();
            if let Err(error) = connection.close().await {
                log::warn!("could not close SIAT sender {} after synchronization: {error}", sender.address);
            }

            let Some(remote_next_sequence) = remote_next_sequence.filter(|sequence| *sequence != 0) else {
                accept_zero_siat_sequence(sender, "synchronization returned no nonzero remote sequence")?;
                continue;
            };

            remote_next_sequences.insert(sender.address, remote_next_sequence);
        }

        // Prepared commissioning plans are immutable. Raise every SIAT row
        // before lowering application security, then compile exactly once so
        // the inspected image and the executed image cannot diverge.
        for device in &mut planned_devices {
            raise_siat_rows(device.device.key_material_mut(), &remote_next_sequences);
        }

        let mut devices = Vec::with_capacity(planned_devices.len());

        for mut planned in planned_devices {
            ensure_not_cancelled(observer)?;
            let commissioner = Commissioner::new(bus).with_options(policy.commissioner);

            let ProjectDeviceCommissioningOptions { intent, target, allow_plaintext, differential_policy } =
                planned.commissioning.clone();
            let deployment = deployments.remove(&planned.id).flatten();

            let credentials = commissioning_credentials(allow_plaintext);
            let mut preparation = PreparationOptions::new(credentials);
            preparation.differential_policy = differential_policy;
            preparation.deployment = deployment;
            let input = ProgrammingInput::new(planned.device.clone(), intent, planned.compile_options(intent, target));

            let mut device = DeviceObserver { device: &planned.id, project: &mut *observer };
            let commissioning = commissioner.prepare(input, preparation, &mut device).await?;
            if let Some(sections) = commissioning.plan().program_sections() {
                planned.automatic_sections = sections;
            }

            // Retain the complete materialized input beside the prepared
            // procedure. This makes the preparation reproducible and lets a
            // compatibility runner hand the exact same instance to another
            // engine instead of reconstructing its key or selector state.
            devices.push(PreparedProjectDevice { planned, commissioning });
        }

        Ok(PreparedProjectBatch { devices, policy })
    }
}

impl ProjectCommissioningSession {
    /// Re-evaluate each initially selected target after persisting the preceding
    /// outcome. Inputs are loaded before this call; no store guard crosses I/O.
    /// The observer may inspect/veto a prepared target before it is executed.
    /// Later failures retain all earlier physical reports in `ProjectBatch`.
    pub(crate) async fn program_queued(
        &self,
        bus: &KnxBus,
        initial: ProgrammingBatchPlan,
        inputs: ProjectProgrammingInputs<'_>,
        observer: &mut impl CommissioningObserver<ProjectDeviceId>,
    ) -> Result<ProjectBatchReport> {
        let mut reports = Vec::new();
        // The caller's plan may predate this locked session or use different
        // loaded inputs. Validate the complete queue before its first write;
        // later per-target evaluation incorporates newly persisted evidence.
        for original in &initial.devices {
            ensure_not_cancelled(observer).map_err(|source| {
                project_batch_error(
                    original.id.clone(),
                    ProjectBatchFailureStage::Preparation,
                    Vec::new(),
                    source,
                    Vec::new(),
                )
            })?;
            self.replan_queued_device(original, &inputs, initial.policy).map_err(|source| {
                project_batch_error(
                    original.id.clone(),
                    ProjectBatchFailureStage::Preparation,
                    Vec::new(),
                    source,
                    Vec::new(),
                )
            })?;
        }
        for original in initial.devices {
            let id = original.id.clone();
            let prepare = async {
                ensure_not_cancelled(observer)?;
                let plan = self.replan_queued_device(&original, &inputs, initial.policy)?;
                if initial.skip_current && plan.devices.iter().all(|device| device.status.is_complete()) {
                    return Ok(None);
                }
                let batch = plan.prepare(bus, observer).await?;
                for device in batch.devices() {
                    observer.approve(device.id(), device.commissioning()).map_err(Error::Vetoed)?;
                }
                Ok(Some(batch))
            }
            .await;
            let batch = match prepare {
                Ok(Some(batch)) => batch,
                Ok(None) => continue,
                Err(source) => {
                    return Err(project_batch_error(
                        id.clone(),
                        ProjectBatchFailureStage::Preparation,
                        reports,
                        source,
                        Vec::new(),
                    ));
                }
            };
            match self.execute(bus, batch, observer).await {
                Ok(batch) => reports.extend(batch.devices),
                Err(Error::ProjectBatch(mut failure)) => {
                    reports.append(&mut failure.report.devices);
                    failure.report.devices = reports;
                    failure.capture_effects();
                    return Err(Error::ProjectBatch(failure));
                }
                Err(source) => {
                    return Err(project_batch_error(
                        id.clone(),
                        ProjectBatchFailureStage::Commissioning,
                        reports,
                        source,
                        Vec::new(),
                    ));
                }
            }
        }
        Ok(ProjectBatchReport::from_devices(reports))
    }

    fn replan_queued_device(
        &self,
        original: &PlannedProjectDevice,
        inputs: &ProjectProgrammingInputs<'_>,
        policy: ProgrammingPolicy,
    ) -> Result<ProgrammingBatchPlan> {
        self.inspect(|store| {
            let mut plan = super::ProjectPlanner::for_store(store.authored(), store, inputs.products, inputs.keyring)
                .with_master_data(inputs.master_data)
                .plan_commissioning(
                    std::slice::from_ref(&original.id),
                    super::BatchSelection::Selected,
                    original.evaluated_intent,
                )?;
            plan.set_policy(policy);
            if let Some(target) = &original.target_override {
                plan.set_target(&original.id, target.clone())?;
            }
            Ok(plan)
        })?
    }

    /// Execute the immutable prepared batch with frontend-owned cancellation.
    /// The same event vocabulary is used during preparation and mutation.
    pub(crate) async fn execute(
        &self,
        bus: &KnxBus,
        batch: PreparedProjectBatch,
        observer: &mut impl CommissioningObserver<ProjectDeviceId>,
    ) -> Result<ProjectBatchReport> {
        let PreparedProjectBatch { devices, policy } = batch;
        let mut reports = Vec::with_capacity(devices.len());

        for device in devices {
            let PreparedProjectDevice { planned, commissioning } = device;
            let commissioner = Commissioner::new(bus).with_options(policy.commissioner);
            let id = planned.id.clone();
            let mut device = DeviceObserver { device: &id, project: &mut *observer };
            match commissioner.execute(commissioning, &mut device).await {
                Ok(report) => {
                    let persistence =
                        record_success(&self.store, &planned, &report, report.effects().affected_sections());
                    reports.push(ProjectDeviceCommissioningReport { id, report });
                    if let Err(failure) = persistence {
                        return Err(project_batch_error(
                            planned.id.clone(),
                            ProjectBatchFailureStage::SuccessPersistence,
                            reports,
                            failure.source,
                            failure.state_errors,
                        ));
                    }
                }
                Err(source) => {
                    let invalidated = source.effects().affected_sections().clone();
                    let state_errors = record_programming_failure(&self.store, &planned, invalidated, &source);
                    return Err(project_batch_error(
                        id.clone(),
                        ProjectBatchFailureStage::Commissioning,
                        reports,
                        Error::Commissioning(source),
                        state_errors,
                    ));
                }
            }
        }

        Ok(ProjectBatchReport::from_devices(reports))
    }
}

/// Static project inputs acquired before any queue mutation begins.
pub(crate) struct ProjectProgrammingInputs<'a> {
    pub(crate) products: &'a BTreeMap<ProjectDeviceId, super::ProjectProduct>,
    pub(crate) master_data: &'a super::ProjectMasterData,
    pub(crate) keyring: Option<&'a Keyring>,
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use crate::commissioning::DownloadMode;
    use crate::project::{BatchSelection, ProjectPlanner};

    #[test]
    fn generated_tool_key_provenance_matches_its_durable_project_scope() {
        use zweidraehte_project::{KeyId, KeyKind, KeyMaterialSource, KeyOrigin, KeyScope};

        let mut fixture = crate::project::tests::secure_fixture();
        let receiver_keys = fixture.keyring.devices.remove(0).with_tool_key(None);
        fixture.keyring.devices.insert(0, receiver_keys);
        let directory = tempfile::tempdir().expect("project directory");
        let path = directory.path().join("project.knx");
        std::fs::write(&path, fixture.project.source()).expect("authored fixture");
        let mut store = ProjectStore::open(path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let receiver = ProjectDeviceId::new("receiver").expect("literal is an identifier");
        let mut plan = ProjectPlanner::new(store.authored(), &fixture.products)
            .with_state(store.state().expect("initialized state"))
            .with_keyring(&fixture.keyring)
            .with_master_data(&fixture.catalogs)
            .plan_commissioning(
                std::slice::from_ref(&receiver),
                BatchSelection::Selected,
                CommissioningIntent::Download(DownloadMode::Full),
            )
            .expect("imported FDSK permits key generation");
        let session = ProjectCommissioningSession::begin(store).expect("project writer");

        assert_eq!(session.materialize_tool_keys(&mut plan).expect("tool key persists"), 1);
        let saved = session
            .inspect(|store| {
                store
                    .keys()
                    .expect("keys")
                    .read(&KeyId { scope: KeyScope::Device(receiver.to_string()), kind: KeyKind::ToolKey }, None)
            })
            .expect("inspect saved key")
            .expect("read saved key")
            .expect("saved tool key");
        let material = plan.device(&receiver).expect("receiver").device().key_material();
        let provenance = material
            .provenance()
            .iter()
            .find(|metadata| metadata.origin == KeyOrigin::Generated)
            .expect("generation has provenance");
        assert_eq!(provenance, &saved.metadata);
        assert_eq!(material.tool_key(), Some(saved.value.key16_ref().expect("tool key width")));
        assert!(!material.needs_tool_key_generation());
        assert_eq!(session.materialize_tool_keys(&mut plan).expect("key stays stable"), 0);
    }

    #[test]
    fn queued_receiver_replans_from_persisted_sender_evidence() {
        let fixture = crate::project::tests::secure_fixture();
        let directory = tempfile::tempdir().expect("project directory");
        let path = directory.path().join("project.knx");
        std::fs::write(&path, fixture.project.source()).expect("authored fixture");
        let mut store = ProjectStore::open(path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let receiver = ProjectDeviceId::new("receiver").expect("literal is an identifier");
        let initial = ProjectPlanner::new(store.authored(), &fixture.products)
            .with_state(store.state().expect("initialized state"))
            .with_keyring(&fixture.keyring)
            .with_master_data(&fixture.catalogs)
            .plan_commissioning(
                std::slice::from_ref(&receiver),
                BatchSelection::Selected,
                CommissioningIntent::Download(DownloadMode::Full),
            )
            .expect("initial receiver plan");
        let original = initial.device(&receiver).expect("receiver");
        let session = ProjectCommissioningSession::begin(store).expect("writer owns state");

        // Earlier sender programming durably observes a newer outgoing epoch.
        // The receiver must compile from that result, not its initial snapshot.
        session.observe_device_outgoing("00FA:00000002".into(), 500).expect("persist sender observation");
        let replanned = session
            .replan_queued_device(
                original,
                &ProjectProgrammingInputs {
                    products: &fixture.products,
                    master_data: &fixture.catalogs,
                    keyring: Some(&fixture.keyring),
                },
                Default::default(),
            )
            .expect("receiver replans");
        let current = replanned.device(&receiver).expect("same receiver target");
        assert_eq!(replanned.devices().len(), 1);
        assert_eq!(current.device().key_material().application_security().expect("secure receiver").siat(), &[(
            fixture.sender,
            499
        )]);
        assert_eq!(
            original.device().key_material().application_security().expect("initial secure receiver").siat(),
            &[(fixture.sender, 0)]
        );
    }
}

fn project_batch_error(
    device: ProjectDeviceId,
    stage: ProjectBatchFailureStage,
    physical_reports: Vec<ProjectDeviceCommissioningReport>,
    source: Error,
    state_errors: Vec<Error>,
) -> Error {
    let mut failure = ProjectBatchFailure {
        device: Some(device),
        stage,
        report: ProjectBatchReport::from_devices(physical_reports),
        source: Some(Box::new(source)),
        state_errors,
        finalization: Vec::new(),
    };
    failure.capture_effects();
    Error::ProjectBatch(Box::new(failure))
}

fn commissioning_credentials(allow_plaintext: bool) -> ManagementAccessOptions {
    ManagementAccessOptions::new().allow_plaintext(allow_plaintext)
}

fn raise_siat_rows(
    key_material: &mut ResolvedKeyMaterial,
    remote_next_sequences: &BTreeMap<zweidraehte_proto::address::IndividualAddress, u64>,
) {
    let Some(security) = key_material.application_security_mut() else {
        return;
    };

    let mut rows: BTreeMap<_, _> = security.siat().iter().copied().collect();
    let mut changed = false;

    for (address, last_valid) in &mut rows {
        let Some(remote_next_sequence) = remote_next_sequences.get(address) else {
            continue;
        };

        // The project image stores the raw `SeqNrremote` returned by Sync,
        // whereas live receiver state is expressed as `SeqNrremote - 1`.
        if *last_valid < *remote_next_sequence {
            *last_valid = *remote_next_sequence;
            changed = true;
        }
    }

    if changed {
        security.replace_siat(rows.into_iter().collect());
    }
}

/// Completed physical work retained when a later batch stage fails.
#[derive(Debug)]
#[non_exhaustive]
pub struct ProjectBatchFailure {
    /// Absent for project-wide setup/finalization failures.
    pub device: Option<ProjectDeviceId>,
    pub stage: crate::project::ProjectBatchFailureStage,
    /// Successful physical reports survive post-execution journal errors.
    /// Callers can therefore distinguish a retryable device failure from
    /// a completed mutation whose project evidence needs recovery.
    pub report: ProjectBatchReport,
    pub source: Option<Box<Error>>,
    pub state_errors: Vec<Error>,
    pub finalization: Vec<super::ProjectFinalizationFailure>,
}

impl std::fmt::Display for ProjectBatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "project batch {} failed", self.stage)?;
        if let Some(device) = &self.device {
            write!(f, " at `{device}`")?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        if !self.report.devices.is_empty() {
            write!(
                f,
                "; physically completed: {:?}",
                self.report.devices.iter().map(|device| &device.id).collect::<Vec<_>>()
            )?;
        }
        for error in &self.state_errors {
            write!(f, "; inconsistent-state journal error: {error}")?;
        }
        for failure in &self.finalization {
            write!(f, "; {failure}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ProjectBatchFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as &(dyn std::error::Error + 'static))
    }
}
