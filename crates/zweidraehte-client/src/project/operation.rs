//! Project-wide lifetime and finalization around the existing commissioning queue.
//!
//! Cancellation is cooperative: callers must await the operation to receive its
//! physical and persistence outcomes. Dropping the future only provides the bus
//! actor's best-effort shutdown; it cannot complete asynchronous finalization.

use super::{
    ProgrammingBatchPlan, ProjectBatchFailure, ProjectBatchFailureStage, ProjectBatchReport,
    ProjectCommissioningSession, ProjectProgrammingInputs,
};
use crate::PropertyAddress;
use crate::commissioning::{
    CommissioningError, CommissioningObserver, Diagnostic, ExecutionEffects, LearnedTarget, MutationStatus,
};
use crate::project::error::{Error, Result};
use crate::security::{Keyring, SecurityStore};
use crate::{BusResult, KnxBus};
use std::future::Future;
use zweidraehte_project::{ProgrammingSection, ProjectDeviceId};

#[cfg(test)]
mod tests;

/// Run the exact selected queue, retaining all effects and cleanup failures.
///
/// Missing Tool Keys are persisted first when the plan's policy asks for it,
/// so a generated key is durable before any device can receive it.
pub(crate) async fn execute_batch<Connect, Connecting>(
    session: ProjectCommissioningSession,
    mut plan: ProgrammingBatchPlan,
    connect: Connect,
    inputs: ProjectProgrammingInputs<'_>,
    observer: &mut impl CommissioningObserver<ProjectDeviceId>,
) -> Result<ProjectBatchReport>
where
    Connect: FnOnce(SecurityStore) -> Connecting,
    Connecting: Future<Output = BusResult<KnxBus>>,
{
    if let Err(error) = ensure_not_cancelled(observer) {
        return Err(setup_failure(session, error));
    }
    if plan.policy().generate_missing_tool_keys
        && let Err(error) = session.materialize_tool_keys(&mut plan)
    {
        return Err(setup_failure(session, error));
    }
    let operation = ProjectOperation::connect(session, inputs.keyring, connect).await?;
    operation.program(plan, inputs, observer).await
}

/// Cancellation before a device is touched is a commissioning failure with no
/// physical effect, exactly like cancellation inside the commissioner.
pub(super) fn ensure_not_cancelled(observer: &impl CommissioningObserver<ProjectDeviceId>) -> Result<()> {
    if observer.cancelled() {
        return Err(CommissioningError::before_execution(Diagnostic::new("commissioning was cancelled")).into());
    }
    Ok(())
}

/// Owns the bus and the project writer until explicit async finalization.
#[must_use = "await an operation or finish to collect outcomes and finalize"]
pub struct ProjectOperation {
    session: ProjectCommissioningSession,
    bus: KnxBus,
}

impl std::fmt::Debug for ProjectOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectOperation").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectFinalizationFailure {
    #[error("persisting serial for `{device}`: {source}")]
    AuthoredSerial {
        device: ProjectDeviceId,
        #[source]
        source: Error,
    },
    #[error("disconnecting the bus: {0}")]
    Disconnect(#[source] Error),
    #[error("compacting project state: {0}")]
    Compact(#[source] Error),
    #[error("completing project recovery: {0}")]
    Recovery(#[source] Error),
}

impl ProjectOperation {
    /// Prepare security and connect. Setup failure still compacts the journal.
    pub async fn connect<C, Fut>(
        session: ProjectCommissioningSession,
        keyring: Option<&Keyring>,
        connect: C,
    ) -> Result<Self>
    where
        C: FnOnce(SecurityStore) -> Fut,
        Fut: Future<Output = BusResult<KnxBus>>,
    {
        let security = match session.security_store(keyring) {
            Ok(security) => security,
            Err(error) => return Err(setup_failure(session, error)),
        };
        match connect(security).await {
            Ok(bus) => Ok(Self { session, bus }),
            Err(error) => Err(setup_failure(session, error.into())),
        }
    }

    pub fn bus(&self) -> &KnxBus {
        &self.bus
    }
    pub fn session(&self) -> &ProjectCommissioningSession {
        &self.session
    }

    pub(crate) async fn program(
        self,
        plan: ProgrammingBatchPlan,
        inputs: ProjectProgrammingInputs<'_>,
        observer: &mut impl CommissioningObserver<ProjectDeviceId>,
    ) -> Result<ProjectBatchReport> {
        let result = self.session.program_queued(&self.bus, plan, inputs, observer).await;
        self.finish(result).await
    }

    /// Reconcile authored identities, disconnect, then compact. Every phase is
    /// attempted even when an earlier phase fails; physical reports survive.
    ///
    /// Programming never completes recovery; only synchronization does.
    pub(crate) async fn finish(self, result: Result<ProjectBatchReport>) -> Result<ProjectBatchReport> {
        let mut outcome = capture(result);
        let mut failures = reconcile_serials(&self.session, &self.bus, &mut outcome).await;
        failures.extend(self.close(false).await);
        finish_result(outcome, failures)
    }

    /// Programming and raw management share ordered cleanup and retain every
    /// failure. Their reports remain separate because they describe different
    /// evidence: configuration effects versus diagnostic observations.
    pub(super) async fn close(self, complete_recovery: bool) -> Vec<ProjectFinalizationFailure> {
        let mut failures = Vec::new();
        if let Err(error) = self.bus.disconnect().await {
            failures.push(ProjectFinalizationFailure::Disconnect(error.into()));
        }
        // Recovery completion and compaction are separate: a failed completion
        // must not suppress the attempt to preserve already-observed evidence.
        if complete_recovery && let Err(error) = self.session.complete_recovery() {
            failures.push(ProjectFinalizationFailure::Recovery(error));
        }
        if let Err(error) = self.session.finish() {
            failures.push(ProjectFinalizationFailure::Compact(error));
        }
        failures
    }
}

type Outcome = std::result::Result<ProjectBatchReport, Box<ProjectBatchFailure>>;

fn capture(result: Result<ProjectBatchReport>) -> Outcome {
    let mut outcome = result.map_err(|error| match error {
        Error::ProjectBatch(failure) => failure,
        source => Box::new(ProjectBatchFailure {
            device: None,
            stage: ProjectBatchFailureStage::Preparation,
            report: ProjectBatchReport::default(),
            source: Some(Box::new(source)),
            state_errors: Vec::new(),
            finalization: vec![],
        }),
    });
    match &mut outcome {
        Ok(report) => report.capture_effects(),
        Err(failure) => failure.capture_effects(),
    }
    outcome
}

impl ProjectBatchReport {
    pub(super) fn from_devices(devices: Vec<super::ProjectDeviceCommissioningReport>) -> Self {
        let mut report = Self { devices, ..Default::default() };
        report.capture_effects();
        report
    }

    fn capture_effects(&mut self) {
        for completed in &self.devices {
            record_effects(
                &completed.id,
                completed.report.effects(),
                completed.report.discovered.serial_number,
                &mut self.affected_devices,
                &mut self.learned_targets,
            );
        }
    }
}

impl ProjectBatchFailure {
    /// A failure at `stage` that retains `report`, for frontends that replay
    /// or simulate a batch outcome.
    pub fn new(stage: crate::project::ProjectBatchFailureStage, report: ProjectBatchReport) -> Self {
        Self { device: None, stage, report, source: None, state_errors: Vec::new(), finalization: Vec::new() }
    }

    pub(super) fn capture_effects(&mut self) {
        self.report.capture_effects();
        if let Some(device) = &self.device
            && let Some(Error::Commissioning(error)) = self.source.as_deref()
        {
            record_effects(
                device,
                error.effects(),
                None,
                &mut self.report.affected_devices,
                &mut self.report.learned_targets,
            );
        }
    }
}

fn record_effects(
    id: &ProjectDeviceId,
    effects: &ExecutionEffects,
    serial: Option<[u8; 6]>,
    affected: &mut std::collections::BTreeSet<ProjectDeviceId>,
    targets: &mut std::collections::BTreeMap<ProjectDeviceId, LearnedTarget>,
) {
    if !effects.affected_sections().is_empty()
        || matches!(effects.mutation_status(), MutationStatus::PartiallyApplied | MutationStatus::Complete)
    {
        affected.insert(id.clone());
    }
    if let Some(mut target) = effects.learned_target() {
        target.serial_number =
            target.serial_number.filter(|serial| *serial != [0; 6]).or(serial.filter(|serial| *serial != [0; 6]));
        targets.insert(id.clone(), target);
    }
}

fn report_mut(outcome: &mut Outcome) -> &mut ProjectBatchReport {
    match outcome {
        Ok(report) => report,
        Err(failure) => &mut failure.report,
    }
}

async fn reconcile_serials(
    session: &ProjectCommissioningSession,
    bus: &KnxBus,
    outcome: &mut Outcome,
) -> Vec<ProjectFinalizationFailure> {
    let report = report_mut(outcome);
    for target in report.learned_targets.values_mut().filter(|target| target.serial_number.is_none()) {
        // This is optional identity discovery after confirmed assignment. Some
        // legacy devices do not expose a serial; their confirmed address remains.
        if let Ok(value) = bus.network_management().property_read(target.address, serial_number_property(), 1, 1).await
        {
            target.serial_number = value.try_into().ok().filter(|serial| *serial != [0; 6]);
        }
    }
    let mut updates = std::collections::BTreeMap::new();
    for completed in &report.devices {
        if completed.report.effects().cleared_sections().contains(&ProgrammingSection::Address) {
            updates.insert(completed.id.clone(), None);
        }
    }
    if let Err(failure) = &outcome
        && let Some(device) = &failure.device
        && let Some(Error::Commissioning(error)) = failure.source.as_deref()
        && error.effects().cleared_sections().contains(&ProgrammingSection::Address)
    {
        updates.insert(device.clone(), None);
    }
    let report = report_mut(outcome);
    for (id, target) in &report.learned_targets {
        if let Some(serial) = target.serial_number {
            updates.insert(id.clone(), Some(serial));
        }
    }
    let mut failures = Vec::new();
    for (device, serial) in updates {
        match session.persist_serial(&device, serial) {
            Ok(true) => {
                report.serial_updates.insert(device, serial);
            }
            Ok(false) => {}
            Err(source) => failures.push(ProjectFinalizationFailure::AuthoredSerial { device, source }),
        }
    }
    failures
}

fn setup_failure(session: ProjectCommissioningSession, source: Error) -> Error {
    let mut failure = ProjectBatchFailure {
        device: None,
        stage: ProjectBatchFailureStage::Preparation,
        report: ProjectBatchReport::default(),
        source: Some(Box::new(source)),
        state_errors: Vec::new(),
        finalization: vec![],
    };
    if let Err(error) = session.finish() {
        failure.finalization.push(ProjectFinalizationFailure::Compact(error));
    }
    Error::ProjectBatch(Box::new(failure))
}

pub(super) fn finish_result(outcome: Outcome, failures: Vec<ProjectFinalizationFailure>) -> Result<ProjectBatchReport> {
    match outcome {
        Ok(report) if failures.is_empty() => Ok(report),
        Ok(report) => Err(Error::ProjectBatch(Box::new(ProjectBatchFailure {
            device: None,
            stage: ProjectBatchFailureStage::Finalization,
            report,
            source: None,
            state_errors: Vec::new(),
            finalization: failures,
        }))),
        Err(mut failure) => {
            failure.finalization.extend(failures);
            Err(Error::ProjectBatch(failure))
        }
    }
}

/// `PID_SERIAL_NUMBER` of the device object.
fn serial_number_property() -> PropertyAddress {
    PropertyAddress::indexed(0, crate::pid::SERIAL_NUMBER).expect("PID_SERIAL_NUMBER fits one octet")
}
