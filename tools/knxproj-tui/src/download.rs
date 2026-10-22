//! Project programming worker for the synchronous terminal UI.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;
use zweidraehte_client::project::{
    BatchSelection, ProgrammingPolicy, ProjectBatchReport, ProjectInputRequest, ProjectOperationInputs,
    ProjectSetupRequirement, Result as ProjectResult, SerialAddressingSupport,
};

use tokio::sync::mpsc::UnboundedReceiver;

use crate::error_message;
use zweidraehte_client::cli::SecurityArgs;
use zweidraehte_client::commissioning::{
    CommissionerOptions, CommissioningEvent, CommissioningIntent, CommissioningObserver, CommissioningStage,
    CommissioningVeto, CompiledProgram, DifferentialFallback, DifferentialPolicy, DownloadMode, PreparedProgram,
    ProgramSections, ProgrammingModePolling, TargetSelection, UnloadMode,
};
use zweidraehte_client::{BusTarget, IndividualAddress, KnxBus};
use zweidraehte_project::{ProjectDeviceId, ProjectStore};

const PROGRAMMING_MODE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The five programming operations exposed by ETS. Keeping this vocabulary
/// at the UI/worker boundary prevents shortcut names from acquiring subtly
/// different meanings than the operation the worker actually performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgrammingOperation {
    All,
    Partial,
    IndividualAddress,
    OverwriteIndividualAddress,
    Application,
}

impl ProgrammingOperation {
    pub const ALL: [Self; 5] =
        [Self::All, Self::Partial, Self::IndividualAddress, Self::OverwriteIndividualAddress, Self::Application];

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "IA & application",
            Self::Partial => "Partial download",
            Self::IndividualAddress => "Individual address",
            Self::OverwriteIndividualAddress => "Overwrite individual address",
            Self::Application => "Application",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::All => "Download all project data and commission the IA when needed.",
            Self::Partial => "Download only project data whose programming status is stale.",
            Self::IndividualAddress => "Assign the configured IA by serial number or programming mode.",
            Self::OverwriteIndividualAddress => "Replace an entered current IA; retain Security Mode and Tool Key.",
            Self::Application => "Download the application while retaining the configured IA.",
        }
    }

    pub const fn supports_affected_target(self) -> bool {
        matches!(self, Self::All | Self::Partial)
    }

    const fn intent(self) -> CommissioningIntent {
        match self {
            Self::All => CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full),
            Self::Partial => CommissioningIntent::AssignAddressAndDownload(DownloadMode::Automatic),
            Self::IndividualAddress | Self::OverwriteIndividualAddress => CommissioningIntent::AssignAddress,
            Self::Application => CommissioningIntent::Download(DownloadMode::Full),
        }
    }
}

/// The two useful ETS-style device unload scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnloadScope {
    Application,
    All,
}

impl UnloadScope {
    pub const ALL: [Self; 2] = [Self::Application, Self::All];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Application => "Application only",
            Self::All => "All",
        }
    }

    const fn mode(self) -> UnloadMode {
        match self {
            Self::Application => UnloadMode::Application,
            Self::All => UnloadMode::AllConfiguration,
        }
    }
}

#[derive(Debug)]
pub enum DownloadMsg {
    Task(String, usize, usize),
    Data(u64, u64),
    AwaitingProgrammingMode { serial_number: Option<[u8; 6]> },
    Done(Result<DownloadOutcome, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadControl {
    UseSerialNumber,
    Cancel,
}

#[derive(Debug)]
pub struct DownloadOutcome {
    pub project_path: PathBuf,
    pub summary: String,
    pub execution: ProjectResult<ProjectBatchReport>,
    /// Exact product/dependency closure whose persisted evidence may have
    /// changed during this operation.
    pub status_scope: std::collections::BTreeSet<ProjectDeviceId>,
}

pub struct DownloadJob {
    pub target: BusTarget,
    pub project_path: PathBuf,
    pub device: Option<ProjectDeviceId>,
    /// Select every device whose desired deployment fingerprint changed.
    pub affected_only: bool,
    pub master_data: Option<PathBuf>,
    pub security: SecurityArgs,
    pub operation: ProgrammingOperation,
    pub overwrite_current_address: Option<IndividualAddress>,
    pub control: UnboundedReceiver<DownloadControl>,
}

pub struct UnloadJob {
    pub target: BusTarget,
    pub project_path: PathBuf,
    pub device: ProjectDeviceId,
    pub master_data: Option<PathBuf>,
    pub security: SecurityArgs,
    pub scope: UnloadScope,
}

pub fn spawn(job: DownloadJob, tx: Sender<DownloadMsg>) {
    std::thread::spawn(move || {
        let outcome = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime.block_on(run(job, &tx)),
            Err(error) => Err(format!("starting the async runtime: {error}")),
        };
        let _ = tx.send(DownloadMsg::Done(outcome));
    });
}

pub fn spawn_unload(job: UnloadJob, tx: Sender<DownloadMsg>) {
    std::thread::spawn(move || {
        let outcome = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime.block_on(run_unload(job, &tx)),
            Err(error) => Err(format!("starting the async runtime: {error}")),
        };
        let _ = tx.send(DownloadMsg::Done(outcome));
    });
}

async fn run(mut job: DownloadJob, tx: &Sender<DownloadMsg>) -> Result<DownloadOutcome, String> {
    let stage = |text: &str| {
        let _ = tx.send(DownloadMsg::Task(text.to_string(), 0, 0));
    };

    stage("Opening project");
    let store = ProjectStore::open(&job.project_path).map_err(|error| format!("opening project: {error}"))?;
    let selected: Vec<_> = job.device.iter().cloned().collect();
    let requested_intent = job.operation.intent();

    if job.operation == ProgrammingOperation::OverwriteIndividualAddress && job.affected_only {
        return Err("overwrite IA requires one selected device".into());
    }

    let selection = programming_batch_selection(job.affected_only);
    let mut request = ProjectInputRequest::new(&selected, selection, requested_intent);
    request.sources.master_data = job.master_data.as_deref();
    request.sources.keyring_path = job.security.keyring_path();
    let inputs = ProjectOperationInputs::load(store, request, || job.security.load_keyring().map_err(Into::into))
        .map_err(|error| format!("loading project programming inputs: {}", error_message(&error)))?;
    let product_scope = inputs.product_scope().clone();
    let mut programming =
        inputs.into_programming().map_err(|error| format!("planning project download: {}", error_message(&error)))?;
    if job.operation == ProgrammingOperation::Partial
        && !job.affected_only
        && programming.plan().devices().iter().all(|device| device.status().is_complete())
    {
        return Ok(DownloadOutcome {
            project_path: job.project_path,
            summary: "Selected device has no stale project data".into(),
            execution: Ok(Default::default()),
            status_scope: std::collections::BTreeSet::new(),
        });
    }
    if programming.plan().devices().is_empty() {
        return Ok(DownloadOutcome {
            project_path: job.project_path,
            summary: "No affected devices".into(),
            execution: Ok(Default::default()),
            status_scope: std::collections::BTreeSet::new(),
        });
    }

    let requirements = programming.requirements();
    if job.operation == ProgrammingOperation::Application
        && let Some(ProjectSetupRequirement::GenerateToolKey { device }) = requirements
            .iter()
            .find(|requirement| matches!(requirement, ProjectSetupRequirement::GenerateToolKey { .. }))
    {
        return Err(format!("{device} has no Tool Key; commission its address first"));
    }
    if requirements.contains(&ProjectSetupRequirement::RecoverProject) {
        return Err("project keys/state require recovery; use knx-loader recover-state".into());
    }

    let mut policy = ProgrammingPolicy::default();
    policy.differential = if job.operation == ProgrammingOperation::Partial {
        DifferentialPolicy::FallBackToUndifferenced
    } else {
        DifferentialPolicy::Disabled
    };
    // Overwriting a known IA retains the device's Security Mode and Tool Key.
    policy.generate_missing_tool_keys = job.operation != ProgrammingOperation::OverwriteIndividualAddress;
    programming.set_policy(policy);

    let plan = programming.plan();
    let address_targets = plan
        .devices()
        .iter()
        .filter(|device| {
            plan.impact().selected.contains(device.id()) && device.commissioning().intent.mutates_address()
        })
        .map(|device| device.id().clone())
        .collect::<Vec<_>>();
    let needs_programming_button = address_targets.iter().any(|device| {
        matches!(
            plan.device(device).expect("planned device").commissioning().target,
            TargetSelection::ProgrammingButton(_)
        )
    });

    let target_label = if job.affected_only { "Affected devices" } else { "Selected device" };
    stage(&format!(
        "{target_label}: {}",
        plan.devices().iter().map(|device| device.id().to_string()).collect::<Vec<_>>().join(", ")
    ));

    let interactive_assignment = !job.affected_only
        && job.operation != ProgrammingOperation::OverwriteIndividualAddress
        && address_targets.len() == 1;
    let assignment_target = interactive_assignment.then(|| {
        let device = plan
            .devices()
            .iter()
            .find(|device| device.id() == &address_targets[0])
            .expect("address target comes from the plan");
        (device.id().clone(), device.serial_addressing() == SerialAddressingSupport::Supported, device.serial_target())
    });
    match job.operation {
        ProgrammingOperation::OverwriteIndividualAddress => {
            let current =
                job.overwrite_current_address.ok_or_else(|| "overwrite IA requires the current address".to_string())?;
            let device =
                address_targets.first().ok_or_else(|| "overwrite IA requires one address target".to_string())?;
            programming
                .set_target(device, TargetSelection::KnownPreviousAddress(current))
                .map_err(|error| error.to_string())?;
        }
        _ if interactive_assignment => {
            let (device, serial_capable, serial_number) =
                assignment_target.as_ref().expect("interactive assignment has a target");
            let selection =
                await_assignment_target(&job.target, *serial_capable, *serial_number, &mut job.control, tx).await?;
            programming.set_target(device, selection.target).map_err(|error| error.to_string())?;
        }
        _ if needs_programming_button && (job.affected_only || address_targets.len() != 1) => {
            return Err(
                "multiple selected devices require physical programming mode; commission them one at a time".into()
            );
        }
        _ => {}
    }
    if programming.inputs().state_requirement() == Some(ProjectSetupRequirement::InitializeProject) {
        programming.initialize().map_err(|error| format!("initializing project state: {error}"))?;
    }
    stage("Connecting to the bus");
    let execution = programming
        .execute(|security| KnxBus::builder().with_security(security).connect(&job.target), &mut WorkerProgress { tx })
        .await;
    let completed = execution
        .as_ref()
        .map(|report| report.devices.iter().map(|device| device.id.to_string()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let verb = match job.operation {
        ProgrammingOperation::IndividualAddress | ProgrammingOperation::OverwriteIndividualAddress => "Commissioned",
        ProgrammingOperation::Application => "Loaded",
        ProgrammingOperation::All | ProgrammingOperation::Partial => "Programmed",
    };
    Ok(DownloadOutcome {
        project_path: job.project_path,
        summary: format!("{verb} {completed}"),
        execution,
        status_scope: product_scope,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentSelection {
    target: TargetSelection,
    serial_number: Option<[u8; 6]>,
}

async fn await_assignment_target(
    target: &BusTarget,
    serial_capable: bool,
    configured_serial: Option<[u8; 6]>,
    control: &mut UnboundedReceiver<DownloadControl>,
    tx: &Sender<DownloadMsg>,
) -> Result<AssignmentSelection, String> {
    let _ = tx.send(DownloadMsg::Task("Connecting for individual-address assignment".into(), 0, 0));
    let bus = KnxBus::connect(target).await.map_err(|error| format!("connecting for IA assignment: {error}"))?;
    let management = bus.network_management();
    let scan_window = CommissionerOptions::default().scan_window;

    let _ = tx.send(DownloadMsg::AwaitingProgrammingMode { serial_number: configured_serial });

    let selection = 'waiting: loop {
        tokio::select! {
            biased;

            command = control.recv() => {
                if let Some(decision) = assignment_control_decision(command, configured_serial) {
                    break decision;
                }
            }
            found = management.await_programming_mode(scan_window, PROGRAMMING_MODE_TIMEOUT) => {
                let found = match found {
                    Ok(found) => found,
                    Err(error) => break Err(format!("polling physical programming mode: {error}")),
                };
                match found.as_slice() {
                    [] => break Err("no device entered physical programming mode within five minutes".to_string()),
                    [address] => {
                        if let Some(decision) = pending_assignment_control(control, configured_serial) {
                            break decision;
                        }

                        let serial_number = if serial_capable {
                            let serial_read = tokio::select! {
                                biased;

                                command = control.recv() => {
                                    if let Some(decision) = assignment_control_decision(command, configured_serial) {
                                        break 'waiting decision;
                                    }

                                    continue 'waiting;
                                }
                                serial = read_programming_mode_serial(&management, *address, scan_window) => serial,
                            };

                            match serial_read {
                                Ok(serial_number) => serial_number,
                                Err(error) => break Err(error),
                            }
                        } else {
                            None
                        };

                        if let Some(decision) = pending_assignment_control(control, configured_serial) {
                            break decision;
                        }

                        break Ok(AssignmentSelection {
                            target: TargetSelection::ProgrammingButton(ProgrammingModePolling::default()),
                            serial_number,
                        });
                    }
                    _ => break Err(format!(
                        "{} devices are in physical programming mode; leave exactly one active",
                        found.len()
                    )),
                }
            }
        }
    };

    let disconnect = bus.disconnect().await.map_err(|error| format!("disconnecting IA assignment scan: {error}"));
    let selection = match pending_assignment_control(control, configured_serial) {
        Some(decision) if selection.is_ok() => decision,
        _ => selection,
    }?;
    disconnect?;

    Ok(selection)
}

fn assignment_control_decision(
    command: Option<DownloadControl>,
    configured_serial: Option<[u8; 6]>,
) -> Option<Result<AssignmentSelection, String>> {
    match command {
        Some(DownloadControl::UseSerialNumber) if configured_serial.is_some() => Some(Ok(AssignmentSelection {
            target: TargetSelection::SerialNumber(configured_serial.expect("serial checked above")),
            serial_number: None,
        })),
        Some(DownloadControl::UseSerialNumber) => None,
        Some(DownloadControl::Cancel) | None => Some(Err("individual-address assignment cancelled".to_string())),
    }
}

fn pending_assignment_control(
    control: &mut UnboundedReceiver<DownloadControl>,
    configured_serial: Option<[u8; 6]>,
) -> Option<Result<AssignmentSelection, String>> {
    loop {
        match control.try_recv() {
            Ok(command) => {
                if let Some(decision) = assignment_control_decision(Some(command), configured_serial) {
                    return Some(decision);
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return assignment_control_decision(None, configured_serial);
            }
        }
    }
}

async fn read_programming_mode_serial(
    management: &zweidraehte_client::NetworkManagement<'_>,
    address: IndividualAddress,
    scan_window: Duration,
) -> Result<Option<[u8; 6]>, String> {
    let found = management
        .read_programming_mode_devices(scan_window)
        .await
        .map_err(|error| format!("reading the programming-mode device serial: {error}"))?;
    let matching = found.iter().filter(|device| device.address == address).collect::<Vec<_>>();

    match matching.as_slice() {
        [] => Ok(None),
        [device] if device.serial_number != [0; 6] => Ok(Some(device.serial_number)),
        [device] => {
            log::debug!("programming-mode device {address} reports an all-zero serial number");
            let _ = device;
            Ok(None)
        }
        _ => Err(format!("{} serial-number responses came from programming-mode device {address}", matching.len())),
    }
}

fn programming_batch_selection(affected_only: bool) -> BatchSelection {
    if affected_only {
        return BatchSelection::AllStale;
    }

    // Programming the selected device is deliberately independent from
    // repairing its dependency closure. Any consumers made stale by an IA or
    // security change retain that status for the explicit "affected" action.
    BatchSelection::Selected
}

pub(crate) fn parse_individual_address(value: &str) -> Option<IndividualAddress> {
    value.parse().ok()
}

async fn run_unload(job: UnloadJob, tx: &Sender<DownloadMsg>) -> Result<DownloadOutcome, String> {
    let stage = |text: &str| {
        let _ = tx.send(DownloadMsg::Task(text.to_string(), 0, 0));
    };

    stage("Opening project");
    let store = ProjectStore::open(&job.project_path).map_err(|error| format!("opening project: {error}"))?;

    let selected = [job.device.clone()];
    let mut request =
        ProjectInputRequest::new(&selected, BatchSelection::Selected, CommissioningIntent::Unload(job.scope.mode()));
    request.sources.master_data = job.master_data.as_deref();
    request.sources.keyring_path = job.security.keyring_path();
    let inputs = ProjectOperationInputs::load(store, request, || job.security.load_keyring().map_err(Into::into))
        .map_err(|error| format!("loading project unload inputs: {}", error_message(&error)))?;
    let product_scope = inputs.product_scope().clone();
    let mut programming =
        inputs.into_programming().map_err(|error| format!("resolving project device: {}", error_message(&error)))?;
    if programming.plan().devices().len() != 1 {
        return Err("project unload did not resolve exactly one device".into());
    }
    let mut policy = ProgrammingPolicy::default();
    policy.differential = DifferentialPolicy::Disabled;
    programming.set_policy(policy);
    stage("Connecting to the bus");
    let execution = programming
        .execute(|security| KnxBus::builder().with_security(security).connect(&job.target), &mut WorkerProgress { tx })
        .await;
    Ok(DownloadOutcome {
        project_path: job.project_path,
        summary: format!("Unloaded {} from {}", job.scope.label().to_lowercase(), job.device),
        execution,
        status_scope: product_scope,
    })
}

/// Forwards progress to the UI thread and announces each prepared device.
struct WorkerProgress<'a> {
    tx: &'a Sender<DownloadMsg>,
}

impl CommissioningObserver<ProjectDeviceId> for WorkerProgress<'_> {
    fn event(&mut self, _device: &ProjectDeviceId, event: CommissioningEvent) {
        forward_commissioning_event(event, self.tx);
    }

    fn approve(&mut self, device: &ProjectDeviceId, prepared: &PreparedProgram) -> Result<(), CommissioningVeto> {
        let plan = prepared.plan();
        let label = format!(
            "{device}: {} ({} steps)",
            commissioning_plan_label(plan),
            plan.procedure().map_or(0, |procedure| procedure.steps.len())
        );
        let _ = self.tx.send(DownloadMsg::Task(label, 0, 0));
        Ok(())
    }
}

fn forward_commissioning_event(event: CommissioningEvent, tx: &Sender<DownloadMsg>) {
    let message = match event {
        // `Complete` is the commissioner's return notification, not another
        // device operation. The project owner still has to close the bus and
        // durably compact evidence before the worker can report completion.
        CommissioningEvent::Stage(CommissioningStage::Complete) => return,
        CommissioningEvent::Stage(stage) => DownloadMsg::Task(stage_label(stage).into(), 0, 0),
        CommissioningEvent::TargetDiscovered { address, serial_number } => {
            let serial = serial_number.map(|serial| format!(" ({})", zweidraehte_project::format_serial(&serial)));

            DownloadMsg::Task(format!("Discovered {address}{}", serial.unwrap_or_default()), 0, 0)
        }
        CommissioningEvent::AddressAssigned { previous, current, .. } => {
            DownloadMsg::Task(format!("Assigned individual address {previous} → {current}"), 0, 0)
        }
        CommissioningEvent::ProgrammingSectionsMutated { .. } => return,
        CommissioningEvent::DifferentialFallback(reason) => DownloadMsg::Task(
            format!("Using an undifferenced image for the selected scope: {}", differential_fallback_label(reason)),
            0,
            0,
        ),
        // The worker reports human-facing one-based step numbers, while the
        // TUI stores the number of fully completed preceding steps so it can
        // blend the current step's byte progress into the gauge.
        CommissioningEvent::Step { index, total, description } => {
            DownloadMsg::Task(description, index.saturating_sub(1), total)
        }
        CommissioningEvent::Data { done, total } => DownloadMsg::Data(done, total),
        CommissioningEvent::ProgressText(text) => DownloadMsg::Task(text, 0, 0),
        // A newer engine may report events this worker has no message for.
        _ => return,
    };
    let _ = tx.send(message);
}

fn stage_label(stage: CommissioningStage) -> &'static str {
    match stage {
        CommissioningStage::DiscoveringTarget => "Discovering physical target",
        CommissioningStage::IdentifyingProfile => "Identifying exact programming profile",
        CommissioningStage::CompilingPlan => "Compiling commissioning plan",
        CommissioningStage::ValidatingDifferential => "Validating installed state and deployment stamps",
        CommissioningStage::AssigningAddress => "Assigning individual address",
        CommissioningStage::BootstrappingSecurity => "Bootstrapping secure management",
        CommissioningStage::ConfiguringNetwork => "Configuring network identity and security",
        CommissioningStage::Verifying => "Verifying device state",
        CommissioningStage::Connecting => "Opening device-management session",
        CommissioningStage::Executing => "Executing compiled procedure",
        CommissioningStage::RestoringDeviceState => "Restoring temporary device state",
        CommissioningStage::Disconnecting => "Closing device-management session",
        CommissioningStage::Complete => unreachable!("the completion notification is handled before labeling"),
        _ => "Commissioning device",
    }
}

fn differential_fallback_label(reason: DifferentialFallback) -> &'static str {
    match reason {
        DifferentialFallback::MissingDeploymentHistory => "no verified deployment history exists",
        DifferentialFallback::MissingDeviceStamp => "the exact bound device-stamp set is unavailable",
        DifferentialFallback::StampMismatch => "a device-resident stamp changed",
        DifferentialFallback::ProfileChanged => "the exact programming profile changed",
        DifferentialFallback::UnprovenImageCoverage => "download stamps do not prove previous image coverage",
        DifferentialFallback::NoUsefulDifference => "the differential image would not save traffic",
        _ => "a differential download is unavailable",
    }
}

fn commissioning_plan_label(plan: &CompiledProgram) -> String {
    match plan.intent() {
        CommissioningIntent::AssignAddress => "individual-address commissioning".into(),
        CommissioningIntent::Download(_) => download_plan_label(plan.program_sections(), plan.is_full_program_scope()),
        CommissioningIntent::AssignAddressAndDownload(_) => {
            format!("IA and {}", download_plan_label(plan.program_sections(), plan.is_full_program_scope()))
        }
        CommissioningIntent::Unload(UnloadMode::Application) => "application unload".into(),
        CommissioningIntent::Unload(UnloadMode::AllConfiguration) => "complete configuration unload".into(),
        CommissioningIntent::Unload(_) => "unload".into(),
        _ => "commissioning".into(),
    }
}

fn download_plan_label(sections: Option<ProgramSections>, full_program_scope: bool) -> String {
    let Some(sections) = sections else {
        return "download".into();
    };
    if full_program_scope {
        return "full download".into();
    }

    let mut selected = Vec::new();
    for (section, label) in [
        (ProgramSections::APPLICATION_PROGRAM_1, "application 1"),
        (ProgramSections::APPLICATION_PROGRAM_2, "application 2"),
        (ProgramSections::PARAMETERS, "parameters"),
        (ProgramSections::GROUP_COMMUNICATION, "group communication"),
        (ProgramSections::CONFIGURATION, "configuration"),
    ] {
        if sections.contains(section) {
            selected.push(label);
        }
    }

    format!("{} download", selected.join(" + "))
}

#[cfg(test)]
mod tests {
    use zweidraehte_client::project::BatchSelection;

    use super::{
        DownloadControl, ProgrammingOperation, UnloadScope, assignment_control_decision, parse_individual_address,
        pending_assignment_control, programming_batch_selection,
    };

    #[test]
    fn unload_scopes_select_the_corresponding_factory_reset() {
        assert_eq!(UnloadScope::Application.mode(), zweidraehte_client::commissioning::UnloadMode::Application);
        assert_eq!(UnloadScope::All.mode(), zweidraehte_client::commissioning::UnloadMode::AllConfiguration);
    }

    #[test]
    fn programming_operations_keep_the_ets_order() {
        assert_eq!(ProgrammingOperation::ALL[0], ProgrammingOperation::All);
        assert_eq!(ProgrammingOperation::ALL[1], ProgrammingOperation::Partial);
        assert_eq!(ProgrammingOperation::ALL[2], ProgrammingOperation::IndividualAddress);
        assert_eq!(ProgrammingOperation::ALL[3], ProgrammingOperation::OverwriteIndividualAddress);
        assert_eq!(ProgrammingOperation::ALL[4], ProgrammingOperation::Application);

        assert_eq!(
            ProgrammingOperation::All.intent(),
            zweidraehte_client::commissioning::CommissioningIntent::AssignAddressAndDownload(
                zweidraehte_client::commissioning::DownloadMode::Full
            )
        );
        assert_eq!(
            ProgrammingOperation::Application.intent(),
            zweidraehte_client::commissioning::CommissioningIntent::Download(
                zweidraehte_client::commissioning::DownloadMode::Full
            )
        );
    }

    #[test]
    fn entered_individual_addresses_are_parsed_strictly() {
        assert_eq!(parse_individual_address("1.2.3"), Some(zweidraehte_client::IndividualAddress::new(1, 2, 3)));
        assert_eq!(parse_individual_address("16.2.3"), None);
        assert_eq!(parse_individual_address("1.2.3.4"), None);
    }

    #[test]
    fn cancellation_is_not_lost_behind_an_unavailable_serial_shortcut() {
        let (control, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        control.send(DownloadControl::UseSerialNumber).expect("control receiver remains alive");
        control.send(DownloadControl::Cancel).expect("control receiver remains alive");

        assert!(matches!(pending_assignment_control(&mut receiver, None), Some(Err(_))));
        assert!(matches!(assignment_control_decision(Some(DownloadControl::Cancel), None), Some(Err(_))));
    }

    #[test]
    fn selected_programming_never_expands_to_affected_devices() {
        assert_eq!(programming_batch_selection(false), BatchSelection::Selected);
        assert_eq!(programming_batch_selection(true), BatchSelection::AllStale);
    }
}
