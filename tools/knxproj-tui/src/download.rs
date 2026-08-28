//! Project programming worker for the synchronous terminal UI.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedReceiver;

use zweidraehte_client::cli::{BusTarget, SecurityArgs};
use zweidraehte_client::download::{DownloadEvent, DownloadScope, MaskDb};
use zweidraehte_client::{
    AddressAssignmentMethod, AddressingMode, BatchSelection, IndividualAddress, MaskFamily, MaskVersion,
    ProgrammingEvent, ProgrammingOptions, ProgrammingScope, ProgrammingStage, ProjectPlanRequest, ProjectProgrammer,
    ProjectProgrammingSession, UnloadEvent, UnloadOptions, UnloadStage, load_project_products, pid,
    project_unload_state_events, unload_project_device,
};
use zweidraehte_project::{KeyMaterialSource, ProjectDeviceId, ProjectStore};

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

    const fn scope(self) -> ProgrammingScope {
        match self {
            Self::All | Self::Partial => ProgrammingScope::AddressAndApplication,
            Self::IndividualAddress | Self::OverwriteIndividualAddress => ProgrammingScope::Address,
            Self::Application => ProgrammingScope::Application,
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
}

impl From<UnloadScope> for zweidraehte_client::UnloadScope {
    fn from(value: UnloadScope) -> Self {
        match value {
            UnloadScope::Application => Self::Application,
            UnloadScope::All => Self::All,
        }
    }
}

#[derive(Debug)]
pub enum DownloadMsg {
    Task(String, usize, usize),
    Data(usize, usize),
    AwaitingProgrammingMode { serial_number: Option<[u8; 6]> },
    SerialAssigned([u8; 6]),
    Done(Result<DownloadOutcome, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadControl {
    UseSerialNumber,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectSerialUpdate {
    Set([u8; 6]),
    Clear,
}

#[derive(Debug)]
pub struct DownloadOutcome {
    pub summary: String,
    pub serial_update: Option<ProjectSerialUpdate>,
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
    let mut store = ProjectStore::open(&job.project_path).map_err(|error| format!("opening project: {error}"))?;
    if store.keys().is_none() && store.state().is_none() {
        store.initialize().map_err(|error| format!("initializing project state: {error}"))?;
    }
    if store.keys().is_none() || store.state().is_none() {
        return Err("project keys/state are only partially initialized; use knx-loader recover-state".into());
    }
    let products = load_project_products(&store).map_err(|error| format!("loading project products: {error}"))?;
    let keyring = job.security.load_keyring().map_err(|error| format!("loading ETS keyring: {error}"))?;
    let mut selected: Vec<_> = job.device.iter().cloned().collect();
    let scope = job.operation.scope();

    if job.operation == ProgrammingOperation::Partial && !job.affected_only {
        let statuses = ProjectProgrammer::new()
            .programming_statuses(
                store.authored(),
                store.state(),
                &products,
                Some(store.keys().expect("keys checked above") as &dyn KeyMaterialSource),
                keyring.as_ref(),
            )
            .map_err(|error| format!("calculating programming status: {error}"))?;
        selected.retain(|device| statuses.get(device).is_none_or(|status| !status.is_complete()));
        if selected.is_empty() {
            return Ok(DownloadOutcome {
                summary: "Selected device has no stale project data".into(),
                serial_update: None,
            });
        }
    }

    if job.operation == ProgrammingOperation::OverwriteIndividualAddress && job.affected_only {
        return Err("overwrite IA requires one selected device".into());
    }

    let selection = programming_batch_selection(job.affected_only);
    let mut plan = ProjectProgrammer::new()
        .plan(ProjectPlanRequest {
            project: store.authored(),
            state: store.state(),
            selected: &selected,
            selection,
            products: &products,
            keys: store.keys().expect("keys checked above") as &dyn KeyMaterialSource,
            keyring: keyring.as_ref(),
            scope,
        })
        .map_err(|error| format!("planning project download: {error}"))?;
    if job.operation == ProgrammingOperation::All {
        for device in &mut plan.devices {
            device.download_scope = DownloadScope::Full;
        }
    }
    if plan.devices.is_empty() {
        return Ok(DownloadOutcome { summary: "No affected devices".into(), serial_update: None });
    }

    let configured_serial = |device: &zweidraehte_client::PlannedProjectDevice| {
        let serial = store.authored().devices.get(&device.id).and_then(|device| device.serial);
        serial_assignment_option(serial, device.product.mask_version())
    };
    let address_targets =
        plan.devices.iter().filter(|device| plan.impact.selected.contains(&device.id)).collect::<Vec<_>>();
    let needs_programming_button = address_targets.iter().any(|device| configured_serial(device).is_none());

    let target_label = if job.affected_only { "Affected devices" } else { "Selected device" };
    stage(&format!(
        "{target_label}: {}",
        plan.devices.iter().map(|device| device.id.to_string()).collect::<Vec<_>>().join(", ")
    ));

    let interactive_assignment =
        matches!(job.operation, ProgrammingOperation::IndividualAddress | ProgrammingOperation::All)
            && !job.affected_only
            && address_targets.len() == 1;
    let assignment_target = interactive_assignment.then(|| {
        let device = address_targets[0];
        let mask = device.product.mask_version();
        (device.configuration.identity.desired_address, serial_addressing_capable(mask), configured_serial(device))
    });
    let mut serial_learned_by_programming_mode = None;
    let addressing = match job.operation {
        ProgrammingOperation::OverwriteIndividualAddress => AddressingMode::KnownAddress(
            job.overwrite_current_address.ok_or_else(|| "overwrite IA requires the current address".to_string())?,
        ),
        ProgrammingOperation::IndividualAddress | ProgrammingOperation::All if interactive_assignment => {
            let (_, serial_capable, serial_number) = assignment_target.expect("interactive assignment has a target");
            let selection =
                await_assignment_target(&job.target, serial_capable, serial_number, &mut job.control, tx).await?;
            serial_learned_by_programming_mode = selection.serial_number;
            if selection.addressing == AddressingMode::ProgrammingButton {
                stage("Programming-mode device selected");
            }
            selection.addressing
        }
        ProgrammingOperation::IndividualAddress | ProgrammingOperation::All if needs_programming_button => {
            if job.affected_only || address_targets.len() != 1 {
                return Err(
                    "multiple selected devices require physical programming mode; commission them one at a time".into(),
                );
            }
            AddressingMode::ProgrammingButton
        }
        _ => AddressingMode::Automatic,
    };
    if scope == ProgrammingScope::Application
        && let Some(device) = plan.devices.iter().find(|device| device.key_material.needs_tool_key_generation())
    {
        return Err(format!("{} has no Tool Key; commission its address first", device.id));
    }
    if job.operation != ProgrammingOperation::OverwriteIndividualAddress {
        ProjectProgrammer::new()
            .materialize_tool_keys(&mut plan, store.keys_mut().expect("keys checked above"))
            .map_err(|error| format!("persisting generated tool keys: {error}"))?;
    }

    let mask_db = match &job.master_data {
        Some(path) => MaskDb::from_file(path).map_err(|error| format!("reading master data: {error}"))?,
        None => MaskDb::resolve().map_err(|error| format!("resolving master data: {error} (set KNX_MASTER_DATA)"))?,
    };
    let session = ProjectProgrammingSession::begin(store)
        .map_err(|error| format!("opening project programming session: {error}"))?;
    let security_state = job
        .security
        .prepare_project(session.shared_store(), keyring)
        .map_err(|error| format!("preparing project security: {error}"))?;
    stage("Connecting to the bus");
    let bus =
        job.target.connect_with_security(security_state.store).await.map_err(|error| format!("connecting: {error}"))?;
    let options = ProgrammingOptions { scope, addressing, ..ProgrammingOptions::default() };
    stage("Preflighting affected devices");
    let programmer = ProjectProgrammer::new();
    let prepared = programmer
        .prepare_batch(&bus, &mask_db, plan, options)
        .await
        .map_err(|error| format!("preflighting batch: {error}"))?;
    for device in prepared.devices() {
        let programming = device.programming();
        if let Some(reason) = programming.partial_fallback_reason() {
            stage(&format!("{}: partial unavailable ({reason}); using full", device.id()));
        }
        if let Some(compiled) = programming.compiled() {
            stage(&format!(
                "{}: {} ({} steps)",
                device.id(),
                download_scope_label(compiled.scope()),
                compiled.instructions.len()
            ));
        } else {
            stage(&format!("{}: network configuration only", device.id()));
        }
    }

    let mut programming_button_assignment_succeeded = false;
    let mut serial_update_announced = false;
    let execution = {
        let mut report_progress = |_device: &ProjectDeviceId, event| {
            let message = match event {
                ProgrammingEvent::Stage(stage) => DownloadMsg::Task(stage_label(stage).to_string(), 0, 0),
                ProgrammingEvent::AddressAssigned(report) => {
                    if report.method == AddressAssignmentMethod::ProgrammingButton {
                        programming_button_assignment_succeeded = true;

                        if let Some(serial) = serial_learned_by_programming_mode {
                            let _ = tx.send(DownloadMsg::SerialAssigned(serial));
                            serial_update_announced = true;
                        }
                    }

                    DownloadMsg::Task(format!("Assigned individual address {}", report.current), 0, 0)
                }
                ProgrammingEvent::Download(DownloadEvent::Step { index, total, description }) => {
                    DownloadMsg::Task(description, index, total)
                }
                ProgrammingEvent::Download(DownloadEvent::Data { done, total }) => DownloadMsg::Data(done, total),
                ProgrammingEvent::FallingBackToFullDownload { reason } => {
                    DownloadMsg::Task(format!("Partial load failed ({reason}); falling back to full download"), 0, 0)
                }
            };
            let _ = tx.send(message);
        };

        programmer.execute_batch(&session, &bus, prepared, &mut report_progress).await
    };

    // The programming-mode system scan supplies the serial without relying
    // on the device's old IA. Smaller plain profiles may not implement that
    // optional scan, so retry PID 11 only after the device owns its unique
    // project address.
    if programming_button_assignment_succeeded
        && serial_learned_by_programming_mode.is_none()
        && let Some((desired, true, _)) = assignment_target
    {
        serial_learned_by_programming_mode = read_serial_at_address(&bus, desired).await;
    }
    if !serial_update_announced
        && let Some(serial) = serial_learned_by_programming_mode
        && programming_button_assignment_succeeded
    {
        let _ = tx.send(DownloadMsg::SerialAssigned(serial));
    }

    let disconnect = bus.disconnect().await;
    let finish = session.finish();
    let reports = execution.map_err(|error| error.to_string())?;
    disconnect.map_err(|error| format!("disconnecting: {error}"))?;
    finish.map_err(|error| format!("compacting project state: {error}"))?;
    let completed: Vec<String> = reports.devices.iter().map(|report| report.id.to_string()).collect();
    let verb = match scope {
        ProgrammingScope::Address => "Commissioned",
        ProgrammingScope::Application => "Loaded",
        ProgrammingScope::AddressAndApplication => "Programmed",
    };
    let serial_update = matches!(addressing, AddressingMode::ProgrammingButton)
        .then_some(serial_learned_by_programming_mode)
        .flatten()
        .filter(|serial| *serial != [0; 6])
        .map(ProjectSerialUpdate::Set);

    Ok(DownloadOutcome { summary: format!("{verb} {}", completed.join(", ")), serial_update })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AssignmentSelection {
    addressing: AddressingMode,
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
    let bus = target.connect().await.map_err(|error| format!("connecting for IA assignment: {error}"))?;
    let management = bus.network_management();
    let scan_window = ProgrammingOptions::default().scan_window;

    let _ = tx.send(DownloadMsg::AwaitingProgrammingMode { serial_number: configured_serial });

    let selection = 'waiting: loop {
        tokio::select! {
            biased;

            command = control.recv() => {
                if let Some(decision) = assignment_control_decision(command, configured_serial) {
                    break decision;
                }
            }
            found = management.read_individual_addresses_with_wait(scan_window, Some(PROGRAMMING_MODE_TIMEOUT)) => {
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
                            addressing: AddressingMode::ProgrammingButton,
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
        Some(DownloadControl::UseSerialNumber) if configured_serial.is_some() => {
            Some(Ok(AssignmentSelection { addressing: AddressingMode::Automatic, serial_number: None }))
        }
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

async fn read_serial_at_address(bus: &zweidraehte_client::KnxBus, address: IndividualAddress) -> Option<[u8; 6]> {
    match bus.network_management().property_read(address, 0, pid::SERIAL_NUMBER, 1, 1).await {
        Ok(value) => value.try_into().ok().filter(|serial| *serial != [0; 6]),
        Err(error) => {
            log::debug!("cannot learn the serial number from {address} after IA assignment: {error}");
            None
        }
    }
}

fn serial_addressing_capable(mask: Option<MaskVersion>) -> bool {
    mask.is_some_and(|mask| mask.family() != MaskFamily::Bcu1)
}

fn serial_assignment_option(serial: Option<[u8; 6]>, mask: Option<MaskVersion>) -> Option<[u8; 6]> {
    serial.filter(|serial| *serial != [0; 6] && serial_addressing_capable(mask))
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
    let mut parts = value.split('.');
    let area = parts.next()?.parse::<u8>().ok()?;
    let line = parts.next()?.parse::<u8>().ok()?;
    let device = parts.next()?.parse::<u8>().ok()?;

    (parts.next().is_none() && area <= 15 && line <= 15).then(|| IndividualAddress::new(area, line, device))
}

async fn run_unload(job: UnloadJob, tx: &Sender<DownloadMsg>) -> Result<DownloadOutcome, String> {
    let stage = |text: &str| {
        let _ = tx.send(DownloadMsg::Task(text.to_string(), 0, 0));
    };

    stage("Opening project");
    let store = ProjectStore::open(&job.project_path).map_err(|error| format!("opening project: {error}"))?;
    if store.keys().is_none() || store.state().is_none() {
        return Err("project keys and state are not initialized".into());
    }

    let products = load_project_products(&store).map_err(|error| format!("loading project products: {error}"))?;
    let keyring = job.security.load_keyring().map_err(|error| format!("loading ETS keyring: {error}"))?;
    let selected = [job.device.clone()];
    let plan = ProjectProgrammer::new()
        .plan(ProjectPlanRequest {
            project: store.authored(),
            state: store.state(),
            selected: &selected,
            selection: BatchSelection::Selected,
            products: &products,
            keys: store.keys().expect("keys checked above") as &dyn KeyMaterialSource,
            keyring: keyring.as_ref(),
            scope: ProgrammingScope::AddressAndApplication,
        })
        .map_err(|error| format!("resolving project device: {error}"))?;
    let planned = plan.devices.into_iter().next().ok_or_else(|| "project device was not planned".to_string())?;

    let mask_db = match &job.master_data {
        Some(path) => MaskDb::from_file(path).map_err(|error| format!("reading master data: {error}"))?,
        None => MaskDb::resolve().map_err(|error| format!("resolving master data: {error} (set KNX_MASTER_DATA)"))?,
    };

    let session = ProjectProgrammingSession::begin(store)
        .map_err(|error| format!("opening project programming session: {error}"))?;
    let security_state = job
        .security
        .prepare_project(session.shared_store(), keyring)
        .map_err(|error| format!("preparing project security: {error}"))?;

    stage("Connecting to the bus");
    let bus =
        job.target.connect_with_security(security_state.store).await.map_err(|error| format!("connecting: {error}"))?;

    let mut report_progress = |event| {
        let message = match event {
            UnloadEvent::Stage(stage) => DownloadMsg::Task(unload_stage_label(stage).into(), 0, 0),
            UnloadEvent::Download(DownloadEvent::Step { index, total, description }) => {
                DownloadMsg::Task(description, index, total)
            }
            UnloadEvent::Download(DownloadEvent::Data { done, total }) => DownloadMsg::Data(done, total),
        };
        let _ = tx.send(message);
    };
    let unload_scope = job.scope.into();
    let action = unload_project_device(
        &bus,
        &mask_db,
        &planned,
        UnloadOptions { scope: unload_scope, ..UnloadOptions::default() },
        &mut report_progress,
    )
    .await;

    let disconnect = bus.disconnect().await.map_err(|error| format!("disconnecting: {error}"));
    let events = project_unload_state_events(&planned, unload_scope, &action);
    let record: Result<(), String> = (|| {
        let shared_store = session.shared_store();
        let mut store = shared_store.lock().map_err(|_| "project-store lock is poisoned".to_string())?;

        for event in events {
            store.record(event).map_err(|error| format!("recording unloaded state: {error}"))?;
        }

        Ok(())
    })();
    let finish = session.finish().map_err(|error| format!("compacting project state: {error}"));

    action.map_err(|error| error.to_string())?;
    disconnect?;
    record?;
    finish?;

    let serial_update = (job.scope == UnloadScope::All).then_some(ProjectSerialUpdate::Clear);
    Ok(DownloadOutcome {
        summary: format!("Unloaded {} from {}", job.scope.label().to_lowercase(), job.device),
        serial_update,
    })
}

fn unload_stage_label(stage: UnloadStage) -> &'static str {
    match stage {
        UnloadStage::SelectingManagementAccess => "Selecting management access",
        UnloadStage::ReadingDescriptor => "Reading device descriptor",
        UnloadStage::UnloadingApplication => "Unloading application",
        UnloadStage::FactoryResettingApplication => "Factory-resetting application configuration",
        UnloadStage::FactoryResettingDevice => "Factory-resetting device",
        UnloadStage::ResettingIndividualAddress => "Resetting individual address",
        UnloadStage::WaitingForRestart => "Waiting for restart",
        UnloadStage::Verifying => "Verifying factory reset",
    }
}

fn download_scope_label(scope: DownloadScope) -> &'static str {
    match scope {
        DownloadScope::Full => "full download",
        DownloadScope::Parameters => "parameter-only download",
        DownloadScope::GroupCommunication => "group-communication download",
        DownloadScope::ParametersAndGroupCommunication => "parameter and group-communication download",
    }
}

fn stage_label(stage: ProgrammingStage) -> &'static str {
    match stage {
        ProgrammingStage::PersistingToolKey => "Persisting generated tool key",
        ProgrammingStage::DiscoveringDevice => "Discovering device",
        ProgrammingStage::ReadingDescriptor => "Reading device descriptor",
        ProgrammingStage::Compiling => "Compiling download",
        ProgrammingStage::AssigningAddress => "Assigning individual address",
        ProgrammingStage::SelectingManagementAccess => "Selecting management access",
        ProgrammingStage::EnablingSecurityMode => "Enabling Security Mode",
        ProgrammingStage::InstallingToolKey => "Installing tool key",
        ProgrammingStage::RestartingSecurityBootstrap => "Restarting after security bootstrap",
        ProgrammingStage::SettingDeviceSequence => "Setting device sequence number",
        ProgrammingStage::Downloading => "Downloading",
        ProgrammingStage::RestartingDevice => "Restarting device",
        ProgrammingStage::WaitingForRestart => "Waiting for restart",
        ProgrammingStage::Verifying => "Verifying",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DownloadControl, ProgrammingOperation, UnloadScope, assignment_control_decision, parse_individual_address,
        pending_assignment_control, programming_batch_selection, serial_assignment_option,
    };

    #[test]
    fn unload_scopes_select_the_corresponding_factory_reset() {
        assert_eq!(
            zweidraehte_client::UnloadScope::from(UnloadScope::Application),
            zweidraehte_client::UnloadScope::Application
        );
        assert_eq!(zweidraehte_client::UnloadScope::from(UnloadScope::All), zweidraehte_client::UnloadScope::All);
    }

    #[test]
    fn programming_operations_keep_the_ets_order() {
        assert_eq!(ProgrammingOperation::ALL[0], ProgrammingOperation::All);
        assert_eq!(ProgrammingOperation::ALL[1], ProgrammingOperation::Partial);
        assert_eq!(ProgrammingOperation::ALL[2], ProgrammingOperation::IndividualAddress);
        assert_eq!(ProgrammingOperation::ALL[3], ProgrammingOperation::OverwriteIndividualAddress);
        assert_eq!(ProgrammingOperation::ALL[4], ProgrammingOperation::Application);
    }

    #[test]
    fn entered_individual_addresses_are_parsed_strictly() {
        assert_eq!(parse_individual_address("1.2.3"), Some(zweidraehte_client::IndividualAddress::new(1, 2, 3)));
        assert_eq!(parse_individual_address("16.2.3"), None);
        assert_eq!(parse_individual_address("1.2.3.4"), None);
    }

    #[test]
    fn serial_shortcut_requires_a_real_serial_and_a_capable_mask() {
        let serial = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

        assert_eq!(
            serial_assignment_option(Some(serial), Some(zweidraehte_client::MaskVersion::Bcu2Tp1)),
            Some(serial)
        );
        assert_eq!(
            serial_assignment_option(Some(serial), Some(zweidraehte_client::MaskVersion::System7Tp1)),
            Some(serial)
        );
        assert_eq!(
            serial_assignment_option(Some(serial), Some(zweidraehte_client::MaskVersion::SystemBTp1)),
            Some(serial)
        );

        assert_eq!(serial_assignment_option(Some(serial), Some(zweidraehte_client::MaskVersion::Bcu1Tp1)), None);
        assert_eq!(serial_assignment_option(Some([0; 6]), Some(zweidraehte_client::MaskVersion::Bcu2Tp1)), None);
        assert_eq!(serial_assignment_option(None, Some(zweidraehte_client::MaskVersion::Bcu2Tp1)), None);
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
        assert_eq!(programming_batch_selection(false), zweidraehte_client::BatchSelection::Selected);
        assert_eq!(programming_batch_selection(true), zweidraehte_client::BatchSelection::AllStale);
    }
}
