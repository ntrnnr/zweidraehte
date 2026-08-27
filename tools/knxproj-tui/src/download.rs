//! Project programming worker for the synchronous terminal UI.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use zweidraehte_client::cli::{BusTarget, SecurityArgs};
use zweidraehte_client::download::{
    DeviceImage, DownloadEvent, DownloadModel, DownloadScope, MaskDb, ProcedureKind, assemble, load_control_path,
    select_download_mask,
};
use zweidraehte_client::security::ResolvedKeyMaterial;
use zweidraehte_client::{
    AddressingMode, BatchSelection, DeviceConnection, EraseCode, IndividualAddress, ManagementAccess, MaskFamily,
    MaskVersion, ProgrammingEvent, ProgrammingOptions, ProgrammingScope, ProgrammingStage, ProjectPlanRequest,
    ProjectProgrammer, ProjectProgrammingSession, connect_management, load_project_products,
};
use zweidraehte_project::{KeyMaterialSource, ProjectDeviceId, ProjectEvent, ProjectStore, format_serial};

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

    const fn erase_code(self) -> EraseCode {
        match self {
            Self::Application => EraseCode::FactoryResetKeepIA,
            Self::All => EraseCode::FactoryReset,
        }
    }
}

#[derive(Debug)]
pub enum DownloadMsg {
    Task(String, usize, usize),
    Data(usize, usize),
    Done(Result<String, String>),
}

pub struct DownloadJob {
    pub target: BusTarget,
    pub project_path: PathBuf,
    pub device: Option<ProjectDeviceId>,
    /// Select every device whose desired deployment fingerprint changed.
    pub affected_only: bool,
    pub master_data: Option<PathBuf>,
    pub security: SecurityArgs,
    pub include_affected: bool,
    pub operation: ProgrammingOperation,
    pub overwrite_current_address: Option<IndividualAddress>,
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

async fn run(job: DownloadJob, tx: &Sender<DownloadMsg>) -> Result<String, String> {
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
            return Ok("Selected device has no stale project data".into());
        }
    }

    if job.operation == ProgrammingOperation::OverwriteIndividualAddress && job.affected_only {
        return Err("overwrite IA requires one selected device".into());
    }

    let selection = if job.affected_only {
        BatchSelection::AllStale
    } else {
        BatchSelection::Selected {
            include_affected: job.include_affected && scope.includes_application(),
            force_single: !scope.includes_application(),
        }
    };
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
        return Ok("No affected devices".into());
    }

    let needs_programming_button = plan.devices.iter().any(|device| {
        device.key_material.serial_number().is_none()
            || device.product.mask_version().is_some_and(|mask| mask.family() == MaskFamily::Bcu1)
    });
    let addressing = match job.operation {
        ProgrammingOperation::OverwriteIndividualAddress => AddressingMode::KnownAddress(
            job.overwrite_current_address.ok_or_else(|| "overwrite IA requires the current address".to_string())?,
        ),
        ProgrammingOperation::IndividualAddress | ProgrammingOperation::All if needs_programming_button => {
            if job.affected_only || plan.devices.len() != 1 {
                return Err(
                    "one or more affected devices require physical programming mode; program those devices individually"
                        .into(),
                );
            }
            AddressingMode::ProgrammingButton
        }
        _ => AddressingMode::Automatic,
    };

    stage(&format!(
        "Affected devices: {}",
        plan.devices.iter().map(|device| device.id.to_string()).collect::<Vec<_>>().join(", ")
    ));
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

    let mut report_progress = |_device: &ProjectDeviceId, event| {
        let message = match event {
            ProgrammingEvent::Stage(stage) => DownloadMsg::Task(stage_label(stage).to_string(), 0, 0),
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
    let execution = programmer.execute_batch(&session, &bus, prepared, &mut report_progress).await;
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
    Ok(format!("{verb} {}", completed.join(", ")))
}

pub(crate) fn parse_individual_address(value: &str) -> Option<IndividualAddress> {
    let mut parts = value.split('.');
    let area = parts.next()?.parse::<u8>().ok()?;
    let line = parts.next()?.parse::<u8>().ok()?;
    let device = parts.next()?.parse::<u8>().ok()?;

    (parts.next().is_none() && area <= 15 && line <= 15).then(|| IndividualAddress::new(area, line, device))
}

async fn run_unload(job: UnloadJob, tx: &Sender<DownloadMsg>) -> Result<String, String> {
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
            selection: BatchSelection::Selected { include_affected: false, force_single: true },
            products: &products,
            keys: store.keys().expect("keys checked above") as &dyn KeyMaterialSource,
            keyring: keyring.as_ref(),
            scope: ProgrammingScope::AddressAndApplication,
        })
        .map_err(|error| format!("resolving project device: {error}"))?;
    let planned = plan.devices.into_iter().next().ok_or_else(|| "project device was not planned".to_string())?;

    let session = ProjectProgrammingSession::begin(store)
        .map_err(|error| format!("opening project programming session: {error}"))?;
    let security_state = job
        .security
        .prepare_project(session.shared_store(), keyring)
        .map_err(|error| format!("preparing project security: {error}"))?;

    stage("Connecting to the bus");
    let bus =
        job.target.connect_with_security(security_state.store).await.map_err(|error| format!("connecting: {error}"))?;
    let desired = planned.configuration.identity.desired_address;
    let current = locate_current_address(&bus, &planned.key_material, desired).await?;

    let mut changed = false;
    let action = async {
        stage("Selecting management access");
        let (mut connection, access) = connect_management(&bus, current, &planned.key_material, true)
            .await
            .map_err(|error| format!("selecting management access: {error}"))?;

        let descriptor = connection.device_descriptor_read(0).await.map_err(|error| format!("reading DD0: {error}"))?;
        let [high, low] = descriptor.as_slice() else {
            let _ = connection.close().await;
            return Err("DD0 did not return two octets".into());
        };

        let device_mask = MaskVersion::from(u16::from_be_bytes([*high, *low]));

        if device_mask.family() == MaskFamily::Bcu1 {
            if job.scope == UnloadScope::All && planned.key_material.serial_number().is_none() {
                // TODO: Add a programming-mode IA reset for serial-less BCU1
                // devices. A broadcast write without that physical opt-in is
                // unsafe on a populated bus.
                let _ = connection.close().await;
                return Err(
                    "the BCU1 device has no KNX serial number; refusing a broadcast individual-address reset that could affect other devices"
                        .into(),
                );
            }

            let mask_db = match &job.master_data {
                Some(path) => MaskDb::from_file(path).map_err(|error| format!("reading master data: {error}"))?,
                None => {
                    MaskDb::resolve().map_err(|error| format!("resolving master data: {error} (set KNX_MASTER_DATA)"))?
                }
            };
            let product_mask =
                planned.product.mask_version().ok_or_else(|| "product has no mask version".to_string())?;
            let mask = select_download_mask(&mask_db, product_mask, device_mask)
                .map_err(|error| format!("selecting the unload procedure: {error}"))?;
            let max_apdu = planned.configuration.max_apdu.unwrap_or(bus.max_apdu()).min(bus.max_apdu()).max(15);

            unload_legacy_application(&mut connection, &planned, &mask, max_apdu, tx, &mut changed).await?;

            connection.close().await.map_err(|error| format!("closing management connection: {error}"))?;

            if job.scope == UnloadScope::All {
                reset_legacy_individual_address(&bus, current, access, &planned.key_material, tx, &mut changed).await?;
            }
        } else {
            let process_time = factory_reset(&mut connection, job.scope, tx, &mut changed).await?;
            let _ = connection.close().await;

            tokio::time::sleep(process_time.max(ProgrammingOptions::default().restart_delay)).await;

            if job.scope == UnloadScope::All {
                finish_factory_reset(&bus, current, &planned.key_material).await?;
            }
        }

        Ok::<(), String>(())
    }
    .await;

    let disconnect = bus.disconnect().await.map_err(|error| format!("disconnecting: {error}"));
    let event = if action.is_ok() {
        Some(ProjectEvent::RecordUnload {
            device: job.device.to_string(),
            preserve_network_configuration: job.scope == UnloadScope::Application,
        })
    } else if changed {
        Some(ProjectEvent::MarkInconsistent { devices: vec![job.device.to_string()] })
    } else {
        None
    };
    let record = match event {
        Some(event) => session
            .shared_store()
            .lock()
            .map_err(|_| "project-store lock is poisoned".to_string())?
            .record(event)
            .map_err(|error| format!("recording unloaded state: {error}")),
        None => Ok(()),
    };
    let finish = session.finish().map_err(|error| format!("compacting project state: {error}"));

    action?;
    disconnect?;
    record?;
    finish?;

    Ok(format!("Unloaded {} from {}", job.scope.label().to_lowercase(), job.device))
}

async fn locate_current_address(
    bus: &zweidraehte_client::KnxBus,
    keys: &ResolvedKeyMaterial,
    desired: IndividualAddress,
) -> Result<IndividualAddress, String> {
    let Some(serial) = keys.serial_number() else { return Ok(desired) };
    let found = bus
        .network_management()
        .read_individual_addresses_by_serial(&serial, Duration::from_secs(2))
        .await
        .map_err(|error| format!("locating the device by serial: {error}"))?;

    match found.as_slice() {
        [address] => Ok(*address),
        [] => Ok(desired),
        _ => Err(format!("{} devices answered for serial {}", found.len(), format_serial(&serial))),
    }
}

async fn unload_legacy_application(
    connection: &mut DeviceConnection,
    planned: &zweidraehte_client::PlannedProjectDevice,
    mask: &zweidraehte_client::download::MaskData<'_>,
    max_apdu: u16,
    tx: &Sender<DownloadMsg>,
    changed: &mut bool,
) -> Result<(), String> {
    let instructions = assemble(mask, &planned.product, ProcedureKind::UnloadAll)
        .map_err(|error| format!("assembling the unload procedure: {error}"))?;
    let model = DownloadModel::for_management_model(mask.management_model());
    let path = load_control_path(mask).map_err(|error| format!("selecting the unload path: {error}"))?;

    let mut report_progress = |event| {
        let message = match event {
            DownloadEvent::Step { index, total, description } => DownloadMsg::Task(description, index, total),
            DownloadEvent::Data { done, total } => DownloadMsg::Data(done, total),
        };
        let _ = tx.send(message);
    };
    let mut downloader = zweidraehte_client::download::Downloader::with_path(connection, path, max_apdu)
        .with_progress(&mut report_progress);
    if let Some(model) = model {
        if !model.authorize_on_connect {
            downloader = downloader.without_authorize();
        }
        if model.diff_writes {
            downloader = downloader.with_diffed_writes();
        }
    }

    // Once the mask procedure starts, a failure can still leave some load
    // machines unloaded. Persist that uncertainty instead of claiming the
    // project still describes the device.
    *changed = true;
    let result = downloader
        .run(&instructions, &DeviceImage::new())
        .await
        .map_err(|error| format!("executing Unload-all: {error}"));
    drop(downloader);

    result?;
    Ok(())
}

async fn factory_reset(
    connection: &mut DeviceConnection,
    scope: UnloadScope,
    tx: &Sender<DownloadMsg>,
    changed: &mut bool,
) -> Result<Duration, String> {
    let description = match scope {
        UnloadScope::Application => "Factory-resetting application configuration",
        UnloadScope::All => "Factory-resetting device",
    };
    let _ = tx.send(DownloadMsg::Task(description.into(), 0, 0));

    // HawkNET's `UnloadDeviceTask` uses these two master-reset codes when
    // confirmed restart is available. 07h deliberately preserves IA,
    // Security Mode and Tool Key; 02h also resets the IA, disables Security
    // Mode and makes the FDSK the active tool key again.
    *changed = true;
    let restart = connection
        .master_reset(scope.erase_code(), 0)
        .await
        .map_err(|error| format!("factory-resetting the device: {error}"))?;

    Ok(restart.process_time)
}

async fn reset_legacy_individual_address(
    bus: &zweidraehte_client::KnxBus,
    current: IndividualAddress,
    access: ManagementAccess,
    keys: &ResolvedKeyMaterial,
    tx: &Sender<DownloadMsg>,
    changed: &mut bool,
) -> Result<(), String> {
    let serial = keys.serial_number().expect("individual-address unload requires a serial number");
    let default_address = IndividualAddress::from([0xFF, 0xFF]);
    let _ = tx.send(DownloadMsg::Task("Resetting individual address".into(), 0, 0));

    // 03/05/03 §3.5.4 places this serial-addressed write after the
    // application procedure. It deliberately is not `ResetIA`: secure
    // profiles are forbidden from implementing that master-reset code.
    *changed = true;
    match access {
        ManagementAccess::Plain => bus
            .network_management()
            .write_individual_address_by_serial(&serial, default_address)
            .await
            .map_err(|error| format!("resetting individual address: {error}"))?,
        ManagementAccess::ToolKey => {
            let key =
                keys.tool_key().copied().ok_or_else(|| "Tool-Key management access has no Tool Key".to_string())?;
            bus.network_management()
                .write_individual_address_by_serial_secure(&serial, current, default_address, key)
                .await
                .map_err(|error| format!("securely resetting individual address: {error}"))?;
        }
        ManagementAccess::Fdsk => {
            let key = keys.fdsk().copied().ok_or_else(|| "FDSK management access has no FDSK".to_string())?;
            bus.network_management()
                .write_individual_address_by_serial_secure(&serial, current, default_address, key)
                .await
                .map_err(|error| format!("securely resetting individual address: {error}"))?;
        }
    }

    let found = bus
        .network_management()
        .read_individual_addresses_by_serial(&serial, Duration::from_secs(2))
        .await
        .map_err(|error| format!("verifying individual-address reset: {error}"))?;
    match found.as_slice() {
        [address] if *address == default_address => {}
        [address] => return Err(format!("individual-address reset returned {address}, expected 15.15.255")),
        [] => return Err("device did not answer after individual-address reset".into()),
        _ => return Err(format!("{} devices answered for serial {}", found.len(), format_serial(&serial))),
    }

    bus.remove_device_security(current)
        .await
        .map_err(|error| format!("removing the old address security entry: {error}"))?;
    Ok(())
}

async fn finish_factory_reset(
    bus: &zweidraehte_client::KnxBus,
    current: IndividualAddress,
    keys: &ResolvedKeyMaterial,
) -> Result<(), String> {
    if let Some(serial) = keys.serial_number() {
        let default_address = IndividualAddress::from([0xFF, 0xFF]);
        let found = bus
            .network_management()
            .read_individual_addresses_by_serial(&serial, Duration::from_secs(2))
            .await
            .map_err(|error| format!("verifying factory reset: {error}"))?;

        match found.as_slice() {
            [address] if *address == default_address => {}
            [address] => return Err(format!("factory reset returned {address}, expected 15.15.255")),
            [] => return Err("device did not answer after factory reset".into()),
            _ => return Err(format!("{} devices answered for serial {}", found.len(), format_serial(&serial))),
        }
    }

    // The device is now in factory state: Security Mode is off and the FDSK
    // is active. Retaining the commissioned address entry would make the next
    // client connection try its obsolete Tool Key.
    bus.remove_device_security(current)
        .await
        .map_err(|error| format!("removing the old address security entry: {error}"))?;

    Ok(())
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
    use super::{ProgrammingOperation, UnloadScope, parse_individual_address};

    #[test]
    fn unload_scopes_select_the_corresponding_factory_reset() {
        assert_eq!(UnloadScope::Application.erase_code(), zweidraehte_client::EraseCode::FactoryResetKeepIA);
        assert_eq!(UnloadScope::All.erase_code(), zweidraehte_client::EraseCode::FactoryReset);
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
}
