//! Project programming worker for the synchronous terminal UI.

use std::path::PathBuf;
use std::sync::mpsc::Sender;

use zweidraehte_client::cli::{BusTarget, SecurityArgs};
use zweidraehte_client::download::{DownloadEvent, DownloadScope, MaskDb};
use zweidraehte_client::{
    AddressingMode, BatchSelection, ProgrammingEvent, ProgrammingOptions, ProgrammingScope, ProgrammingStage,
    ProjectPlanRequest, ProjectProgrammer, ProjectProgrammingSession, load_project_products,
};
use zweidraehte_project::{KeyMaterialSource, ProjectDeviceId, ProjectStore};

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
    pub program_ia: bool,
    pub scope: ProgrammingScope,
    /// Bypass differential selection and execute the complete application flow.
    pub force_full: bool,
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
    let selected: Vec<_> = job.device.iter().cloned().collect();
    let selection = if job.affected_only {
        if job.scope == ProgrammingScope::Address { BatchSelection::All } else { BatchSelection::AllStale }
    } else {
        BatchSelection::Selected {
            include_affected: job.include_affected && job.scope.includes_application(),
            force_single: job.scope == ProgrammingScope::Address,
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
            scope: job.scope,
        })
        .map_err(|error| format!("planning project download: {error}"))?;
    if job.force_full {
        for device in &mut plan.devices {
            device.download_scope = DownloadScope::Full;
        }
    }
    if plan.devices.is_empty() {
        return Ok("No affected devices".into());
    }
    stage(&format!(
        "Affected devices: {}",
        plan.devices.iter().map(|device| device.id.to_string()).collect::<Vec<_>>().join(", ")
    ));
    if job.scope == ProgrammingScope::Application
        && let Some(device) = plan.devices.iter().find(|device| device.key_material.needs_tool_key_generation())
    {
        return Err(format!("{} has no Tool Key; commission its address first", device.id));
    }
    ProjectProgrammer::new()
        .materialize_tool_keys(&mut plan, store.keys_mut().expect("keys checked above"))
        .map_err(|error| format!("persisting generated tool keys: {error}"))?;

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
    let options = ProgrammingOptions {
        scope: job.scope,
        addressing: if job.program_ia { AddressingMode::ProgrammingButton } else { AddressingMode::Automatic },
        ..ProgrammingOptions::default()
    };
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
    let verb = match job.scope {
        ProgrammingScope::Address => "Commissioned",
        ProgrammingScope::Application => "Loaded",
        ProgrammingScope::AddressAndApplication => "Programmed",
    };
    Ok(format!("{verb} {}", completed.join(", ")))
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
