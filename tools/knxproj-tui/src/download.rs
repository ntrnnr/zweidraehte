//! Project programming worker for the synchronous terminal UI.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use zweidraehte_client::cli::{BusTarget, SecurityArgs};
use zweidraehte_client::download::{DownloadEvent, MaskDb, ProductData};
use zweidraehte_client::{
    AddressingMode, BatchSelection, DeviceProgrammer, ProgrammingEvent, ProgrammingOptions, ProgrammingRequest,
    ProgrammingScope, ProgrammingStage, ProjectProduct, ProjectProgrammer,
};
use zweidraehte_knxprod::runtime::KnxprodArchive;
use zweidraehte_knxprod::runtime::parser::parse_application_program_from_file;
use zweidraehte_project::{KeyMaterialSource, ProjectDeviceId, ProjectEvent, ProjectStore};

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
    let products = load_products(&store)?;
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
        .plan_with_scope(
            store.authored(),
            store.state(),
            &selected,
            selection,
            &products,
            store.keys().expect("keys checked above") as &dyn KeyMaterialSource,
            keyring.as_ref(),
            job.scope,
        )
        .map_err(|error| format!("planning project download: {error}"))?;
    if plan.devices.is_empty() {
        return Ok("No affected devices".into());
    }
    stage(&format!(
        "Affected devices: {}",
        plan.devices.iter().map(|device| device.id.to_string()).collect::<Vec<_>>().join(", ")
    ));
    let lock = store.acquire_lock().map_err(|error| format!("locking project: {error}"))?;
    store.begin_mutation(&lock).map_err(|error| format!("opening project journal: {error}"))?;
    if job.scope == ProgrammingScope::Application
        && let Some(device) = plan.devices.iter().find(|device| device.key_material.needs_tool_key_generation)
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
    let shared = Arc::new(Mutex::new(store));
    let prepared = job
        .security
        .prepare_project(Arc::clone(&shared), keyring)
        .map_err(|error| format!("preparing project security: {error}"))?;
    stage("Connecting to the bus");
    let bus = job.target.connect_with_security(prepared.store).await.map_err(|error| format!("connecting: {error}"))?;
    let options = ProgrammingOptions {
        scope: job.scope,
        addressing: if job.program_ia { AddressingMode::ProgrammingButton } else { AddressingMode::Automatic },
        ..ProgrammingOptions::default()
    };
    stage("Preflighting affected devices");
    ProjectProgrammer::new()
        .preflight_batch(&bus, &mask_db, &mut plan, options.clone())
        .await
        .map_err(|error| format!("preflighting batch: {error}"))?;

    let mut completed = Vec::new();
    for planned in &plan.devices {
        let sink_tx = tx.clone();
        let report = DeviceProgrammer::new()
            .program_with_progress(
                &bus,
                ProgrammingRequest {
                    mask_db: &mask_db,
                    product: &planned.product,
                    configuration: &planned.configuration,
                    key_material: planned.key_material.clone(),
                    options: options.clone(),
                },
                None,
                Box::new(move |event| {
                    let message = match event {
                        ProgrammingEvent::Stage(stage) => DownloadMsg::Task(stage_label(stage).to_string(), 0, 0),
                        ProgrammingEvent::Download(DownloadEvent::Step { index, total, description }) => {
                            DownloadMsg::Task(description, index, total)
                        }
                        ProgrammingEvent::Download(DownloadEvent::Data { done, total }) => {
                            DownloadMsg::Data(done, total)
                        }
                    };
                    let _ = sink_tx.send(message);
                }),
            )
            .await;
        match report {
            Ok(report) => {
                if report.application_downloaded {
                    record_success(&shared, planned)?;
                }
                completed.push(planned.id.to_string());
            }
            Err(error) => {
                let devices = plan.devices.iter().map(|device| device.id.0.clone()).collect();
                shared
                    .lock()
                    .map_err(|_| "project-store lock is poisoned".to_string())?
                    .record(ProjectEvent::MarkInconsistent { devices })
                    .map_err(|state| format!("recording partial batch failure: {state}"))?;
                let _ = bus.disconnect().await;
                let operation = match job.scope {
                    ProgrammingScope::Address => "commissioning",
                    ProgrammingScope::Application => "loading",
                    ProgrammingScope::AddressAndApplication => "programming",
                };
                return Err(format!(
                    "{operation} {}: {error}; completed devices: {}",
                    planned.id,
                    completed.join(", ")
                ));
            }
        }
    }
    bus.disconnect().await.map_err(|error| format!("disconnecting: {error}"))?;
    shared
        .lock()
        .map_err(|_| "project-store lock is poisoned".to_string())?
        .compact()
        .map_err(|error| format!("compacting project state: {error}"))?;
    let verb = match job.scope {
        ProgrammingScope::Address => "Commissioned",
        ProgrammingScope::Application => "Loaded",
        ProgrammingScope::AddressAndApplication => "Programmed",
    };
    Ok(format!("{verb} {}", completed.join(", ")))
}

fn record_success(
    store: &Arc<Mutex<ProjectStore>>,
    planned: &zweidraehte_client::PlannedProjectDevice,
) -> Result<(), String> {
    let mut store = store.lock().map_err(|_| "project-store lock is poisoned".to_string())?;
    store
        .record(ProjectEvent::RecordDeployment {
            device: planned.id.0.clone(),
            fingerprints: planned.fingerprints.clone(),
        })
        .map_err(|error| format!("recording deployment: {error}"))?;
    for metadata in &planned.key_material.provenance {
        if let zweidraehte_project::KeyScope::Group(net) = &metadata.id.scope {
            let fingerprint = metadata.fingerprint.iter().map(|byte| format!("{byte:02x}")).collect();
            store
                .record(ProjectEvent::RecordGroupKey { net: net.clone(), fingerprint })
                .map_err(|error| format!("recording group-key deployment: {error}"))?;
        }
    }
    Ok(())
}

fn load_products(store: &ProjectStore) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>, String> {
    store
        .authored()
        .devices
        .iter()
        .map(|(id, device)| {
            let path = store
                .authored()
                .resolve_product_path(device)
                .ok_or_else(|| format!("cannot resolve product path for `{id}`"))?;
            let program = load_program(&path)?;
            let product =
                ProductData::from_program(&program).map_err(|error| format!("{}: {error}", path.display()))?;
            Ok((id.clone(), ProjectProduct { program, product }))
        })
        .collect()
}

pub(crate) fn load_program(path: &Path) -> Result<zweidraehte_knxprod::schema::ApplicationProgram, String> {
    let knx = if path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod")) {
        let archive = KnxprodArchive::open(path).map_err(|error| format!("opening {}: {error}", path.display()))?;
        match archive.application_program_count() {
            1 => archive
                .parse_sole_application_program()
                .expect("one program has a sole parser")
                .map_err(|error| format!("parsing {}: {error}", path.display()))?,
            count => {
                return Err(format!(
                    "{} contains {count} application programs; exactly one is required",
                    path.display()
                ));
            }
        }
    } else {
        parse_application_program_from_file(path).map_err(|error| format!("parsing {}: {error}", path.display()))?
    };
    let mut programs = knx.manufacturer_data.manufacturer.application_programs.programs;
    match programs.len() {
        1 => Ok(programs.remove(0)),
        count => Err(format!("{} defines {count} application programs; exactly one is required", path.display())),
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
