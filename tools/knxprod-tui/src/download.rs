//! Programming the opened device from inside the TUI.
//!
//! The TUI is a synchronous crossterm loop and the client is tokio,
//! so the download runs on its own thread with a single-threaded
//! runtime, reporting through an `std::sync::mpsc` channel the UI
//! drains every tick. The flow mirrors `knx-loader load`: resolve the
//! session's configuration and security material through the same
//! [`DeviceProgrammer`](zweidraehte_client::DeviceProgrammer) used by
//! `knx-loader`.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use zweidraehte_client::cli::{BusTarget, SecurityArgs};
use zweidraehte_client::download::{DownloadEvent, MaskDb, ProductData, resolve_mods};
use zweidraehte_client::security::{ModsFileKeyStore, resolve_key_material};
use zweidraehte_client::{
    DeviceProgrammer, ProgrammingEvent, ProgrammingOptions, ProgrammingRequest, ProgrammingStage,
};
use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::mods::{DeviceMods, apply_mods};
use zweidraehte_knxprod::schema::ApplicationProgram;

/// What the worker reports to the UI.
#[derive(Debug)]
pub enum DownloadMsg {
    /// A new step began: label, 0-based index, step count.
    Task(String, usize, usize),
    /// Byte progress inside the current step.
    Data(usize, usize),
    /// The run finished; a summary or the failure.
    Done(Result<String, String>),
    /// A generated tool key was persisted; keep the complete in-memory mods
    /// state aligned so a later export cannot erase it.
    ModsUpdated(DeviceMods),
}

/// Everything the worker thread needs, all owned.
pub struct DownloadJob {
    pub target: BusTarget,
    /// The session's configuration, exported from the device.
    pub mods: DeviceMods,
    pub mods_path: PathBuf,
    /// The pristine program (language-independent facts only matter).
    pub program: ApplicationProgram,
    /// Explicit master data path; falls back to `MaskDb::resolve()`.
    pub master_data: Option<PathBuf>,
    pub security: SecurityArgs,
}

/// Spawn the worker; progress arrives on `tx`.
pub fn spawn(job: DownloadJob, tx: Sender<DownloadMsg>) {
    std::thread::spawn(move || {
        let outcome = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime.block_on(run(job, &tx)),
            Err(e) => Err(format!("starting the async runtime: {e}")),
        };
        let _ = tx.send(DownloadMsg::Done(outcome));
    });
}

async fn run(job: DownloadJob, tx: &Sender<DownloadMsg>) -> Result<String, String> {
    let stage = |text: &str| {
        let _ = tx.send(DownloadMsg::Task(text.to_string(), 0, 0));
    };

    // ---- Offline: masks, product, configuration.
    stage("Resolving master data");
    let mask_db = match &job.master_data {
        Some(path) => MaskDb::from_file(path).map_err(|e| format!("master data: {e}"))?,
        None => MaskDb::resolve().map_err(|e| format!("master data: {e} (set KNX_MASTER_DATA)"))?,
    };
    let product = ProductData::from_program(&job.program).map_err(|e| format!("product data: {e}"))?;

    stage("Resolving the configuration");
    let mut device = Device::new(job.program, None, None);
    apply_mods(&mut device, &job.mods).map_err(|e| format!("applying the configuration: {e}"))?;
    let resolved = resolve_mods(&device, &job.mods, &product).map_err(|e| format!("resolving: {e}"))?;
    let keyring = job.security.load_keyring().map_err(|e| format!("loading the ETS keyring: {e}"))?;
    let key_material =
        resolve_key_material(&resolved.configuration, &job.mods, keyring.as_ref(), product.is_secure_enabled)
            .map_err(|e| format!("resolving security: {e}"))?;

    // ---- Online.
    stage("Connecting to the bus");
    let prepared =
        job.security.prepare_with_keyring(keyring).map_err(|e| format!("preparing secure sequence state: {e}"))?;
    let bus = job.target.connect_with_security(prepared.store).await.map_err(|e| format!("connecting: {e}"))?;
    let mut mods_store = ModsFileKeyStore::open(&job.mods_path).map_err(|e| format!("opening mods key store: {e}"))?;
    let sink_tx = tx.clone();
    let report = DeviceProgrammer::new()
        .program_with_progress(
            &bus,
            ProgrammingRequest {
                mask_db: &mask_db,
                product: &product,
                configuration: &resolved.configuration,
                key_material,
                options: ProgrammingOptions::default(),
            },
            Some(&mut mods_store),
            Box::new(move |event| {
                let message = match event {
                    ProgrammingEvent::Stage(stage) => DownloadMsg::Task(stage_label(stage).to_string(), 0, 0),
                    ProgrammingEvent::Download(DownloadEvent::Step { index, total, description }) => {
                        DownloadMsg::Task(description, index, total)
                    }
                    ProgrammingEvent::Download(DownloadEvent::Data { done, total }) => DownloadMsg::Data(done, total),
                };
                let _ = sink_tx.send(message);
            }),
        )
        .await
        .map_err(|e| format!("programming: {e}"))?;

    // A generated key was inserted with `toml_edit`; reflect the complete
    // document back into App state before any later full export.
    let updated = std::fs::read_to_string(&job.mods_path)
        .map_err(|e| format!("reading updated mods: {e}"))
        .and_then(|text| toml::from_str(&text).map_err(|e| format!("parsing updated mods: {e}")))?;
    let _ = tx.send(DownloadMsg::ModsUpdated(updated));
    let _ = bus.disconnect().await;
    let rendered: Vec<String> = report.load_states.iter().map(|(target, state)| format!("{target}={state}")).collect();
    let security = if report.security.is_some() { ", Security Mode enabled" } else { "" };
    Ok(format!(
        "Device {} programmed via {:?} — load states [{}]{security}",
        report.individual_address,
        report.management_access,
        rendered.join(", ")
    ))
}

fn stage_label(stage: ProgrammingStage) -> &'static str {
    match stage {
        ProgrammingStage::PersistingToolKey => "Persisting generated tool key",
        ProgrammingStage::DiscoveringDevice => "Discovering device",
        ProgrammingStage::ReadingDescriptor => "Reading device descriptor",
        ProgrammingStage::Compiling => "Compiling download",
        ProgrammingStage::AssigningAddress => "Assigning individual address",
        ProgrammingStage::SelectingManagementAccess => "Selecting management access",
        ProgrammingStage::InstallingToolKey => "Installing tool key",
        ProgrammingStage::Downloading => "Downloading",
        ProgrammingStage::WaitingForRestart => "Waiting for restart",
        ProgrammingStage::Verifying => "Verifying",
    }
}
