//! Programming the opened device from inside the TUI.
//!
//! The TUI is a synchronous crossterm loop and the client is tokio,
//! so the download runs on its own thread with a single-threaded
//! runtime, reporting through an `std::sync::mpsc` channel the UI
//! drains every tick. The flow mirrors `knx-loader load`: resolve the
//! session's configuration through the mods machinery, compile,
//! negotiate the APDU, run the procedure with a progress sink, and
//! read the load states back after the restart.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use zweidraehte_client::IndividualAddress;
use zweidraehte_client::cli::BusTarget;
use zweidraehte_client::download::{
    DownloadEvent, DownloadModel, Downloader, Instruction, LoadControlPath, LoadEvent, MaskDb, ProductData, compile,
    resolve_mods, select_download_mask,
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
}

/// Everything the worker thread needs, all owned.
pub struct DownloadJob {
    pub target: BusTarget,
    pub ia: IndividualAddress,
    /// The session's configuration, exported from the device.
    pub mods: DeviceMods,
    /// The pristine program (language-independent facts only matter).
    pub program: ApplicationProgram,
    /// Explicit master data path; falls back to `MaskDb::resolve()`.
    pub master_data: Option<PathBuf>,
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
    let mut product = ProductData::from_program(&job.program).map_err(|e| format!("product data: {e}"))?;
    let product_mask = product.mask_version.ok_or("the product names no mask version")?;

    stage("Resolving the configuration");
    let mut device = Device::new(job.program, None, None);
    apply_mods(&mut device, &job.mods).map_err(|e| format!("applying the configuration: {e}"))?;
    let resolved = resolve_mods(&device, &job.mods, &product).map_err(|e| format!("resolving: {e}"))?;
    product.com_objects = resolved.com_objects.clone();

    // ---- Online.
    stage("Connecting to the bus");
    let bus = job.target.connect().await.map_err(|e| format!("connecting: {e}"))?;

    // The mask the download is compiled for is the *device's* (its
    // DD0), the way ETS decides it — a BCU2 answering 0020 runs a
    // downward-compatible BCU1 product through the BCU2 procedure.
    stage("Reading the device descriptor");
    let dd0 = {
        let mut connection = bus.connect_device(job.ia).await.map_err(|e| format!("connecting to device: {e}"))?;
        let descriptor = connection.device_descriptor_read(0).await;
        let _ = connection.close().await;
        let descriptor = descriptor.map_err(|e| format!("reading the device descriptor: {e}"))?;
        match descriptor[..] {
            [hi, lo] => zweidraehte_client::MaskVersion::from(u16::from_be_bytes([hi, lo])),
            _ => return Err(format!("DD0 answered {} octets, expected 2", descriptor.len())),
        }
    };
    let mask = select_download_mask(&mask_db, product_mask, dd0)
        .map_err(|e| format!("matching the product to the device: {e}"))?;

    stage("Compiling the download");
    let compiled = compile(&mask, &product, &resolved.project).map_err(|e| format!("compiling: {e}"))?;

    // ETS's NegotiateMaxApduLength, unless the mods pinned a value —
    // or the model knows the device has no properties to ask (BCU1).
    let model = DownloadModel::for_management_model(mask.management_model());
    let max_apdu = match (job.mods.device.max_apdu, model) {
        (Some(fixed), _) => fixed,
        (None, Some(model)) if !model.has_properties => model.default_max_apdu,
        (None, _) => match bus
            .network_management()
            .property_read(job.ia, 0, zweidraehte_client::pid::device::MAX_APDU_LENGTH, 1, 1)
            .await
        {
            Ok(bytes) => {
                let device_max = bytes.iter().fold(0u16, |acc, &b| (acc << 8) | u16::from(b));
                device_max.min(bus.max_apdu()).max(15)
            }
            Err(_) => 15,
        },
    };

    stage(&format!("Programming {} (APDU {max_apdu})", job.ia));
    let result = async {
        let mut connection = bus.connect_device(job.ia).await.map_err(|e| format!("connecting to device: {e}"))?;
        let sink_tx = tx.clone();
        let mut downloader = Downloader::with_path(&mut connection, compiled.path(), max_apdu);
        if let Some(model) = model
            && !model.authorize_on_connect
        {
            downloader = downloader.without_authorize();
        }
        let outcome = downloader
            .with_progress(Box::new(move |event| {
                let _ = match event {
                    DownloadEvent::Step { index, total, description } => {
                        sink_tx.send(DownloadMsg::Task(description, index, total))
                    }
                    DownloadEvent::Data { done, total } => sink_tx.send(DownloadMsg::Data(done, total)),
                };
            }))
            .run(&compiled.instructions, &compiled.image)
            .await;
        // The procedure ends in a restart; the connection died with it.
        let _ = connection.close().await;
        outcome.map_err(|e| format!("download: {e}"))
    }
    .await;
    result?;

    // ---- Verify: the machines the procedure completed must read
    // Loaded once the device is back up.
    stage("Waiting for the device to restart");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let completed: Vec<u8> = compiled
        .instructions
        .iter()
        .filter_map(|i| match i {
            Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted } => Some(*lsm),
            _ => None,
        })
        .collect();

    stage("Reading load states back");
    let mut connection = bus.connect_device(job.ia).await.map_err(|e| format!("verification reconnect: {e}"))?;
    let mut states = Vec::new();
    for machine in &completed {
        let state = match compiled.path() {
            LoadControlPath::Property => connection
                .property_read(*machine, zweidraehte_client::pid::LOAD_STATE_CONTROL, 1, 1)
                .await
                .map(|bytes| bytes.first().copied().unwrap_or(0xFF)),
            LoadControlPath::Memory(resources) => connection
                .memory_read(resources.load_status_addr + u16::from(machine - 1), 1)
                .await
                .map(|bytes| bytes.first().copied().unwrap_or(0xFF)),
            // A direct-path procedure contains no LoadCompleted
            // events, so `completed` is empty and this loop body
            // never runs.
            LoadControlPath::Direct => {
                Err(zweidraehte_client::Error::UnsupportedInstruction("no load states on the direct path"))
            }
        }
        .map_err(|e| format!("reading machine {machine}'s state: {e}"))?;
        states.push((*machine, state));
    }
    let _ = connection.close().await;
    let _ = bus.disconnect().await;

    if let Some((machine, state)) = states.iter().find(|(_, state)| *state != 0x01) {
        return Err(format!("machine {machine} reports {state:#04X} after the download, expected Loaded"));
    }
    let rendered: Vec<String> = states.iter().map(|(_, s)| format!("{s:02X}")).collect();
    Ok(format!("Device programmed — load states [{}]", rendered.join(" ")))
}
