//! Project-based KNX commissioning frontend.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use knx_config::load;
use zweidraehte_client::cli::{BusTarget, OptionalTargetArgs, SecurityArgs};
use zweidraehte_client::download::{
    DeviceImage, DownloadModel, MaskDb, ProcedureKind, ProductData, assemble, compile, load_control_path,
    select_download_mask,
};
use zweidraehte_client::security::ResolvedKeyMaterial;
use zweidraehte_client::{
    AddressingMode, BatchSelection, DeviceProgrammer, KnxBus, MaskVersion, ProgrammingEvent, ProgrammingOptions,
    ProgrammingRequest, ProgrammingStage, ProjectProduct, ProjectProgrammer, connect_management,
};
use zweidraehte_project::{
    KeyEpoch, KeyId, KeyMaterialSource, KeyMetadata, KeyRecord, KeyStoreError, ProductReference, ProjectDeviceId,
    ProjectEvent, ProjectStore,
};

#[derive(Parser)]
#[command(about = "Check, program, read, and unload devices from a KNX project")]
struct Args {
    #[arg(long, default_value = "project.knx")]
    project: PathBuf,
    #[arg(long)]
    master_data: Option<PathBuf>,
    #[command(flatten)]
    target: OptionalTargetArgs,
    #[command(flatten)]
    security: SecurityArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Check,
    Status,
    Load {
        device: Option<String>,
        #[arg(long)]
        affected: bool,
        #[arg(long, conflicts_with = "affected")]
        force_single: bool,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        program_ia: bool,
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
        #[arg(long, value_name = "DIR")]
        dump_blobs: Option<PathBuf>,
    },
    Read {
        device: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    Unload {
        device: String,
    },
    Sync,
    RecoverState {
        #[arg(long)]
        client_floor: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let mut store = ProjectStore::open(&args.project)
        .with_context(|| format!("while attempting to open {}", args.project.display()))?;

    match args.command {
        Command::Status => print_status(&store, &args.security),
        Command::Check => run_check(&store, args.master_data.as_deref(), &args.security),
        Command::Load { device, affected, force_single, all, dry_run, program_ia, device_mask, dump_blobs } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_load(
                &mut store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                affected,
                force_single,
                all,
                dry_run,
                program_ia,
                device_mask,
                dump_blobs.as_deref(),
            )
            .await
        }
        Command::Read { device, out } => {
            run_read(&mut store, args.master_data.as_deref(), &args.target, &args.security, &device, &out).await
        }
        Command::Unload { device } => {
            run_unload(&mut store, args.master_data.as_deref(), &args.target, &args.security, &device).await
        }
        Command::Sync => {
            run_sync(&mut store, args.master_data.as_deref(), &args.target, &args.security, false, None).await
        }
        Command::RecoverState { client_floor } => {
            run_sync(&mut store, args.master_data.as_deref(), &args.target, &args.security, true, client_floor).await
        }
    }
}

fn print_status(store: &ProjectStore, security: &SecurityArgs) -> Result<()> {
    store.authored().validate_download().map_err(|error| {
        anyhow::anyhow!(
            "{}",
            error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; ")
        )
    })?;
    let products = load_products(store).context("while attempting to load products for status")?;
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let fingerprints = ProjectProgrammer::new()
        .deployment_fingerprints(
            store.authored(),
            &products,
            store.keys().map(|keys| keys as &dyn KeyMaterialSource),
            keyring.as_ref(),
        )
        .context("while attempting to compute deployment fingerprints")?;
    for id in store.authored().devices.keys() {
        let authored = &fingerprints[id];
        let deployed = store.state().and_then(|state| state.deployments.get(&id.0));
        let status = if deployed == Some(authored) { "current" } else { "stale" };
        let inconsistent =
            store.state().is_some_and(|state| state.inconsistent_devices.iter().any(|candidate| candidate == &id.0));
        println!("{id}: {status}{}", if inconsistent { ", inconsistent batch" } else { "" });
    }
    match (store.keys(), store.state()) {
        (None, None) => println!("project state: not initialized"),
        (Some(_), Some(state)) if state.recovery_required => {
            println!("project state: recovery required; secure group sending is blocked")
        }
        (Some(_), Some(_)) if !store.secure_state_ready() => {
            println!("project state: identity mismatch; run recover-state")
        }
        (Some(_), Some(state)) => println!("project state: ready, next client sequence {}", state.client_next),
        _ => println!("project state: partially initialized; run recover-state"),
    }
    Ok(())
}

fn run_check(store: &ProjectStore, master_data: Option<&Path>, security: &SecurityArgs) -> Result<()> {
    let products = load_products(store)?;
    let mask_db = load::load_mask_db(master_data, None)?;
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let empty = EmptyKeySource;
    let keys: &dyn KeyMaterialSource = store.keys().map_or(&empty, |keys| keys);
    let selected: Vec<_> = store.authored().devices.keys().cloned().collect();
    let plan = ProjectProgrammer::new()
        .plan(
            store.authored(),
            store.state(),
            &selected,
            BatchSelection::Selected { include_affected: true, force_single: false },
            &products,
            keys,
            keyring.as_ref(),
        )
        .context("while attempting to validate and lower the project")?;
    for device in &plan.devices {
        compile_offline(device, &mask_db, None)?;
        for warning in &device.warnings {
            eprintln!("warning: {warning}");
        }
    }
    println!("{} devices validated and compiled", plan.devices.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_load(
    store: &mut ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device: Option<String>,
    affected: bool,
    force_single: bool,
    all: bool,
    dry_run: bool,
    program_ia: bool,
    device_mask: Option<MaskVersion>,
    dump_blobs: Option<&Path>,
) -> Result<()> {
    if all == device.is_some() {
        bail!("give exactly one device identifier or --all");
    }
    let products = load_products(store)?;
    let mask_db = load::load_mask_db(master_data, None)?;
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let selected = device.map(|id| vec![ProjectDeviceId(id)]).unwrap_or_default();
    let selection = if all {
        BatchSelection::AllStale
    } else {
        BatchSelection::Selected { include_affected: affected, force_single }
    };

    if dry_run {
        let empty = EmptyKeySource;
        let keys: &dyn KeyMaterialSource = store.keys().map_or(&empty, |keys| keys);
        let plan = ProjectProgrammer::new()
            .plan(store.authored(), store.state(), &selected, selection, &products, keys, keyring.as_ref())
            .context("while attempting to plan the download batch")?;
        for planned in &plan.devices {
            let compiled = compile_offline(planned, &mask_db, device_mask)?;
            print_compiled(planned, &compiled);
            dump_blob_files(dump_blobs, &planned.id.0, &compiled)?;
            if planned.key_material.needs_tool_key_generation {
                println!("{}: would generate and persist a tool key before bus access", planned.id);
            }
        }
        println!("dry run: {} devices in the affected closure", plan.devices.len());
        return Ok(());
    }

    if store.state().is_none() && store.keys().is_none() {
        store.initialize().context("while attempting to initialize project keys and state")?;
    }
    let lock = store.acquire_lock().context("while attempting to acquire the project lock")?;
    store.begin_mutation(&lock).context("while attempting to open the project journal")?;
    let mut plan = ProjectProgrammer::new()
        .plan(
            store.authored(),
            store.state(),
            &selected,
            selection,
            &products,
            store.keys().context("project has no keys.toml")?,
            keyring.as_ref(),
        )
        .context("while attempting to plan the download batch")?;
    if plan.devices.is_empty() {
        println!("no stale devices");
        return Ok(());
    }
    ProjectProgrammer::new()
        .materialize_tool_keys(&mut plan, store.keys_mut().context("project has no writable keys.toml")?)
        .context("while attempting to persist generated tool keys")?;

    let shared = move_store(store)?;
    let prepared = security
        .prepare_project(Arc::clone(&shared), keyring)
        .context("while attempting to prepare project security state")?;
    let bus = require_target(target)?
        .connect_with_security(prepared.store)
        .await
        .context("while attempting to connect to the bus")?;

    let options = ProgrammingOptions {
        addressing: if program_ia { AddressingMode::ProgrammingButton } else { AddressingMode::Automatic },
        ..ProgrammingOptions::default()
    };
    let preflight = ProjectProgrammer::new()
        .preflight_batch(&bus, &mask_db, &mut plan, options.clone())
        .await
        .context("while attempting to preflight the complete affected batch")?;
    for (planned, report) in plan.devices.iter().zip(preflight) {
        println!(
            "preflight {}: current {}, device mask {}, {} instructions",
            planned.id,
            report.current_address,
            report.device_mask,
            report.compiled.instructions.len()
        );
    }

    let mut successful = Vec::new();
    let mut failure = None;
    for planned in &plan.devices {
        println!("programming {} ({})", planned.id, planned.configuration.identity.desired_address);
        let request = ProgrammingRequest {
            mask_db: &mask_db,
            product: &planned.product,
            configuration: &planned.configuration,
            key_material: planned.key_material.clone(),
            options: options.clone(),
        };
        match DeviceProgrammer::new().program_with_progress(&bus, request, None, Box::new(print_progress)).await {
            Ok(report) => {
                println!(
                    "{}: loaded at {}, mask {}, {} instructions",
                    planned.id, report.individual_address, report.device_mask, report.instruction_count
                );
                record_success(&shared, planned)?;
                successful.push(planned.id.0.clone());
            }
            Err(error) => {
                failure =
                    Some(anyhow::Error::new(error).context(format!("while attempting to program {}", planned.id)));
                break;
            }
        }
    }
    if let Some(error) = failure {
        let devices = plan.devices.iter().map(|device| device.id.0.clone()).collect();
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
            .record(ProjectEvent::MarkInconsistent { devices })
            .context("while attempting to record the partial batch failure")?;
        let _ = bus.disconnect().await;
        bail!("{error}; successful devices: {}", successful.join(", "));
    }
    bus.disconnect().await.context("while attempting to disconnect")?;
    shared
        .lock()
        .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
        .compact()
        .context("while attempting to compact project state")?;
    println!("programmed {} devices", successful.len());
    Ok(())
}

fn record_success(store: &Arc<Mutex<ProjectStore>>, planned: &zweidraehte_client::PlannedProjectDevice) -> Result<()> {
    let mut store = store.lock().map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?;
    store
        .record(ProjectEvent::RecordDeployment {
            device: planned.id.0.clone(),
            fingerprints: planned.fingerprints.clone(),
        })
        .context("while attempting to record the successful deployment")?;
    for metadata in &planned.key_material.provenance {
        if let zweidraehte_project::KeyScope::Group(net) = &metadata.id.scope {
            let fingerprint = metadata.fingerprint.iter().map(|byte| format!("{byte:02x}")).collect();
            store
                .record(ProjectEvent::RecordGroupKey { net: net.clone(), fingerprint })
                .context("while attempting to record the deployed group key")?;
        }
    }
    Ok(())
}

async fn run_read(
    store: &mut ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device_id: &str,
    out: &Path,
) -> Result<()> {
    let (shared, _lock, bus, planned, _mask_db) =
        open_device_session(store, master_data, target, security, device_id).await?;
    let addressed: Vec<_> =
        planned.product.segments.iter().filter_map(|segment| segment.address.map(|at| (at, segment))).collect();
    if addressed.is_empty() {
        bail!("this product has no absolutely addressed segments to read");
    }
    std::fs::create_dir_all(out).with_context(|| format!("while attempting to create {}", out.display()))?;
    let current =
        locate_current_address(&bus, &planned.key_material, planned.configuration.identity.desired_address).await?;
    let (mut connection, access) = connect_management(&bus, current, &planned.key_material, true)
        .await
        .context("while attempting to select management access")?;
    println!("access: {access:?}");
    let chunk = usize::from(bus.max_apdu().saturating_sub(3)).clamp(1, 63);
    for (address, segment) in addressed {
        let mut bytes = Vec::with_capacity(segment.size as usize);
        while bytes.len() < segment.size as usize {
            let at = address + bytes.len() as u16;
            let count = chunk.min(segment.size as usize - bytes.len()) as u8;
            bytes.extend(
                connection
                    .memory_read(at, count)
                    .await
                    .with_context(|| format!("while attempting to read {count} bytes at {at:#06X}"))?,
            );
        }
        let path = out.join(format!("region_{address:04X}.bin"));
        std::fs::write(&path, bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
    }
    let _ = connection.close().await;
    bus.disconnect().await.context("while attempting to disconnect")?;
    drop(shared);
    Ok(())
}

async fn run_unload(
    store: &mut ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device_id: &str,
) -> Result<()> {
    let (shared, _lock, bus, planned, mask_db) =
        open_device_session(store, master_data, target, security, device_id).await?;
    let desired = planned.configuration.identity.desired_address;
    let current = locate_current_address(&bus, &planned.key_material, desired).await?;
    let (mut connection, _) = connect_management(&bus, current, &planned.key_material, true)
        .await
        .context("while attempting to select management access")?;
    let descriptor = connection.device_descriptor_read(0).await.context("while attempting to read DD0")?;
    let [high, low] = descriptor.as_slice() else { bail!("DD0 did not return two octets") };
    let device_mask = MaskVersion::from(u16::from_be_bytes([*high, *low]));
    let product_mask = planned.product.mask_version.context("product has no mask version")?;
    let mask = select_download_mask(&mask_db, product_mask, device_mask)
        .context("while attempting to select the unload procedure")?;
    let instructions = assemble(&mask, &planned.product, ProcedureKind::UnloadAll)
        .context("while attempting to assemble the unload procedure")?;
    let model = DownloadModel::for_management_model(mask.management_model());
    let path = load_control_path(&mask).context("while attempting to select the unload path")?;
    let max_apdu = planned.configuration.max_apdu.unwrap_or(bus.max_apdu()).min(bus.max_apdu()).max(15);
    let mut downloader = zweidraehte_client::download::Downloader::with_path(&mut connection, path, max_apdu);
    if let Some(model) = model {
        if !model.authorize_on_connect {
            downloader = downloader.without_authorize();
        }
        if model.diff_writes {
            downloader = downloader.with_diffed_writes();
        }
    }
    downloader.run(&instructions, &DeviceImage::new()).await.context("while attempting to execute Unload-all")?;
    let _ = connection.close().await;
    bus.disconnect().await.context("while attempting to disconnect")?;
    shared
        .lock()
        .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
        .record(ProjectEvent::MarkInconsistent { devices: vec![device_id.to_string()] })
        .context("while attempting to record unloaded state")?;
    Ok(())
}

async fn run_sync(
    store: &mut ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    recover: bool,
    client_floor: Option<u64>,
) -> Result<()> {
    if store.keys().is_none() || (!recover && store.state().is_none()) {
        bail!("project keys must exist, and normal synchronisation also requires project state");
    }
    let products = load_products(store)?;
    let _mask_db = load::load_mask_db(master_data, None)?;
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let selected: Vec<_> = store.authored().devices.keys().cloned().collect();
    let plan = ProjectProgrammer::new()
        .plan(
            store.authored(),
            if recover { None } else { store.state() },
            &selected,
            BatchSelection::Selected { include_affected: true, force_single: false },
            &products,
            store.keys().context("project has no keys.toml")?,
            keyring.as_ref(),
        )
        .context("while attempting to plan secure synchronisation")?;
    let lock = if recover {
        store.acquire_recovery_lock().context("while attempting to acquire the project recovery lock")?
    } else {
        store.acquire_lock().context("while attempting to acquire the project lock")?
    };
    if recover {
        store.begin_recovery(&lock).context("while attempting to enter project state recovery")?;
    } else {
        store.begin_mutation(&lock).context("while attempting to open the project journal")?;
    }
    if let Some(floor) = client_floor {
        store.advance_client_sequence(floor).context("while attempting to apply the recovery floor")?;
    }
    let authored = store.authored().clone();
    let shared = move_store(store)?;
    let prepared = security
        .prepare_project(Arc::clone(&shared), keyring)
        .context("while attempting to prepare project security state")?;
    let bus = require_target(target)?
        .connect_with_security(prepared.store)
        .await
        .context("while attempting to connect to the bus")?;

    let mut unavailable = Vec::new();
    for planned in plan
        .devices
        .iter()
        .filter(|device| device.key_material.tool_key.is_some() || device.key_material.fdsk.is_some())
    {
        let current =
            locate_current_address(&bus, &planned.key_material, planned.configuration.identity.desired_address).await?;
        match connect_management(&bus, current, &planned.key_material, false).await {
            Ok((mut connection, _)) => {
                if recover {
                    recover_device_state(&shared, &authored, planned, &mut connection, bus.assigned_address()).await?;
                }
                let _ = connection.close().await;
                println!("{}: synchronised", planned.id);
            }
            Err(error) => {
                unavailable.push(planned.id.0.clone());
                eprintln!("{}: unavailable ({error})", planned.id);
            }
        }
    }
    bus.disconnect().await.context("while attempting to disconnect")?;
    if !unavailable.is_empty() && recover && client_floor.is_none() {
        bail!(
            "state recovery needs every managed secure receiver, or an explicit --client-floor; unavailable: {}",
            unavailable.join(", ")
        );
    }
    if recover {
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
            .finish_recovery()
            .context("while attempting to complete project state recovery")?;
    }
    Ok(())
}

async fn recover_device_state(
    store: &Arc<Mutex<ProjectStore>>,
    authored: &zweidraehte_project::AuthoredProject,
    planned: &zweidraehte_client::PlannedProjectDevice,
    connection: &mut zweidraehte_client::DeviceConnection,
    client_address: zweidraehte_client::IndividualAddress,
) -> Result<()> {
    const SECURITY_IO: u16 = 0x0011;
    let serial_bytes = planned.key_material.serial_number.context("secure managed device has no serial")?;
    let bytes = connection
        .property_ext_read(SECURITY_IO, 1, zweidraehte_client::pid::security::SEQUENCE_NUMBER_SENDING, 1, 1)
        .await
        .context("while attempting to read PID 59")?;
    let next = decode_u48(&bytes)?;
    let serial = zweidraehte_project::format_serial(&serial_bytes);
    store
        .lock()
        .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
        .record(ProjectEvent::ObserveDeviceOutgoing { serial: serial.clone(), next })
        .context("while attempting to record PID 59")?;

    let count = connection
        .property_ext_read(SECURITY_IO, 1, zweidraehte_client::pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0, 1)
        .await
        .context("while attempting to read the SIAT count")?;
    let count = u16::from_be_bytes(count.try_into().map_err(|_| anyhow::anyhow!("SIAT count is not two octets"))?);
    for index in 1..=count {
        let row = connection
            .property_ext_read(
                SECURITY_IO,
                1,
                zweidraehte_client::pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                index,
                1,
            )
            .await
            .with_context(|| format!("while attempting to read SIAT row {index}"))?;
        if row.len() != 8 {
            bail!("SIAT row {index} is {} octets, expected 8", row.len());
        }
        let address = zweidraehte_client::IndividualAddress::from_bytes(&row[..2]);
        let last_valid = decode_u48(&row[2..])?;
        if address == client_address {
            store
                .lock()
                .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
                .advance_client_sequence(last_valid.saturating_add(1))
                .context("while attempting to recover the project client floor from SIAT")?;
        }
        let sender = authored
            .devices
            .values()
            .find(|device| device.address == address)
            .and_then(|device| device.serial)
            .map(|serial| {
                zweidraehte_project::SenderIdentity::ManagedSerial(zweidraehte_project::format_serial(&serial))
            })
            .unwrap_or_else(|| zweidraehte_project::SenderIdentity::UnmanagedAddress(address.to_string()));
        store
            .lock()
            .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
            .record(ProjectEvent::ObserveDeviceSiat { serial: serial.clone(), sender, last_valid })
            .context("while attempting to record a live SIAT row")?;
    }
    Ok(())
}

async fn open_device_session(
    store: &mut ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device_id: &str,
) -> Result<(
    Arc<Mutex<ProjectStore>>,
    zweidraehte_project::ProjectLock,
    KnxBus,
    zweidraehte_client::PlannedProjectDevice,
    MaskDb,
)> {
    if store.state().is_none() || store.keys().is_none() {
        bail!("project keys and state are not initialized");
    }
    let products = load_products(store)?;
    let mask_db = load::load_mask_db(master_data, None)?;
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let selected = [ProjectDeviceId(device_id.to_string())];
    let plan = ProjectProgrammer::new()
        .plan(
            store.authored(),
            store.state(),
            &selected,
            BatchSelection::Selected { include_affected: false, force_single: true },
            &products,
            store.keys().context("project has no keys.toml")?,
            keyring.as_ref(),
        )
        .context("while attempting to resolve the project device")?;
    let planned = plan.devices.into_iter().next().context("project device was not planned")?;
    let lock = store.acquire_lock().context("while attempting to acquire the project lock")?;
    store.begin_mutation(&lock).context("while attempting to open the project journal")?;
    let shared = move_store(store)?;
    let prepared = security
        .prepare_project(Arc::clone(&shared), keyring)
        .context("while attempting to prepare project security state")?;
    let bus = require_target(target)?
        .connect_with_security(prepared.store)
        .await
        .context("while attempting to connect to the bus")?;
    Ok((shared, lock, bus, planned, mask_db))
}

fn move_store(store: &mut ProjectStore) -> Result<Arc<Mutex<ProjectStore>>> {
    let replacement =
        ProjectStore::open(store.project_path()).context("while attempting to retain a project handle")?;
    Ok(Arc::new(Mutex::new(std::mem::replace(store, replacement))))
}

async fn locate_current_address(
    bus: &KnxBus,
    keys: &ResolvedKeyMaterial,
    desired: zweidraehte_client::IndividualAddress,
) -> Result<zweidraehte_client::IndividualAddress> {
    let Some(serial) = keys.serial_number else { return Ok(desired) };
    let found = bus
        .network_management()
        .read_individual_addresses_by_serial(&serial, Duration::from_secs(2))
        .await
        .context("while attempting to locate the device by serial")?;
    match found.as_slice() {
        [address] => Ok(*address),
        [] => Ok(desired),
        _ => bail!("{} devices answered for serial {}", found.len(), zweidraehte_project::format_serial(&serial)),
    }
}

fn load_products(store: &ProjectStore) -> Result<BTreeMap<ProjectDeviceId, ProjectProduct>> {
    let mut products = BTreeMap::new();
    for (id, device) in &store.authored().devices {
        let ProductReference::Local(relative) = &device.product;
        let path = store
            .authored()
            .resolve_product_path(device)
            .with_context(|| format!("project device `{id}` has no resolvable product path"))?;
        let (program, _, _) = load::load_program(&path).with_context(|| {
            format!("while attempting to load product `{}` from {}", relative.display(), path.display())
        })?;
        let product = ProductData::from_program(&program)
            .with_context(|| format!("while attempting to extract product data for `{id}`"))?;
        products.insert(id.clone(), ProjectProduct { program, product });
    }
    Ok(products)
}

fn compile_offline(
    planned: &zweidraehte_client::PlannedProjectDevice,
    mask_db: &MaskDb,
    device_mask: Option<MaskVersion>,
) -> Result<zweidraehte_client::download::CompiledDownload> {
    let product_mask = planned.product.mask_version.context("product has no mask version")?;
    let mask = select_download_mask(mask_db, product_mask, device_mask.unwrap_or(product_mask))
        .context("while attempting to select the offline mask")?;
    let lowered = planned
        .configuration
        .lower(planned.key_material.application_security.clone())
        .context("while attempting to lower the planned configuration")?;
    let mut product = planned.product.clone();
    product.com_objects = lowered.com_objects;
    compile(&mask, &product, &lowered.project).context("while attempting to compile the planned download")
}

fn print_compiled(
    planned: &zweidraehte_client::PlannedProjectDevice,
    compiled: &zweidraehte_client::download::CompiledDownload,
) {
    println!(
        "{}: {}, {} parameters, {} associations, {} instructions",
        planned.id,
        planned.configuration.identity.desired_address,
        planned.configuration.parameters.len(),
        planned.configuration.object_memberships.len(),
        compiled.instructions.len()
    );
    for (address, bytes) in compiled.image.regions() {
        println!("  region {address:#06X}: {} bytes", bytes.len());
    }
}

fn dump_blob_files(
    directory: Option<&Path>,
    device: &str,
    compiled: &zweidraehte_client::download::CompiledDownload,
) -> Result<()> {
    let Some(directory) = directory else { return Ok(()) };
    let directory = directory.join(device);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("while attempting to create {}", directory.display()))?;
    for (address, bytes) in compiled.image.regions() {
        let path = directory.join(format!("region_{address:04X}.bin"));
        std::fs::write(&path, bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
    }
    Ok(())
}

fn print_progress(event: ProgrammingEvent) {
    match event {
        ProgrammingEvent::Stage(stage) => println!("  {}", stage_name(stage)),
        ProgrammingEvent::Download(event) => println!("    {event:?}"),
    }
}

fn stage_name(stage: ProgrammingStage) -> &'static str {
    match stage {
        ProgrammingStage::PersistingToolKey => "persisting tool key",
        ProgrammingStage::DiscoveringDevice => "discovering device",
        ProgrammingStage::ReadingDescriptor => "reading DD0",
        ProgrammingStage::Compiling => "compiling",
        ProgrammingStage::AssigningAddress => "assigning individual address",
        ProgrammingStage::SelectingManagementAccess => "selecting management access",
        ProgrammingStage::InstallingToolKey => "installing tool key",
        ProgrammingStage::SettingDeviceSequence => "setting PID 59",
        ProgrammingStage::Downloading => "downloading",
        ProgrammingStage::WaitingForRestart => "waiting for restart",
        ProgrammingStage::Verifying => "verifying",
    }
}

fn decode_u48(bytes: &[u8]) -> Result<u64> {
    let bytes: [u8; 6] = bytes.try_into().map_err(|_| anyhow::anyhow!("expected a six-octet sequence number"))?;
    Ok(u64::from_be_bytes([0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]))
}

fn parse_mask(value: &str) -> Result<MaskVersion> {
    u16::from_str_radix(value.trim_start_matches("0x"), 16)
        .map(MaskVersion::from)
        .context("--device-mask wants a hexadecimal mask such as 0020")
}

fn require_target(target: &OptionalTargetArgs) -> Result<BusTarget> {
    target.to_target().context("give --server or --usb before the subcommand")
}

struct EmptyKeySource;

impl KeyMaterialSource for EmptyKeySource {
    fn list(&self) -> core::result::Result<Vec<KeyMetadata>, KeyStoreError> {
        Ok(Vec::new())
    }

    fn read(&self, _id: &KeyId, _epoch: Option<KeyEpoch>) -> core::result::Result<Option<KeyRecord>, KeyStoreError> {
        Ok(None)
    }
}
