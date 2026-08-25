//! Project-based KNX commissioning frontend.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::{Select, theme::ColorfulTheme};

use knx_config::load;
use zweidraehte_client::cli::{BusTarget, OptionalTargetArgs, SecurityArgs};
use zweidraehte_client::download::{
    DeviceImage, DownloadModel, DownloadScope, MaskDb, ProcedureKind, ProductData, assemble, compile_scoped,
    load_control_path, select_download_mask,
};
use zweidraehte_client::security::{Keyring, KeyringDevice, ResolvedKeyMaterial};
use zweidraehte_client::{
    AddressingMode, BatchSelection, DeviceProgrammer, KnxBus, MaskVersion, ProgrammingEvent, ProgrammingOptions,
    ProgrammingRequest, ProgrammingScope, ProgrammingStage, ProjectProduct, ProjectProgrammer, build_project_keyring,
    connect_management, connect_management_synchronized,
};
use zweidraehte_knxprod::runtime::{KnxprodArchive, KnxprodDevice};
use zweidraehte_knxprod::schema::ApplicationProgram;
use zweidraehte_project::{
    DataSecureMode, DecodedFdsk, DeploymentFingerprints, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource,
    KeyMaterialStore, KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState, KeyStoreError, Medium, ProductReference,
    ProjectDevice, ProjectDeviceDraft, ProjectDeviceId, ProjectEvent, ProjectStore, SecretBytes, SenderIdentity,
    format_serial, parse_fdsk, parse_serial,
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
    /// Create an empty project and its matching key/sequence state
    Init,
    /// Import one device from loose MTXML or a `.knxprod` catalogue
    #[command(alias = "import-device")]
    Add {
        /// Logical project device identifier
        device: String,
        /// Loose ApplicationProgram MTXML or `.knxprod` archive
        product: PathBuf,
        /// Desired individual address
        #[arg(long, value_parser = zweidraehte_client::cli::parse_ia)]
        address: zweidraehte_client::IndividualAddress,
        /// Device serial number, with or without the manufacturer separator
        #[arg(long, value_parser = parse_project_serial)]
        serial: Option<[u8; 6]>,
        /// 32-digit FDSK or CRC-checked KNX device certificate
        #[arg(long, visible_alias = "device-certificate", value_name = "FDSK")]
        fdsk: Option<String>,
        #[arg(long)]
        max_apdu: Option<u16>,
        /// Enable the product's Data Secure application capability
        #[arg(long)]
        data_secure: bool,
        #[arg(long, value_enum, default_value_t = ProjectMedium::Tp1)]
        medium: ProjectMedium,
        /// Select a catalogue product without the interactive dialog
        #[arg(long, value_name = "ID", conflicts_with = "application")]
        catalog_product: Option<String>,
        /// Select an application program without the interactive dialog
        #[arg(long, value_name = "ID")]
        application: Option<String>,
    },
    Check,
    /// Copy matching device and group credentials from an ETS keyring into
    /// this project's authoritative key store
    ImportKeyring,
    /// Export active project credentials and device sequence observations as an ETS keyring
    ExportKeyring {
        /// New `.knxkeys` file; existing files are never replaced
        #[arg(short, long, value_name = "FILE")]
        out: PathBuf,
        /// Keyring project label; defaults to the project directory name
        #[arg(long)]
        name: Option<String>,
    },
    Status,
    /// Assign the IA and establish secure management, without loading an application
    Address {
        device: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        /// Use the physical programming-button procedure instead of serial addressing
        #[arg(long)]
        program_ia: bool,
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
    },
    /// Download application and Security IO configuration without changing the IA
    Load {
        /// Device to load. Omit with `--affected` to load every changed device.
        device: Option<String>,
        /// With a device, include its dependency closure; without one, load
        /// every device affected since its last successful deployment.
        #[arg(long, conflicts_with = "all")]
        affected: bool,
        #[arg(long, conflicts_with = "affected")]
        force_single: bool,
        /// Backward-compatible spelling for project-wide `--affected`
        #[arg(long, conflicts_with_all = ["affected", "force_single"])]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        /// Force the complete application procedure instead of differential programming
        #[arg(long)]
        full: bool,
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
        #[arg(long, value_name = "DIR")]
        dump_blobs: Option<PathBuf>,
    },
    /// Commission the IA/security state when necessary, then load the application
    Program {
        /// Device to program. Omit with `--affected` to program every changed device.
        device: Option<String>,
        /// With a device, include its dependency closure; without one, program
        /// every device affected since its last successful deployment.
        #[arg(long, conflicts_with = "all")]
        affected: bool,
        #[arg(long, conflicts_with = "affected")]
        force_single: bool,
        /// Backward-compatible spelling for project-wide `--affected`
        #[arg(long, conflicts_with_all = ["affected", "force_single"])]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        /// Force the complete application procedure instead of differential programming
        #[arg(long)]
        full: bool,
        /// Use the physical programming-button procedure instead of serial addressing
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectMedium {
    Tp1,
    Rf,
    Ip,
}

impl From<ProjectMedium> for Medium {
    fn from(value: ProjectMedium) -> Self {
        match value {
            ProjectMedium::Tp1 => Self::Tp1,
            ProjectMedium::Rf => Self::Rf,
            ProjectMedium::Ip => Self::Ip,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    match &args.command {
        Command::Init => return run_init(&args.project),
        Command::Add {
            device,
            product,
            address,
            serial,
            fdsk,
            max_apdu,
            data_secure,
            medium,
            catalog_product,
            application,
        } => {
            return run_add(
                &args.project,
                device,
                product,
                *address,
                *serial,
                fdsk.as_deref(),
                *max_apdu,
                *data_secure,
                (*medium).into(),
                catalog_product.as_deref(),
                application.as_deref(),
            );
        }
        _ => {}
    }
    let mut store = ProjectStore::open(&args.project)
        .with_context(|| format!("while attempting to open {}", args.project.display()))?;

    match args.command {
        Command::Init | Command::Add { .. } => unreachable!("authoring commands return before opening the project"),
        Command::Status => print_status(&store, &args.security),
        Command::ImportKeyring => run_import_keyring(&mut store, &args.security),
        Command::ExportKeyring { out, name } => run_export_keyring(&store, &args.security, &out, name.as_deref()),
        Command::Check => run_check(&store, args.master_data.as_deref(), &args.security),
        Command::Address { device, all, dry_run, program_ia, device_mask } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_programming(
                &mut store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                false,
                true,
                all,
                dry_run,
                false,
                program_ia,
                device_mask,
                None,
                ProgrammingScope::Address,
            )
            .await
        }
        Command::Load { device, affected, force_single, all, dry_run, full, device_mask, dump_blobs } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_programming(
                &mut store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                affected,
                force_single,
                all,
                dry_run,
                full,
                false,
                device_mask,
                dump_blobs.as_deref(),
                ProgrammingScope::Application,
            )
            .await
        }
        Command::Program {
            device,
            affected,
            force_single,
            all,
            dry_run,
            full,
            program_ia,
            device_mask,
            dump_blobs,
        } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_programming(
                &mut store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                affected,
                force_single,
                all,
                dry_run,
                full,
                program_ia,
                device_mask,
                dump_blobs.as_deref(),
                ProgrammingScope::AddressAndApplication,
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

fn run_init(project_path: &Path) -> Result<()> {
    if !project_path.exists() {
        let parent = project_path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("while attempting to create project directory {}", parent.display()))?;
        ProjectStore::write_authored(project_path, None, "# KNX project generated by `knx-loader init`\n")
            .with_context(|| format!("while attempting to create {}", project_path.display()))?;
    }

    let mut store = ProjectStore::open(project_path)
        .with_context(|| format!("while attempting to open {}", project_path.display()))?;
    match (store.keys().is_some(), store.state().is_some()) {
        (false, false) => store.initialize().context("while attempting to initialize project keys and state")?,
        (true, true) => {
            println!("project is already initialized: {}", project_path.display());
            return Ok(());
        }
        _ => bail!("project keys/state are only partially initialized; use recover-state rather than init"),
    }
    println!("initialized project: {}", project_path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_add(
    project_path: &Path,
    device: &str,
    product_path: &Path,
    address: zweidraehte_client::IndividualAddress,
    serial: Option<[u8; 6]>,
    fdsk: Option<&str>,
    max_apdu: Option<u16>,
    data_secure: bool,
    medium: Medium,
    catalog_product: Option<&str>,
    application: Option<&str>,
) -> Result<()> {
    let mut store = ProjectStore::open(project_path).with_context(|| {
        format!("while attempting to open {}; run `knx-loader --project ... init` first", project_path.display())
    })?;
    let canonical_product = product_path
        .canonicalize()
        .with_context(|| format!("while attempting to locate product {}", product_path.display()))?;
    let project_directory = project_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .with_context(|| format!("while attempting to locate project directory for {}", project_path.display()))?;
    let product_reference = relative_path(&project_directory, &canonical_product)
        .context("while attempting to make the product path relative to project.knx")?;

    let imported = select_imported_product(&canonical_product, catalog_product, application)?;
    if data_secure && !imported.program.is_secure_enabled.unwrap_or(false) {
        bail!("application `{}` does not declare Data Secure support", imported.program.id);
    }

    // A KNX device certificate is the Base32 spelling of
    // `serial || FDSK || CRC`. Reconcile the embedded serial before changing
    // either project.knx or keys.toml, and reject key conflicts up front.
    let decoded_fdsk =
        fdsk.map(parse_fdsk).transpose().context("while attempting to parse the FDSK or device certificate")?;
    let serial = reconcile_certificate_serial(serial, decoded_fdsk.as_ref())?;
    if let Some(decoded) = &decoded_fdsk {
        let keys = store.keys().context("project keys are not initialized; run `knx-loader --project ... init`")?;
        let id = KeyId { scope: KeyScope::Device(device.to_string()), kind: KeyKind::Fdsk };
        if let Some(existing) = keys.read(&id, None).context("while attempting to check the existing device FDSK")? {
            if existing.value.key16().context("while attempting to decode the existing device FDSK")? != decoded.key {
                bail!("a different FDSK is already stored for device `{device}`");
            }
            if let (Some(project_serial), Some(stored_serial)) = (serial, existing.embedded_serial)
                && project_serial != stored_serial
            {
                bail!(
                    "stored FDSK serial {} disagrees with device serial {}",
                    format_serial(&stored_serial),
                    format_serial(&project_serial)
                );
            }
        }
    }

    let draft = ProjectDeviceDraft {
        id: ProjectDeviceId(device.to_string()),
        product: product_reference,
        catalog_product: imported.catalog_product,
        application_program: imported.application_program,
        language: None,
        address,
        medium,
        serial,
        max_apdu,
        data_secure: if data_secure { DataSecureMode::Enabled } else { DataSecureMode::Disabled },
        parameters: Vec::new(),
        objects: BTreeMap::new(),
        nets: BTreeMap::new(),
    };
    let source =
        store.authored().render_device_add(&draft).context("while attempting to add the device declaration")?;
    let checked = zweidraehte_project::AuthoredProject::parse(source.clone())
        .context("while attempting to parse the updated project")?;
    checked.validate_download().map_err(|error| {
        anyhow::anyhow!(
            "{}",
            error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; ")
        )
    })?;
    // There is no portable atomic rename spanning two files. Persist the
    // credential first so a crash can at worst leave a harmless orphan key;
    // it must never leave an imported secure device without the FDSK the
    // operator supplied. Retrying the same add merges the equal key.
    if let (Some(encoded), Some(decoded)) = (fdsk, decoded_fdsk) {
        let origin = if decoded.serial.is_some() { KeyOrigin::DeviceLabel } else { KeyOrigin::Manual };
        store
            .keys_mut()
            .context("project keys disappeared while adding the device")?
            .put_device_fdsk(device, encoded, origin)
            .context("while attempting to persist the device FDSK")?;
    }
    ProjectStore::write_authored(project_path, Some(store.authored().source()), &source)
        .context("while attempting to persist the updated project")?;

    println!(
        "added {device} at {address} from application {}{}{}",
        imported.program.id,
        serial.as_ref().map_or_else(String::new, |serial| format!(", serial {}", format_serial(serial))),
        fdsk.map_or("", |_| ", FDSK stored")
    );
    Ok(())
}

fn reconcile_certificate_serial(configured: Option<[u8; 6]>, fdsk: Option<&DecodedFdsk>) -> Result<Option<[u8; 6]>> {
    let embedded = fdsk.and_then(|fdsk| fdsk.serial);
    if let (Some(configured), Some(embedded)) = (configured, embedded)
        && configured != embedded
    {
        bail!(
            "device certificate serial {} disagrees with --serial {}",
            format_serial(&embedded),
            format_serial(&configured)
        );
    }
    Ok(configured.or(embedded))
}

struct ImportedProduct {
    program: ApplicationProgram,
    catalog_product: Option<String>,
    application_program: Option<String>,
}

fn select_imported_product(
    path: &Path,
    catalog_product: Option<&str>,
    application: Option<&str>,
) -> Result<ImportedProduct> {
    let is_archive = path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod"));
    if !is_archive {
        if catalog_product.is_some() {
            bail!("--catalog-product applies only to .knxprod archives");
        }
        let (program, _, _) = load::load_program_selected(path, application)
            .with_context(|| format!("while attempting to load loose product {}", path.display()))?;
        return Ok(ImportedProduct { program, catalog_product: None, application_program: None });
    }

    let archive =
        KnxprodArchive::open(path).with_context(|| format!("while attempting to open archive {}", path.display()))?;
    let devices = archive.importable_devices().context("while attempting to read the archive catalogue")?;
    let selected = select_archive_device(path, &devices, catalog_product, application)?;
    let application_program = selected.application_program_id.clone();
    let knx = archive
        .parse_application_program(&application_program)
        .with_context(|| format!("archive has no application program `{application_program}`"))?
        .with_context(|| format!("while attempting to parse application program `{application_program}`"))?;
    let mut programs = knx.manufacturer_data.manufacturer.application_programs.programs;
    let program = match programs.len() {
        1 => programs.remove(0),
        count => bail!("selected application document contains {count} application programs"),
    };
    Ok(ImportedProduct {
        program,
        catalog_product: selected.product_id,
        application_program: Some(application_program),
    })
}

fn select_archive_device(
    path: &Path,
    devices: &[KnxprodDevice],
    catalog_product: Option<&str>,
    application: Option<&str>,
) -> Result<KnxprodDevice> {
    if devices.is_empty() {
        bail!("{} contains no importable device", path.display());
    }
    if let Some(product) = catalog_product {
        return devices
            .iter()
            .find(|device| device.product_id.as_deref() == Some(product))
            .cloned()
            .with_context(|| format!("archive has no catalogue product `{product}`"));
    }
    if let Some(application) = application {
        let matches =
            devices.iter().filter(|device| device.application_program_id == application).cloned().collect::<Vec<_>>();
        return match matches.as_slice() {
            [device] => Ok(device.clone()),
            [] => bail!("archive has no device using application `{application}`"),
            _ => bail!(
                "application `{application}` is used by {} catalogue products; select one with --catalog-product",
                matches.len()
            ),
        };
    }
    if devices.len() == 1 {
        return Ok(devices[0].clone());
    }

    let labels = devices.iter().map(archive_device_label).collect::<Vec<_>>();
    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the KNX product to import")
        .items(&labels)
        .default(0)
        .interact_opt()
        .context("while attempting to show the product selection dialog")?
        .context("product selection cancelled")?;
    Ok(devices[selected].clone())
}

fn archive_device_label(device: &KnxprodDevice) -> String {
    format!(
        "{}{} — {} — {}{}",
        device.name,
        device.order_number.as_ref().map_or_else(String::new, |number| format!(" [{number}]")),
        device.mask_version,
        device.application_program_id,
        if device.supports_data_secure { " — Data Secure" } else { "" }
    )
}

fn relative_path(base: &Path, target: &Path) -> Option<PathBuf> {
    let base = base.components().collect::<Vec<_>>();
    let target = target.components().collect::<Vec<_>>();
    let common = base.iter().zip(&target).take_while(|(left, right)| left == right).count();
    if common == 0 {
        return None;
    }
    let mut relative = PathBuf::new();
    for _ in &base[common..] {
        relative.push("..");
    }
    for component in &target[common..] {
        relative.push(component.as_os_str());
    }
    Some(relative)
}

fn parse_project_serial(value: &str) -> Result<[u8; 6], String> {
    parse_serial(value).map_err(|error| error.to_string())
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
        let desired = &store.authored().devices[id];
        let supports_data_secure = products[id].product.supports_data_secure;
        let deployed = store.state().and_then(|state| state.deployments.get(&id.0));
        let status = if deployed == Some(authored) {
            "current".to_string()
        } else {
            format!("affected ({})", changed_deployment_components(authored, deployed).join(", "))
        };
        let inconsistent =
            store.state().is_some_and(|state| state.inconsistent_devices.iter().any(|candidate| candidate == &id.0));
        let data_secure = match (supports_data_secure, desired.data_secure.is_enabled()) {
            (false, false) => "unsupported",
            (false, true) => "invalid: enabled but unsupported",
            (true, false) => "supported, disabled",
            (true, true) => "supported, enabled",
        };
        println!("{id}: {status}, Data Secure {data_secure}{}", if inconsistent { ", inconsistent batch" } else { "" });
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

fn changed_deployment_components(
    current: &DeploymentFingerprints,
    deployed: Option<&DeploymentFingerprints>,
) -> Vec<&'static str> {
    let Some(deployed) = deployed else { return vec!["never deployed"] };
    [
        (
            current.identity != deployed.identity || current.individual_address != deployed.individual_address,
            "identity",
        ),
        (current.application != deployed.application, "application/product"),
        (current.parameters != deployed.parameters, "parameters"),
        (current.object_flags != deployed.object_flags, "object flags"),
        (current.memberships != deployed.memberships, "memberships"),
        (
            current.net_security != deployed.net_security || current.secured_nets != deployed.secured_nets,
            "net security/key",
        ),
        (
            current.siat_dependencies != deployed.siat_dependencies || current.sender_nets != deployed.sender_nets,
            "SIAT dependencies",
        ),
    ]
    .into_iter()
    .filter_map(|(changed, label)| changed.then_some(label))
    .collect()
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

// ============================================================================
// Explicit ETS keyring import
// ============================================================================

/// Everything checked before either authoritative file is changed.
///
/// In particular, mapping decrypted ETS keys to logical project identities is
/// intentionally separate from persistence. A serial mismatch or ambiguous GA
/// therefore cannot leave a half-imported `keys.toml` behind.
struct KeyringImportPlan {
    records: Vec<KeyRecord>,
    active_epochs: Vec<(KeyId, KeyEpoch)>,
    events: Vec<ProjectEvent>,
    matched_devices: usize,
    matched_groups: usize,
    ignored_devices: usize,
    ignored_groups: usize,
}

fn run_import_keyring(store: &mut ProjectStore, security: &SecurityArgs) -> Result<()> {
    let keyring = security
        .load_keyring()
        .context("while attempting to load the ETS keyring")?
        .context("give --keyring and its password to import-keyring")?;
    let plan = plan_keyring_import(store, &keyring).context("while attempting to reconcile the ETS keyring")?;
    let summary = (plan.matched_devices, plan.matched_groups, plan.ignored_devices, plan.ignored_groups);
    apply_keyring_import(store, plan).context("while attempting to apply the ETS keyring import")?;
    println!(
        "imported or reconciled {} devices and {} group keys; ignored {} unrelated devices and {} unrelated group keys",
        summary.0, summary.1, summary.2, summary.3
    );
    Ok(())
}

fn run_export_keyring(
    store: &ProjectStore,
    security: &SecurityArgs,
    output: &Path,
    project_name: Option<&str>,
) -> Result<()> {
    let keys = store.keys().context("project keys are not initialized; run `knx-loader --project ... init`")?;
    let state = store.state().context("project state is not initialized; run `knx-loader --project ... init`")?;
    let password = security
        .keyring_password()
        .context("give --keyring-password or KNX_KEYRING_PASSWORD to protect the exported keyring")?;
    let default_name = store
        .project_path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("zweidraehte project");
    let created = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .context("while attempting to round the keyring creation time")?
        .format(&time::format_description::well_known::Rfc3339)
        .context("while attempting to format the keyring creation time")?;
    let keyring = build_project_keyring(
        store.authored(),
        state,
        keys,
        project_name.unwrap_or(default_name),
        concat!("zweidraehte knx-loader ", env!("CARGO_PKG_VERSION")),
        created,
    )
    .context("while attempting to collect project keyring material")?;
    let device_count = keyring.devices.len();
    let group_count = keyring.group_keys.len();
    let xml = keyring.to_xml(&password).context("while attempting to encrypt and sign the ETS keyring")?;
    write_new_secret_file(output, xml.as_bytes())
        .with_context(|| format!("while attempting to create keyring {}", output.display()))?;

    println!(
        "exported {device_count} device entries and {group_count} active group keys to {}; client sequence {} remains project-local",
        output.display(),
        state.client_next
    );
    Ok(())
}

fn write_new_secret_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    File::open(parent)?.sync_all()
}

fn apply_keyring_import(store: &mut ProjectStore, plan: KeyringImportPlan) -> Result<()> {
    let lock = store.acquire_lock().context("while attempting to acquire the project lock")?;
    store.begin_mutation(&lock).context("while attempting to open the project journal")?;
    store
        .keys_mut()
        .context("project keys are not initialized; run `knx-loader --project ... init`")?
        .transaction(|transaction| {
            // Create each group with a valid active epoch before adding its
            // first record. A transaction may import several new groups and
            // every intermediate document must remain decodable while later
            // records are conflict-checked.
            for (id, epoch) in plan.active_epochs {
                transaction.set_active_epoch(&id, epoch)?;
            }
            for record in plan.records {
                transaction.put(record)?;
            }
            Ok(())
        })
        .context("while attempting to persist imported key material")?;
    for event in plan.events {
        store.record(event).context("while attempting to persist an imported sequence observation")?;
    }
    store.compact().context("while attempting to compact imported project state")?;
    Ok(())
}

fn plan_keyring_import(store: &ProjectStore, keyring: &Keyring) -> Result<KeyringImportPlan> {
    let keys = store.keys().context("project keys are not initialized; run `knx-loader --project ... init`")?;
    store.state().context("project state is not initialized; run `knx-loader --project ... init`")?;

    let mut records = Vec::new();
    let mut events = Vec::new();
    let mut matched_devices = 0usize;
    let mut matched_keyring_devices = std::collections::BTreeSet::new();
    for device in store.authored().devices.values() {
        let Some((keyring_index, imported)) = select_keyring_device_for_import(device, keyring)? else {
            continue;
        };
        matched_keyring_devices.insert(keyring_index);
        matched_devices += 1;

        let serial = reconcile_imported_serial(device, imported)?;
        if let Some(fdsk) = imported.fdsk {
            records.push(imported_key_record(
                KeyId { scope: KeyScope::Device(device.id.0.clone()), kind: KeyKind::Fdsk },
                None,
                fdsk,
                serial,
            ));
        }
        if let Some(tool_key) = imported.tool_key {
            records.push(imported_key_record(
                KeyId { scope: KeyScope::Device(device.id.0.clone()), kind: KeyKind::ToolKey },
                None,
                tool_key,
                None,
            ));
        }
        if imported.sequence_number > 0
            && let Some(serial) = serial
        {
            let next = imported
                .sequence_number
                .checked_add(1)
                .filter(|next| *next <= 0xFFFF_FFFF_FFFF)
                .context("ETS device sequence number has no representable 48-bit successor")?;
            events.push(ProjectEvent::ObserveDeviceOutgoing { serial: format_serial(&serial), next });
        }
    }

    // An unmanaged sender has no device record in the project. Its keyring
    // sequence is still a useful forward-only SIAT observation when the IA is
    // declared explicitly in `external_sender`.
    for sender in store.authored().external_senders.values() {
        let matches = keyring
            .devices
            .iter()
            .enumerate()
            .filter(|(_, device)| device.individual_address == sender.address)
            .collect::<Vec<_>>();
        let imported = match matches.as_slice() {
            [] => continue,
            [one] => *one,
            _ => bail!("ETS keyring contains multiple devices at external sender address {}", sender.address),
        };
        matched_keyring_devices.insert(imported.0);
        if imported.1.sequence_number > 0 {
            events.push(ProjectEvent::ObserveSender {
                sender: SenderIdentity::UnmanagedAddress(sender.address.to_string()),
                last_valid: imported.1.sequence_number,
            });
        }
    }

    let mut nets_by_address = BTreeMap::new();
    for net in store.authored().nets.values() {
        let raw = u16::from_be_bytes(net.address.0);
        if let Some(previous) = nets_by_address.insert(raw, &net.id) {
            bail!("nets `{previous}` and `{}` use the same group address {}", net.id, net.address);
        }
    }
    let mut active_epochs = Vec::new();
    let mut matched_groups = 0usize;
    for (&address, &key) in &keyring.group_keys {
        let Some(net) = nets_by_address.get(&address) else { continue };
        matched_groups += 1;
        let id = KeyId { scope: KeyScope::Group(net.0.clone()), kind: KeyKind::GroupKey };
        let existing = keys
            .read(&id, None)
            .with_context(|| format!("while attempting to read the active group key for net `{net}`"))?;
        let epoch = existing.as_ref().and_then(|record| record.metadata.epoch).unwrap_or(KeyEpoch(1));
        records.push(imported_key_record(id.clone(), Some(epoch), key, None));
        if existing.is_none() {
            active_epochs.push((id, epoch));
        }
    }

    Ok(KeyringImportPlan {
        records,
        active_epochs,
        events,
        matched_devices,
        matched_groups,
        ignored_devices: keyring.devices.len().saturating_sub(matched_keyring_devices.len()),
        ignored_groups: keyring.group_keys.len().saturating_sub(matched_groups),
    })
}

fn select_keyring_device_for_import<'a>(
    project: &ProjectDevice,
    keyring: &'a Keyring,
) -> Result<Option<(usize, &'a KeyringDevice)>> {
    let matches = match project.serial {
        Some(serial) => {
            keyring.devices.iter().enumerate().filter(|(_, device)| device.serial == Some(serial)).collect::<Vec<_>>()
        }
        None => keyring
            .devices
            .iter()
            .enumerate()
            .filter(|(_, device)| device.individual_address == project.address)
            .collect::<Vec<_>>(),
    };
    match matches.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        _ => bail!(
            "ETS keyring contains multiple matches for project device `{}` ({})",
            project.id,
            project.serial.as_ref().map_or_else(|| project.address.to_string(), format_serial)
        ),
    }
}

fn reconcile_imported_serial(project: &ProjectDevice, imported: &KeyringDevice) -> Result<Option<[u8; 6]>> {
    if let (Some(project_serial), Some(imported_serial)) = (project.serial, imported.serial)
        && project_serial != imported_serial
    {
        bail!(
            "project device `{}` serial {} disagrees with ETS keyring serial {}",
            project.id,
            format_serial(&project_serial),
            format_serial(&imported_serial)
        );
    }
    Ok(project.serial.or(imported.serial))
}

fn imported_key_record(
    id: KeyId,
    epoch: Option<KeyEpoch>,
    key: [u8; 16],
    embedded_serial: Option<[u8; 6]>,
) -> KeyRecord {
    let value = SecretBytes::new(key);
    KeyRecord {
        metadata: KeyMetadata {
            id,
            epoch,
            origin: KeyOrigin::Imported,
            encoding: KeyEncoding::Hex,
            state: KeyState::Active,
            fingerprint: value.fingerprint(),
        },
        value,
        embedded_serial,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_programming(
    store: &mut ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device: Option<String>,
    affected: bool,
    force_single: bool,
    all: bool,
    dry_run: bool,
    force_full: bool,
    program_ia: bool,
    device_mask: Option<MaskVersion>,
    dump_blobs: Option<&Path>,
    scope: ProgrammingScope,
) -> Result<()> {
    let (selected, selection) = programming_selection(device, affected, force_single, all, scope)?;
    let products = load_products(store)?;
    let mask_db = load::load_mask_db(master_data, None)?;
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;

    if dry_run {
        let empty = EmptyKeySource;
        let keys: &dyn KeyMaterialSource = store.keys().map_or(&empty, |keys| keys);
        let mut plan = ProjectProgrammer::new()
            .plan_with_scope(
                store.authored(),
                store.state(),
                &selected,
                selection,
                &products,
                keys,
                keyring.as_ref(),
                scope,
            )
            .context("while attempting to plan the download batch")?;
        force_full_downloads(&mut plan, force_full);
        if plan.devices.is_empty() {
            println!("no affected devices");
            return Ok(());
        }
        for planned in &plan.devices {
            for warning in &planned.warnings {
                eprintln!("warning: {warning}");
            }
            if scope.includes_application() {
                let compiled = compile_offline(planned, &mask_db, device_mask)?;
                print_compiled(planned, &compiled);
                dump_blob_files(dump_blobs, &planned.id.0, &compiled)?;
            } else {
                println!("{}: would commission {}", planned.id, planned.configuration.identity.desired_address);
            }
            if planned.key_material.needs_tool_key_generation {
                if scope == ProgrammingScope::Application {
                    bail!(
                        "device `{}` has no Tool Key; run `knx-loader ... address {}` or `program {}` first",
                        planned.id,
                        planned.id,
                        planned.id
                    );
                }
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
        .plan_with_scope(
            store.authored(),
            store.state(),
            &selected,
            selection,
            &products,
            store.keys().context("project has no keys.toml")?,
            keyring.as_ref(),
            scope,
        )
        .context("while attempting to plan the download batch")?;
    force_full_downloads(&mut plan, force_full);
    if plan.devices.is_empty() {
        println!("no affected devices");
        return Ok(());
    }
    for planned in &plan.devices {
        for warning in &planned.warnings {
            eprintln!("warning: {warning}");
        }
    }
    if scope == ProgrammingScope::Application
        && let Some(planned) = plan.devices.iter().find(|device| device.key_material.needs_tool_key_generation)
    {
        bail!(
            "device `{}` has no Tool Key; run `knx-loader ... address {}` or `program {}` first",
            planned.id,
            planned.id,
            planned.id
        );
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
        scope,
        addressing: if program_ia { AddressingMode::ProgrammingButton } else { AddressingMode::Automatic },
        ..ProgrammingOptions::default()
    };
    let preflight = ProjectProgrammer::new()
        .preflight_batch(&bus, &mask_db, &mut plan, options.clone())
        .await
        .context("while attempting to preflight the complete affected batch")?;
    for (planned, report) in plan.devices.iter().zip(preflight) {
        if let Some(reason) = &report.partial_fallback_reason {
            eprintln!("warning: {} cannot use a partial download ({reason}); using full", planned.id);
        }
        match report.compiled {
            Some(compiled) => println!(
                "preflight {}: current {}, device mask {}, {:?} scope, {} instructions",
                planned.id,
                report.current_address,
                report.device_mask,
                compiled.scope(),
                compiled.instructions.len()
            ),
            None => println!(
                "preflight {}: current {}, device mask {}, network configuration only",
                planned.id, report.current_address, report.device_mask
            ),
        }
    }
    let mut successful = Vec::new();
    let mut failure = None;
    for planned in &plan.devices {
        println!("{} {} ({})", scope_action(scope), planned.id, planned.configuration.identity.desired_address);
        let request = ProgrammingRequest {
            mask_db: &mask_db,
            product: &planned.product,
            configuration: &planned.configuration,
            key_material: planned.key_material.clone(),
            download_scope: planned.download_scope,
            previous_mcb: planned.previous_mcb.clone(),
            options: options.clone(),
        };
        match DeviceProgrammer::new().program_with_progress(&bus, request, None, Box::new(print_progress)).await {
            Ok(report) => {
                println!(
                    "{}: {} at {}, mask {}{}",
                    planned.id,
                    scope_completed(scope),
                    report.individual_address,
                    report.device_mask,
                    if report.application_downloaded {
                        format!(", {} instructions", report.instruction_count)
                    } else {
                        String::new()
                    }
                );
                if report.application_downloaded {
                    record_success(&shared, planned, &report)?;
                }
                successful.push(planned.id.0.clone());
            }
            Err(error) => {
                failure = Some(anyhow::Error::new(error).context(format!(
                    "while attempting to {} {}",
                    scope_action(scope),
                    planned.id
                )));
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
        // Preserve the original error chain. Formatting `anyhow::Error` into
        // a new string here used to discard the actual verification failure,
        // leaving hardware runs with only the outer batch context.
        return Err(error.context(format!("successful devices before the batch stopped: {}", successful.join(", "))));
    }
    bus.disconnect().await.context("while attempting to disconnect")?;
    shared
        .lock()
        .map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?
        .compact()
        .context("while attempting to compact project state")?;
    println!("{} {} devices", scope_completed(scope), successful.len());
    Ok(())
}

fn programming_selection(
    device: Option<String>,
    affected: bool,
    force_single: bool,
    all: bool,
    scope: ProgrammingScope,
) -> Result<(Vec<ProjectDeviceId>, BatchSelection)> {
    if let Some(device) = device {
        if all {
            bail!("a device identifier cannot be combined with --all");
        }
        return Ok((vec![ProjectDeviceId(device)], BatchSelection::Selected {
            include_affected: affected,
            force_single,
        }));
    }
    if all {
        return Ok((
            Vec::new(),
            if scope == ProgrammingScope::Address { BatchSelection::All } else { BatchSelection::AllStale },
        ));
    }
    if force_single {
        bail!("--force-single requires a device identifier");
    }
    if !affected {
        bail!("give a device identifier or use --affected");
    }
    Ok((Vec::new(), BatchSelection::AllStale))
}

fn scope_action(scope: ProgrammingScope) -> &'static str {
    match scope {
        ProgrammingScope::Address => "commissioning",
        ProgrammingScope::Application => "loading",
        ProgrammingScope::AddressAndApplication => "programming",
    }
}

fn scope_completed(scope: ProgrammingScope) -> &'static str {
    match scope {
        ProgrammingScope::Address => "commissioned",
        ProgrammingScope::Application => "loaded",
        ProgrammingScope::AddressAndApplication => "programmed",
    }
}

fn record_success(
    store: &Arc<Mutex<ProjectStore>>,
    planned: &zweidraehte_client::PlannedProjectDevice,
    report: &zweidraehte_client::ProgrammingReport,
) -> Result<()> {
    let mut store = store.lock().map_err(|_| anyhow::anyhow!("project-store lock is poisoned"))?;
    store
        .record(ProjectEvent::RecordDeployment {
            device: planned.id.0.clone(),
            fingerprints: planned.fingerprints.clone(),
            mcb: report.mcb_snapshots.clone(),
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
        match connect_management_synchronized(&bus, current, &planned.key_material, false).await {
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
        let (program, _, _) = load::load_program_selection(
            &path,
            device.catalog_product.as_deref(),
            device.application_program.as_deref(),
        )
        .with_context(|| {
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
    product.configured_com_objects = Some(lowered.com_objects);
    compile_scoped(&mask, &product, &lowered.project, planned.download_scope)
        .context("while attempting to compile the planned download")
}

fn print_compiled(
    planned: &zweidraehte_client::PlannedProjectDevice,
    compiled: &zweidraehte_client::download::CompiledDownload,
) {
    println!(
        "{}: {}, {:?} scope, {} parameters, {} associations, {} instructions",
        planned.id,
        planned.configuration.identity.desired_address,
        compiled.scope(),
        planned.configuration.parameters.len(),
        planned.configuration.object_memberships.len(),
        compiled.instructions.len()
    );
    for (address, bytes) in compiled.image.regions() {
        println!("  region {address:#06X}: {} bytes", bytes.len());
    }
}

fn force_full_downloads(plan: &mut zweidraehte_client::ProgrammingBatchPlan, force_full: bool) {
    if force_full {
        for device in &mut plan.devices {
            device.download_scope = DownloadScope::Full;
        }
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
    for (object, bytes) in compiled.image.relative_objects() {
        let path = directory.join(format!("relative_object_{object:02X}.bin"));
        std::fs::write(&path, bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
    }
    Ok(())
}

fn print_progress(event: ProgrammingEvent) {
    match event {
        ProgrammingEvent::Stage(stage) => println!("  {}", stage_name(stage)),
        ProgrammingEvent::Download(event) => println!("    {event:?}"),
        ProgrammingEvent::FallingBackToFullDownload { reason } => {
            println!("  partial load failed ({reason}); falling back to full download");
        }
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
        ProgrammingStage::EnablingSecurityMode => "enabling Security Mode",
        ProgrammingStage::InstallingToolKey => "installing tool key",
        ProgrammingStage::RestartingSecurityBootstrap => "restarting after security bootstrap",
        ProgrammingStage::SettingDeviceSequence => "setting PID 59",
        ProgrammingStage::Downloading => "downloading",
        ProgrammingStage::RestartingDevice => "restarting device",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn archive_device(product: &str, application: &str) -> KnxprodDevice {
        KnxprodDevice {
            catalog_item_id: None,
            product_id: Some(product.into()),
            hardware_id: None,
            application_program_id: application.into(),
            name: product.into(),
            order_number: None,
            mask_version: "MV-0705".into(),
            supports_data_secure: false,
        }
    }

    #[test]
    fn application_selector_rejects_shared_catalogue_programs() {
        let devices = [archive_device("product-a", "application"), archive_device("product-b", "application")];
        let error = select_archive_device(Path::new("products.knxprod"), &devices, None, Some("application"))
            .expect_err("a shared application does not identify a saleable product");
        assert!(error.to_string().contains("select one with --catalog-product"));
        let selected = select_archive_device(Path::new("products.knxprod"), &devices, Some("product-b"), None)
            .expect("the catalogue product is unambiguous");
        assert_eq!(selected.product_id.as_deref(), Some("product-b"));
    }

    #[test]
    fn imported_product_paths_are_relative_to_the_project() {
        assert_eq!(
            relative_path(Path::new("/work/project"), Path::new("/work/products/switch.knxprod")),
            Some(PathBuf::from("../products/switch.knxprod"))
        );
    }

    #[test]
    fn cli_exposes_separate_address_load_and_combined_operations() {
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "address", "button", "--program-ia"])
                .expect("address command parses")
                .command,
            Command::Address { program_ia: true, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "load", "button"]).expect("application command parses").command,
            Command::Load { .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "program", "button", "--program-ia"])
                .expect("combined command parses")
                .command,
            Command::Program { program_ia: true, .. }
        ));
        assert!(Args::try_parse_from(["knx-loader", "load", "button", "--program-ia"]).is_err());
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "load", "button", "--full"])
                .expect("full application command parses")
                .command,
            Command::Load { full: true, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "program", "button", "--full"])
                .expect("full combined command parses")
                .command,
            Command::Program { full: true, .. }
        ));
    }

    #[test]
    fn cli_exposes_project_wide_affected_programming() {
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "program", "--affected"])
                .expect("project-wide affected command parses")
                .command,
            Command::Program { device: None, affected: true, all: false, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "load", "--affected"])
                .expect("project-wide affected load parses")
                .command,
            Command::Load { device: None, affected: true, all: false, .. }
        ));
        assert!(Args::try_parse_from(["knx-loader", "program", "--affected", "--all"]).is_err());

        let (selected, selection) =
            programming_selection(None, true, false, false, ProgrammingScope::AddressAndApplication)
                .expect("affected selection resolves");
        assert!(selected.is_empty());
        assert_eq!(selection, BatchSelection::AllStale);

        let (selected, selection) =
            programming_selection(Some("button".into()), true, false, false, ProgrammingScope::AddressAndApplication)
                .expect("selected closure resolves");
        assert_eq!(selected, [ProjectDeviceId("button".into())]);
        assert_eq!(selection, BatchSelection::Selected { include_affected: true, force_single: false });
    }

    #[test]
    fn status_names_siat_only_changes() {
        let deployed = DeploymentFingerprints { siat_dependencies: "old".into(), ..Default::default() };
        let current = DeploymentFingerprints { siat_dependencies: "new".into(), ..Default::default() };
        assert_eq!(changed_deployment_components(&current, Some(&deployed)), ["SIAT dependencies"]);
    }

    #[test]
    fn device_certificate_supplies_and_reconciles_the_serial() {
        let decoded = parse_fdsk("AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX").expect("certificate parses");
        assert_eq!(
            reconcile_certificate_serial(None, Some(&decoded)).expect("embedded serial is accepted"),
            Some([0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF])
        );
        let error = reconcile_certificate_serial(Some([0; 6]), Some(&decoded))
            .expect_err("a conflicting explicit serial is rejected");
        assert!(error.to_string().contains("disagrees with --serial"));
    }

    #[test]
    fn keyring_import_persists_project_keys_and_forward_sequence_observations() {
        const PROJECT: &str = r#"
ga secure = 0/0/1
ga secure_2 = 0/0/2
net secure : 1.001 { security authentication_confidentiality }
net secure_2 : 1.001 { security authentication_confidentiality }
external_sender visualisation {
    address 1.1.250
    data_secure enabled
    on secure
}
area 1 bench {
    line 1 main {
        medium tp1
        device button {
            product local:"button.mtxml"
            address 1.1.10
            serial "00FA:00000001"
            data_secure enabled
            object 0 { on secure }
        }
    }
}
"#;
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT).expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store.initialize().expect("project initializes");

        let fdsk = [0x11; 16];
        let tool_key = [0x22; 16];
        let group_key = [0x33; 16];
        let second_group_key = [0x44; 16];
        let keyring = Keyring {
            project: "test".into(),
            created_by: "test".into(),
            created: "test".into(),
            backbone: None,
            interfaces: Vec::new(),
            group_keys: BTreeMap::from([(1, group_key), (2, second_group_key)]),
            devices: vec![
                KeyringDevice {
                    // Matching is deliberately by serial, not the stale IA.
                    individual_address: zweidraehte_client::IndividualAddress::new(1, 1, 99),
                    tool_key: Some(tool_key),
                    fdsk: Some(fdsk),
                    serial: Some([0x00, 0xFA, 0, 0, 0, 1]),
                    sequence_number: 123,
                    management_password: None,
                    authentication: None,
                },
                KeyringDevice {
                    individual_address: zweidraehte_client::IndividualAddress::new(1, 1, 250),
                    tool_key: None,
                    fdsk: None,
                    serial: None,
                    sequence_number: 456,
                    management_password: None,
                    authentication: None,
                },
            ],
        };

        let plan = plan_keyring_import(&store, &keyring).expect("keyring reconciles");
        assert_eq!((plan.matched_devices, plan.matched_groups), (1, 2));
        apply_keyring_import(&mut store, plan).expect("keyring import persists");
        drop(store);

        let store = ProjectStore::open(&project_path).expect("project reopens");
        let keys = store.keys().expect("keys exist");
        let device_scope = KeyScope::Device("button".into());
        assert_eq!(
            keys.read(&KeyId { scope: device_scope.clone(), kind: KeyKind::Fdsk }, None)
                .expect("FDSK reads")
                .expect("FDSK exists")
                .value
                .key16()
                .expect("FDSK has key width"),
            fdsk
        );
        assert_eq!(
            keys.read(&KeyId { scope: device_scope, kind: KeyKind::ToolKey }, None)
                .expect("tool key reads")
                .expect("tool key exists")
                .value
                .key16()
                .expect("tool key has key width"),
            tool_key
        );
        assert_eq!(
            keys.read(&KeyId { scope: KeyScope::Group("secure".into()), kind: KeyKind::GroupKey }, None)
                .expect("group key reads")
                .expect("group key exists")
                .value
                .key16()
                .expect("group key has key width"),
            group_key
        );
        assert_eq!(
            keys.read(&KeyId { scope: KeyScope::Group("secure_2".into()), kind: KeyKind::GroupKey }, None)
                .expect("second group key reads")
                .expect("second group key exists")
                .value
                .key16()
                .expect("second group key has key width"),
            second_group_key
        );
        let state = store.state().expect("state exists");
        assert_eq!(state.devices["00FA:00000001"].outgoing_next, 124);
        assert_eq!(state.sender_floors[&SenderIdentity::UnmanagedAddress("1.1.250".into())], 456);

        let output = directory.path().join("roundtrip.knxkeys");
        let args = Args::try_parse_from([
            "knx-loader",
            "--keyring-password",
            "secret",
            "export-keyring",
            "--out",
            output.to_str().expect("temporary path is UTF-8"),
        ])
        .expect("export command parses");
        let Command::ExportKeyring { out, name } = args.command else {
            panic!("export command expected");
        };
        run_export_keyring(&store, &args.security, &out, name.as_deref()).expect("project keyring exports");
        let exported = Keyring::load(&output, "secret").expect("project keyring imports again");
        assert_eq!(exported.group_keys[&1], group_key);
        assert_eq!(exported.group_keys[&2], second_group_key);
        assert_eq!(
            exported
                .devices
                .iter()
                .find(|device| device.serial == Some([0x00, 0xFA, 0, 0, 0, 1]))
                .expect("managed device exports")
                .sequence_number,
            123
        );
        let error = run_export_keyring(&store, &args.security, &out, name.as_deref())
            .expect_err("an existing secret file is not replaced");
        assert!(error.to_string().contains("create keyring"));
    }
}
