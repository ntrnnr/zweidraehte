//! Drive a real device's configuration: download a mods file, unload
//! back to a clean slate, or read the configured blobs out of the
//! device for comparison.
//!
//! ```text
//! # inspect what would be written
//! knx-loader -p vendor.xml load --mods mods.toml --dry-run --dump-blobs out/
//!
//! # assign the address (programming button) and download
//! knx-loader -p vendor.xml --server 192.168.1.10:3671 load --mods mods.toml --program-ia
//!
//! # clean slate: run the mask's Unload-all
//! knx-loader -p vendor.xml --server 192.168.1.10:3671 unload --ia 1.1.60
//!
//! # dump what the device actually holds (e.g. after an ETS download,
//! # to cross-check our own blob generation against ETS's)
//! knx-loader -p vendor.xml --server 192.168.1.10:3671 read --ia 1.1.60 --out ets-blobs/
//! ```
//!
//! The bus-target and product flags are global and precede the
//! subcommand.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use knx_config::load;
use zweidraehte_client::cli::{BusTarget, OptionalTargetArgs, SecurityArgs, parse_ia};
use zweidraehte_client::download::{
    DeviceConfiguration, DeviceIdentity, DeviceImage, DownloadModel, Downloader, LoadControlPath, MaskData, MaskDb,
    ProcedureKind, ProductData, assemble, compile, load_control_path, resolve_mods, select_download_mask,
};
use zweidraehte_client::security::{ModsFileKeyStore, ResolvedKeyMaterial, parse_serial, resolve_key_material};
use zweidraehte_client::{
    AddressingMode, DeviceProgrammer, IndividualAddress, KnxBus, MaskVersion, ProgrammingEvent, ProgrammingOptions,
    ProgrammingRequest, ProgrammingStage, connect_management,
};
use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::mods::{DeviceMods, apply_mods};

/// Configure, unload, or dump a KNX device from its product file.
#[derive(Parser)]
struct Args {
    /// The product: a loose MTXML application program or a .knxprod
    #[arg(short, long)]
    product: PathBuf,

    /// knx_master.xml; defaults to the archive's bundled copy, the
    /// KNX_MASTER_DATA env var, or the on-disk cache/download
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
    /// Compile a mods file into the download image and load it
    Load {
        /// The mods file (see knx-dump for producing one)
        #[arg(short, long)]
        mods: PathBuf,

        /// Override the mods file's `[device] individual_address`
        #[arg(long, value_parser = parse_ia)]
        ia: Option<IndividualAddress>,

        /// Write the device's individual address first (the device
        /// must be in programming mode — press its button when asked)
        #[arg(long)]
        program_ia: bool,

        /// Compile and report, but do not touch a bus
        #[arg(long)]
        dry_run: bool,

        /// Also write each compiled memory region to <DIR>/region_XXXX.bin
        #[arg(long, value_name = "DIR")]
        dump_blobs: Option<PathBuf>,

        /// Compile as if the device answered this DD0 (hex mask code,
        /// e.g. 0020) — for previewing a downward-compatible download
        /// offline. Live runs read the real DD0 instead.
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
    },

    /// Run the mask's Unload-all procedure — a clean slate: tables
    /// invalidated, application unloaded, the IA kept
    Unload {
        /// The device's individual address (or take it from --mods)
        #[arg(long, value_parser = parse_ia)]
        ia: Option<IndividualAddress>,

        /// A mods file to take the address from instead of --ia
        #[arg(short, long)]
        mods: Option<PathBuf>,

        /// The device's APDU capacity; read from the device
        /// (PID_MAX_APDULENGTH) and bounded by the interface when
        /// omitted
        #[arg(long)]
        max_apdu: Option<u16>,
    },

    /// Read every addressed segment out of the device into
    /// <DIR>/region_XXXX.bin — what the device *actually* holds, for
    /// comparing an ETS-written configuration against our own
    Read {
        /// The device's individual address (or take it from --mods)
        #[arg(long, value_parser = parse_ia)]
        ia: Option<IndividualAddress>,

        /// A mods file to take the address from instead of --ia
        #[arg(short, long)]
        mods: Option<PathBuf>,

        /// Where the region files go
        #[arg(short, long, value_name = "DIR")]
        out: PathBuf,

        /// The device's APDU capacity; read from the device
        /// (PID_MAX_APDULENGTH) and bounded by the interface when
        /// omitted
        #[arg(long)]
        max_apdu: Option<u16>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Every action starts from the same offline facts: the product
    // and the master data. Which *mask* the download is compiled for
    // is decided against the live device (its DD0), the way ETS does
    // — a BCU2 answering 0020 runs a BCU1 (0012) product through the
    // BCU2 procedure. The offline paths use the product's mask.
    let (program, _translations, archive) = load::load_program(&args.product)?;
    let product = ProductData::from_program(&program).context("while attempting to extract the product data")?;
    let mask_db = load::load_mask_db(args.master_data.as_deref(), archive.as_ref())?;

    match args.command {
        Command::Load { mods, ia, program_ia, dry_run, dump_blobs, device_mask } => {
            let device_mask = device_mask
                .as_deref()
                .map(|hex| {
                    u16::from_str_radix(hex.trim_start_matches("0x"), 16)
                        .map(MaskVersion::from)
                        .map_err(|_| anyhow::anyhow!("--device-mask wants a hex mask code such as 0020"))
                })
                .transpose()?;
            run_load(
                &args.target,
                &args.security,
                program,
                product,
                &mask_db,
                &mods,
                ia,
                program_ia,
                dry_run,
                dump_blobs.as_deref(),
                device_mask,
            )
            .await
        }
        Command::Unload { ia, mods, max_apdu } => {
            run_unload(&args.target, &args.security, &product, &mask_db, ia, mods.as_deref(), max_apdu).await
        }
        Command::Read { ia, mods, out, max_apdu } => {
            run_read(&args.target, &args.security, &product, ia, mods.as_deref(), max_apdu, &out).await
        }
    }
}

/// The device's DD0 (mask version), read over a short configuration
/// connection — what everything mask-shaped is selected by.
async fn read_device_mask(bus: &KnxBus, ia: IndividualAddress) -> Result<MaskVersion> {
    let mut connection = bus.connect_device(ia).await.context("while attempting to connect for the DD0 read")?;
    let descriptor = connection.device_descriptor_read(0).await;
    let _ = connection.close().await;
    let descriptor = descriptor.context("while attempting to read the device descriptor")?;
    let [hi, lo] = descriptor[..] else {
        bail!("DD0 answered {} octets, expected 2", descriptor.len());
    };
    Ok(MaskVersion::from(u16::from_be_bytes([hi, lo])))
}

/// ETS's NegotiateMaxApduLength: the device's `PID_MAX_APDULENGTH`
/// (object 0, PID 56) bounded by the interface's own capacity. A
/// device that does not answer the read gets the TP1 standard-frame
/// 15 — correct for anything old enough to lack the property. A mask
/// whose model has no properties at all (BCU1) skips the probe: the
/// timeout would buy nothing the model does not already know.
async fn negotiate_max_apdu_on(
    connection: &mut zweidraehte_client::DeviceConnection,
    interface_max: u16,
    configured: Option<u16>,
    model: Option<&DownloadModel>,
) -> u16 {
    if let Some(configured) = configured {
        let negotiated = configured.min(interface_max).max(15);
        println!("Max APDU:    configured {configured}, interface {interface_max}, using {negotiated}");
        return negotiated;
    }
    if let Some(model) = model
        && !model.has_properties
    {
        println!(
            "Max APDU:    this mask has no PID_MAX_APDULENGTH; using the standard frame's {}",
            model.default_max_apdu
        );
        return model.default_max_apdu.min(interface_max).max(15);
    }
    match connection.property_read(0, zweidraehte_client::pid::device::MAX_APDU_LENGTH, 1, 1).await {
        Ok(bytes) => {
            let device = bytes.iter().fold(0u16, |acc, &b| (acc << 8) | u16::from(b));
            let negotiated = device.min(interface_max).max(15);
            println!("Max APDU:    device {device}, interface {interface_max}, using {negotiated}");
            negotiated
        }
        Err(e) => {
            println!("Max APDU:    device does not answer PID 56 ({e}); using the standard frame's 15");
            15
        }
    }
}

/// Prepare read/unload access. A serial may locate the current IA, but these
/// operations deliberately never assign or move it.
async fn connect_for_management_operation(
    target: &OptionalTargetArgs,
    security_args: &SecurityArgs,
    explicit_ia: Option<IndividualAddress>,
    mods_path: Option<&std::path::Path>,
) -> Result<(KnxBus, IndividualAddress, ResolvedKeyMaterial)> {
    let mut mods = match mods_path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("while attempting to read {}", path.display()))?;
            toml::from_str::<DeviceMods>(&text)
                .with_context(|| format!("while attempting to parse {}", path.display()))?
        }
        None => DeviceMods::default(),
    };
    let desired = match explicit_ia {
        Some(address) => {
            mods.device.individual_address = address.to_string();
            address
        }
        None if mods_path.is_some() => parse_ia(&mods.device.individual_address).map_err(anyhow::Error::msg)?,
        None => bail!("give --ia, or --mods to take the address from"),
    };
    let serial = mods
        .device
        .serial_number
        .as_deref()
        .map(parse_serial)
        .transpose()
        .context("while attempting to parse the device serial number")?;
    let configuration = DeviceConfiguration {
        identity: DeviceIdentity { desired_address: desired, serial_number: serial },
        parameters: Vec::new(),
        object_memberships: Vec::new(),
        objects: Vec::new(),
        net_security: std::collections::BTreeMap::new(),
        max_apdu: mods.device.max_apdu,
    };
    let keyring = security_args.load_keyring().context("while attempting to load the ETS keyring")?;
    let keys = resolve_key_material(&configuration, &mods, keyring.as_ref(), false)
        .context("while attempting to resolve management credentials")?;
    let prepared =
        security_args.prepare_with_keyring(keyring).context("while attempting to prepare secure sequence state")?;
    let Some(target): Option<BusTarget> = target.to_target() else {
        bail!("give --server or --usb (before the subcommand)");
    };
    let bus = target.connect_with_security(prepared.store).await.context("while attempting to connect to the bus")?;

    let address = if let Some(serial) = keys.serial_number {
        let found = bus
            .network_management()
            .read_individual_addresses_by_serial(&serial, Duration::from_secs(2))
            .await
            .context("while attempting to locate the device by serial number")?;
        match found.as_slice() {
            [address] => *address,
            [] => desired,
            _ => bail!("{} devices answered for the same serial number", found.len()),
        }
    } else {
        desired
    };
    Ok((bus, address, keys))
}

/// Match the product to a mask (the device's DD0, or the product's
/// own for offline compiles), with the loader's error framing.
fn select_mask<'a>(db: &'a MaskDb, product_mask: MaskVersion, device_mask: MaskVersion) -> Result<MaskData<'a>> {
    select_download_mask(db, product_mask, device_mask)
        .context("while attempting to match the product to the device's mask")
}

/// The compiled-download summary both the dry-run and the live path
/// print.
fn print_compiled(
    mask: &MaskData<'_>,
    product: &ProductData,
    resolved: &zweidraehte_client::download::ResolvedProject,
    ia: IndividualAddress,
    compiled: &zweidraehte_client::download::CompiledDownload,
) {
    println!("Product:     {}", product.id);
    println!("Mask:        {:?} ({} path)", mask.version(), match compiled.path() {
        LoadControlPath::Memory(_) => "memory",
        LoadControlPath::Property => "property",
        LoadControlPath::Direct => "direct",
    });
    println!("Address:     {ia}");
    println!("Parameters:  {} values patched", resolved.project.parameters.len());
    println!("Links:       {} associations", resolved.project.links.len());
    println!("Objects:     {} in the group object table", product.com_objects.len());
    for (address, bytes) in compiled.image.regions() {
        println!("Region:      {address:#06X}, {} bytes", bytes.len());
    }
    println!("Procedure:   {} instructions", compiled.instructions.len());
}

fn dump_blob_files(
    dir: Option<&std::path::Path>,
    compiled: &zweidraehte_client::download::CompiledDownload,
) -> Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    std::fs::create_dir_all(dir).with_context(|| format!("while attempting to create {}", dir.display()))?;
    for (address, bytes) in compiled.image.regions() {
        let path = dir.join(format!("region_{address:04X}.bin"));
        std::fs::write(&path, bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
        println!("Wrote {}", path.display());
    }
    Ok(())
}

// ============================================================================
// load
// ============================================================================

#[allow(clippy::too_many_arguments)] // the subcommand's flags, passed through once
async fn run_load(
    target: &OptionalTargetArgs,
    security_args: &SecurityArgs,
    program: zweidraehte_knxprod::schema::ApplicationProgram,
    product: ProductData,
    mask_db: &zweidraehte_client::download::MaskDb,
    mods_path: &std::path::Path,
    ia_override: Option<IndividualAddress>,
    program_ia: bool,
    dry_run: bool,
    dump_blobs: Option<&std::path::Path>,
    device_mask: Option<MaskVersion>,
) -> Result<()> {
    let mods_text = std::fs::read_to_string(mods_path)
        .with_context(|| format!("while attempting to read {}", mods_path.display()))?;
    let mut mods: DeviceMods =
        toml::from_str(&mods_text).with_context(|| format!("while attempting to parse {}", mods_path.display()))?;
    // --ia trumps the file: the TUI export leaves a placeholder, and
    // an override also lets one mods file serve several devices.
    if let Some(ia) = ia_override {
        mods.device.individual_address = ia.to_string();
    }

    let mut device = Device::new(program, None, None);
    apply_mods(&mut device, &mods).context("while attempting to apply the mods file")?;
    let resolved = resolve_mods(&device, &mods, &product).context("while attempting to resolve the configuration")?;
    let product_mask = product.mask_version.context("the product names no mask version")?;
    let ia = parse_ia(&mods.device.individual_address).map_err(anyhow::Error::msg)?;

    // Key-source conflicts and security-policy errors are preflighted before
    // the sequence store, connector, or device is touched.
    let keyring = security_args.load_keyring().context("while attempting to load the ETS keyring")?;
    let key_material =
        resolve_key_material(&resolved.configuration, &mods, keyring.as_ref(), product.is_secure_enabled)
            .context("while attempting to resolve security material")?;

    // Offline: compile for the product's own mask, or for the DD0 the
    // user claims with --device-mask.
    if dry_run {
        let mask = select_mask(mask_db, product_mask, device_mask.unwrap_or(product_mask))?;
        let lowered = resolved
            .configuration
            .lower(key_material.application_security.clone())
            .context("while attempting to lower the configuration")?;
        let mut compiled_product = product.clone();
        compiled_product.com_objects = lowered.com_objects;
        let compiled =
            compile(&mask, &compiled_product, &lowered.project).context("while attempting to compile the download")?;
        let mut rendered = resolved.clone();
        rendered.project = lowered.project;
        rendered.com_objects = compiled_product.com_objects.clone();
        print_compiled(&mask, &compiled_product, &rendered, ia, &compiled);
        dump_blob_files(dump_blobs, &compiled)?;

        if key_material.needs_tool_key_generation {
            println!("Tool key:    would generate and persist one before bus access");
        }

        println!("\nDry run — parameter patches:");
        for value in &rendered.project.parameters {
            let location = compiled_product.parameters.iter().find(|l| l.id == value.id);
            let hex: String = value.value.iter().map(|b| format!("{b:02X}")).collect();
            match location {
                Some(l) => println!(
                    "  {} @ {}+{}:{} ({} bits) = {hex}",
                    value.id, l.code_segment, l.offset, l.bit_offset, l.size_bits
                ),
                None => println!("  {} (no location!) = {hex}", value.id),
            }
        }
        println!("\nDry run — the procedure that would execute:");
        for instruction in &compiled.instructions {
            println!("  {instruction:?}");
        }
        return Ok(());
    }

    if program_ia {
        println!("\nPress the programming button on exactly one target device.");
    }

    let Some(bus_target): Option<BusTarget> = target.to_target() else {
        bail!("give --server or --usb (before the subcommand)");
    };
    let prepared =
        security_args.prepare_with_keyring(keyring).context("while attempting to prepare secure sequence state")?;
    let bus =
        bus_target.connect_with_security(prepared.store).await.context("while attempting to connect to the bus")?;
    let mut mods_store = ModsFileKeyStore::open(mods_path).context("while attempting to open the mods key store")?;
    let options = ProgrammingOptions {
        addressing: if program_ia { AddressingMode::ProgrammingButton } else { AddressingMode::Automatic },
        ..ProgrammingOptions::default()
    };
    let report = DeviceProgrammer::new()
        .program_with_progress(
            &bus,
            ProgrammingRequest {
                mask_db,
                product: &product,
                configuration: &resolved.configuration,
                key_material,
                options,
            },
            Some(&mut mods_store),
            Box::new(|event| match event {
                ProgrammingEvent::Stage(stage) => println!("{}…", stage_label(stage)),
                ProgrammingEvent::Download(zweidraehte_client::download::DownloadEvent::Step {
                    index,
                    total,
                    description,
                }) => println!("  [{}/{total}] {description}", index + 1),
                ProgrammingEvent::Download(zweidraehte_client::download::DownloadEvent::Data { .. }) => {}
            }),
        )
        .await
        .context("while attempting to program the device")?;
    if product_mask != report.device_mask {
        println!("Device:      {:?} running product {:?}", report.device_mask, product_mask);
    }
    println!("Address:     {}", report.individual_address);
    println!("Access:      {:?}", report.management_access);
    println!("Max APDU:    {}", report.max_apdu);
    println!("Procedure:   {} instructions", report.instruction_count);
    if report.load_states.is_empty() {
        println!("Load states: none");
    } else {
        let states: Vec<_> = report.load_states.iter().map(|(target, state)| format!("{target}={state}")).collect();
        println!("Load states: [{}]", states.join(", "));
    }
    if let Some(security) = report.security {
        println!(
            "Security:    enabled; {} group keys, {} senders, {} GO flags",
            security.group_key_entries, security.sender_entries, security.group_object_entries
        );
    }
    if let Some(directory) = dump_blobs {
        std::fs::create_dir_all(directory)
            .with_context(|| format!("while attempting to create {}", directory.display()))?;
        for (address, bytes) in report.programmed_image.regions() {
            let path = directory.join(format!("region_{address:04X}.bin"));
            std::fs::write(&path, bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
            println!("Wrote {}", path.display());
        }
    }
    bus.disconnect().await.context("while attempting to disconnect")?;
    println!("Done.");
    Ok(())
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

// ============================================================================
// unload
// ============================================================================

async fn run_unload(
    target: &OptionalTargetArgs,
    security_args: &SecurityArgs,
    product: &ProductData,
    mask_db: &MaskDb,
    explicit_ia: Option<IndividualAddress>,
    mods_path: Option<&std::path::Path>,
    max_apdu: Option<u16>,
) -> Result<()> {
    let product_mask = product.mask_version.context("the product names no mask version")?;
    let (bus, ia, keys) = connect_for_management_operation(target, security_args, explicit_ia, mods_path).await?;

    // An unload is entirely the mask's business, and the mask is the
    // *device's*: a BCU2 carrying a BCU1 product still tears down
    // through the BCU2 Unload template.
    let dd0 = read_device_mask(&bus, ia).await?;
    let mask = select_mask(mask_db, product_mask, dd0)?;
    if mask.version() != product_mask {
        println!("Device:      {dd0:?} — unloading through its own procedure");
    }

    // The Unload template comes from the mask; the product only
    // contributes merge fragments where the family has them (System
    // B), so the real product is the right second argument even for a
    // teardown.
    let instructions =
        assemble(&mask, product, ProcedureKind::UnloadAll).context("while attempting to assemble Unload-all")?;
    let path = load_control_path(&mask)?;

    let model = DownloadModel::for_management_model(mask.management_model());
    println!("Unloading {ia} ({} instructions)…", instructions.len());
    let (mut connection, access) =
        connect_management(&bus, ia, &keys, true).await.context("while attempting to select management access")?;
    println!("Access:      {access:?}");
    let max_apdu = negotiate_max_apdu_on(&mut connection, bus.max_apdu(), max_apdu, model).await;
    let result = async {
        let mut downloader = Downloader::with_path(&mut connection, path, max_apdu);
        if let Some(model) = model {
            if !model.authorize_on_connect {
                downloader = downloader.without_authorize();
            }
            if model.diff_writes {
                downloader = downloader.with_diffed_writes();
            }
        }
        downloader
            .run(&instructions, &DeviceImage::new())
            .await
            .context("while attempting to run the unload procedure")?;

        // Show the clean slate — Unloaded (00h) on every machine.
        if path == LoadControlPath::Direct {
            println!("Load states: none — this mask has no load state machines");
        } else {
            let machines = mask.lsm_model().machines.len().max(1);
            let states = read_states_on(&mut connection, path, machines).await?;
            let rendered: Vec<String> = states.iter().map(|s| format!("{s:02X}")).collect();
            println!("Load states: [{}] (00 = Unloaded)", rendered.join(" "));
        }
        Ok(())
    }
    .await;
    let _ = connection.close().await;
    bus.disconnect().await.context("while attempting to disconnect")?;
    result.map(|()| println!("Unloaded — the device is a clean slate (its address survives)."))
}

// ============================================================================
// read
// ============================================================================

async fn run_read(
    target: &OptionalTargetArgs,
    security_args: &SecurityArgs,
    product: &ProductData,
    explicit_ia: Option<IndividualAddress>,
    mods_path: Option<&std::path::Path>,
    max_apdu: Option<u16>,
    out: &std::path::Path,
) -> Result<()> {
    // Only products with addressed segments can be dumped this way; a
    // System B device places its tables itself and would need the
    // PID_TABLE_REFERENCE dance instead.
    let addressed: Vec<_> = product.segments.iter().filter_map(|s| s.address.map(|a| (a, s))).collect();
    if addressed.is_empty() {
        bail!("this product declares no absolutely-addressed segments; reading them back needs the System 7 layout");
    }

    std::fs::create_dir_all(out).with_context(|| format!("while attempting to create {}", out.display()))?;

    let (bus, ia, keys) = connect_for_management_operation(target, security_args, explicit_ia, mods_path).await?;
    let (mut connection, access) =
        connect_management(&bus, ia, &keys, true).await.context("while attempting to select management access")?;
    println!("Access:      {access:?}");
    let max_apdu = negotiate_max_apdu_on(&mut connection, bus.max_apdu(), max_apdu, None).await;
    // The same chunk bound the downloader writes with: what fits one
    // A_Memory_Read response, capped at the coding's 63 bytes.
    let chunk = usize::from(max_apdu.saturating_sub(3)).clamp(1, 63);

    let result = async {
        for (address, segment) in &addressed {
            let mut bytes = Vec::with_capacity(segment.size as usize);
            while bytes.len() < segment.size as usize {
                let at = address + bytes.len() as u16;
                let want = chunk.min(segment.size as usize - bytes.len()) as u8;
                let part = connection
                    .memory_read(at, want)
                    .await
                    .with_context(|| format!("while attempting to read {want} bytes at {at:#06X}"))?;
                bytes.extend_from_slice(&part);
            }
            let path = out.join(format!("region_{address:04X}.bin"));
            std::fs::write(&path, &bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
            println!("Read {address:#06X} ({} bytes, {}) -> {}", bytes.len(), segment.id, path.display());
        }
        Ok(())
    }
    .await;
    let _ = connection.close().await;
    bus.disconnect().await.context("while attempting to disconnect")?;
    result.map(|()| println!("Done — compare against a `load --dump-blobs` run of the same configuration."))
}

/// One state byte per machine, on whichever path drives this mask:
/// the property realization reads `PID_LOAD_STATE_CONTROL` per object
/// (the machine index is the object index), the memory realization
/// the consecutive status bytes.
async fn read_states_on(
    connection: &mut zweidraehte_client::DeviceConnection,
    path: LoadControlPath,
    machines: usize,
) -> Result<Vec<u8>> {
    let machines = machines.max(1);
    match path {
        LoadControlPath::Direct => Ok(Vec::new()),
        LoadControlPath::Memory(resources) => connection
            .memory_read(resources.load_status_addr, machines as u8)
            .await
            .context("while attempting to read the load states back"),
        LoadControlPath::Property => {
            let mut states = Vec::with_capacity(machines);
            for object in 1..=machines {
                let state = connection
                    .property_read(object as u8, zweidraehte_client::pid::LOAD_STATE_CONTROL, 1, 1)
                    .await
                    .with_context(|| format!("while attempting to read object {object}'s load state"))?;
                states.push(state.first().copied().unwrap_or(0xFF));
            }
            Ok(states)
        }
    }
}
