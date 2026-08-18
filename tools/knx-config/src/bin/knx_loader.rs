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
use zweidraehte_client::cli::{BusTarget, OptionalTargetArgs, parse_ia};
use zweidraehte_client::download::{
    DeviceImage, DownloadModel, Downloader, LoadControlPath, MaskData, MaskDb, ProcedureKind, ProductData, assemble,
    compile, load_control_path, resolve_mods, select_download_mask,
};
use zweidraehte_client::{IndividualAddress, KnxBus, MaskVersion};
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
            let ia = resolve_ia(ia, mods.as_deref())?;
            run_unload(&args.target, &product, &mask_db, ia, max_apdu).await
        }
        Command::Read { ia, mods, out, max_apdu } => {
            let ia = resolve_ia(ia, mods.as_deref())?;
            run_read(&args.target, &product, ia, max_apdu, &out).await
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

/// Switch a device's programming mode off, the way its mask realizes
/// it: masks that locate the master data's `ProgrammingMode` resource
/// in memory keep the mode as bit 0 of that address (a
/// read-modify-write preserves the byte's other bits — on BCU1 the
/// same byte carries the run-control and parity bits); everything
/// else exposes `PID_PROGMODE` on the device object.
async fn disable_programming_mode(
    bus: &KnxBus,
    mask: &zweidraehte_client::download::MaskData<'_>,
    ia: IndividualAddress,
) -> Result<()> {
    // Deliberately the `ProgrammingMode` resource alone, not
    // `memory_resources()`: that bundle also demands the load-control
    // window, which BCU1 masks (memory-mapped programming mode, no
    // load state machines at all) do not declare.
    let memory_prog_mode = mask
        .resources()
        .get("ProgrammingMode")
        .filter(|r| r.is_standard_memory())
        .and_then(|r| r.start_address())
        .and_then(|a| u16::try_from(a).ok());

    let mut connection = bus.connect_device(ia).await.context("while attempting to connect")?;
    let result = async {
        if let Some(address) = memory_prog_mode {
            let byte = connection
                .memory_read(address, 1)
                .await
                .context("while attempting to read the programming-mode byte")?[0];
            if byte & 0x01 != 0 {
                connection
                    .memory_write_verify(address, &[byte & !0x01])
                    .await
                    .context("while attempting to clear the programming-mode bit")?;
            }
        } else {
            connection
                .property_write(0, zweidraehte_client::pid::device::PROGMODE, 1, 1, &[0])
                .await
                .context("while attempting to write PID_PROGMODE")?;
        }
        Ok(())
    }
    .await;
    let _ = connection.close().await;
    result
}

/// ETS's NegotiateMaxApduLength: the device's `PID_MAX_APDULENGTH`
/// (object 0, PID 56) bounded by the interface's own capacity. A
/// device that does not answer the read gets the TP1 standard-frame
/// 15 — correct for anything old enough to lack the property. A mask
/// whose model has no properties at all (BCU1) skips the probe: the
/// timeout would buy nothing the model does not already know.
async fn negotiate_max_apdu(bus: &KnxBus, ia: IndividualAddress, model: Option<&DownloadModel>) -> u16 {
    if let Some(model) = model
        && !model.has_properties
    {
        println!(
            "Max APDU:    this mask has no PID_MAX_APDULENGTH; using the standard frame's {}",
            model.default_max_apdu
        );
        return model.default_max_apdu;
    }
    match bus.network_management().property_read(ia, 0, zweidraehte_client::pid::device::MAX_APDU_LENGTH, 1, 1).await {
        Ok(bytes) => {
            let device = bytes.iter().fold(0u16, |acc, &b| (acc << 8) | u16::from(b));
            let negotiated = device.min(bus.max_apdu()).max(15);
            println!("Max APDU:    device {device}, interface {}, using {negotiated}", bus.max_apdu());
            negotiated
        }
        Err(e) => {
            println!("Max APDU:    device does not answer PID 56 ({e}); using the standard frame's 15");
            15
        }
    }
}

/// The target address: `--ia` wins, a mods file's `[device]` section
/// serves as the fallback.
fn resolve_ia(explicit: Option<IndividualAddress>, mods: Option<&std::path::Path>) -> Result<IndividualAddress> {
    if let Some(ia) = explicit {
        return Ok(ia);
    }
    let Some(path) = mods else {
        bail!("give --ia, or --mods to take the address from");
    };
    let text = std::fs::read_to_string(path).with_context(|| format!("while attempting to read {}", path.display()))?;
    let mods: DeviceMods =
        toml::from_str(&text).with_context(|| format!("while attempting to parse {}", path.display()))?;
    parse_ia(&mods.device.individual_address).map_err(anyhow::Error::msg)
}

async fn connect(target: &OptionalTargetArgs) -> Result<KnxBus> {
    let Some(target): Option<BusTarget> = target.to_target() else {
        bail!("give --server or --usb (before the subcommand)");
    };
    target.connect().await.context("while attempting to connect to the bus")
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
    program: zweidraehte_knxprod::schema::ApplicationProgram,
    mut product: ProductData,
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

    // The group object table must describe the *configuration* (ref
    // and mods overrides included), not the product's base roster.
    product.com_objects = resolved.com_objects.clone();

    let product_mask = product.mask_version.context("the product names no mask version")?;
    let ia = parse_ia(&mods.device.individual_address).map_err(anyhow::Error::msg)?;

    // Offline: compile for the product's own mask, or for the DD0 the
    // user claims with --device-mask.
    if dry_run {
        let mask = select_mask(mask_db, product_mask, device_mask.unwrap_or(product_mask))?;
        let compiled =
            compile(&mask, &product, &resolved.project).context("while attempting to compile the download")?;
        print_compiled(&mask, &product, &resolved, ia, &compiled);
        dump_blob_files(dump_blobs, &compiled)?;

        println!("\nDry run — parameter patches:");
        for value in &resolved.project.parameters {
            let location = product.parameters.iter().find(|l| l.id == value.id);
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

    let bus = connect(target).await?;

    if program_ia {
        // Poll for the programming button instead of asking for Enter:
        // scan until exactly one device answers, assign, verify, and
        // switch programming mode back off ourselves — no keyboard
        // round trips.
        println!("\nPress the programming button on the target device… (Ctrl+C to abort)");
        let nm = bus.network_management();
        let mut warned_about_crowd = 0usize;
        let present = loop {
            let found = nm
                .read_individual_addresses(Duration::from_secs(1))
                .await
                .context("while attempting to scan for programming mode")?;
            match found.len() {
                0 => {}
                1 => break found[0],
                n if n != warned_about_crowd => {
                    println!("{n} devices are in programming mode — release all but one");
                    warned_about_crowd = n;
                }
                _ => {}
            }
        };
        println!("Device {present} is in programming mode; assigning {ia}…");
        nm.write_individual_address(ia).await.context("while attempting to write the individual address")?;
        let found = nm
            .read_individual_addresses(Duration::from_secs(2))
            .await
            .context("while attempting to verify the address")?;
        if !found.contains(&ia) {
            bail!("the device did not take address {ia}");
        }
        println!("Address {ia} assigned.");
    }

    // The mask everything below is keyed on comes from the *device*
    // (its DD0), the way ETS decides it — a BCU2 answering 0020 runs
    // a downward-compatible BCU1 product through the BCU2 procedure.
    let dd0 = read_device_mask(&bus, ia).await?;
    let mask = select_mask(mask_db, product_mask, dd0)?;
    if mask.version() != product_mask {
        println!("Device:      {dd0:?} — running the {product_mask:?} product through its own procedure");
    }

    if program_ia {
        // Best-effort: a device that cannot be switched remotely just
        // needs its button released, which must not fail the download.
        match disable_programming_mode(&bus, &mask, ia).await {
            Ok(()) => println!("Programming mode switched off."),
            Err(e) => println!("Switch programming mode off manually ({e})."),
        }
    }

    let compiled = compile(&mask, &product, &resolved.project).context("while attempting to compile the download")?;
    print_compiled(&mask, &product, &resolved, ia, &compiled);
    dump_blob_files(dump_blobs, &compiled)?;

    // ETS negotiates the write chunk before the procedure; so do we,
    // unless the mods file pins max_apdu explicitly. 52-byte chunks
    // instead of the standard frame's 12 cut the image phase ~4x.
    let mut resolved = resolved;
    if mods.device.max_apdu.is_none() {
        resolved.project.max_apdu =
            negotiate_max_apdu(&bus, ia, DownloadModel::for_management_model(mask.management_model())).await;
    }

    println!("Downloading…");
    bus.configure_device(&mask, &product, &resolved.project)
        .await
        .context("while attempting to download the configuration")?;
    println!("Download complete; the device is restarting…");

    // Boot grace before the verification reconnect — the procedure
    // ends in a restart, and ETS gives the device ~3 s too.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Read the load states back on the same path the download drove
    // them. Only the machines the procedure completed must report
    // Loaded — a product without a PEI program leaves machine 4
    // Unloaded, and that is correct, not a failure.
    let completed: std::collections::BTreeSet<u8> = compiled
        .instructions
        .iter()
        .filter_map(|i| match i {
            zweidraehte_client::download::Instruction::LsmEvent {
                lsm,
                event: zweidraehte_client::download::LoadEvent::LoadCompleted,
            } => Some(*lsm),
            _ => None,
        })
        .collect();
    if compiled.path() == LoadControlPath::Direct {
        println!("Load states: none — this mask has no load state machines");
    } else {
        let states = read_load_states(&bus, ia, compiled.path(), mask.lsm_model().machines.len()).await?;
        let rendered: Vec<String> = states.iter().map(|s| format!("{s:02X}")).collect();
        println!("Load states: [{}] (01 = Loaded)", rendered.join(" "));
        for (index, state) in states.iter().enumerate() {
            let machine = index as u8 + 1;
            if completed.contains(&machine) && *state != 0x01 {
                bail!("load state machine {machine} reports {state:#04X}, expected Loaded (01)");
            }
        }
    }

    bus.disconnect().await.context("while attempting to disconnect")?;
    println!("Done.");
    Ok(())
}

// ============================================================================
// unload
// ============================================================================

async fn run_unload(
    target: &OptionalTargetArgs,
    product: &ProductData,
    mask_db: &MaskDb,
    ia: IndividualAddress,
    max_apdu: Option<u16>,
) -> Result<()> {
    let product_mask = product.mask_version.context("the product names no mask version")?;
    let bus = connect(target).await?;

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
    let max_apdu = match max_apdu {
        Some(fixed) => fixed,
        None => negotiate_max_apdu(&bus, ia, model).await,
    };
    let mut connection = bus.connect_device(ia).await.context("while attempting to connect to the device")?;
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
    product: &ProductData,
    ia: IndividualAddress,
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

    let bus = connect(target).await?;
    let max_apdu = match max_apdu {
        Some(fixed) => fixed,
        // No mask at hand here — the probe's read-failure fallback
        // covers property-less devices, at the cost of one timeout.
        None => negotiate_max_apdu(&bus, ia, None).await,
    };
    // The same chunk bound the downloader writes with: what fits one
    // A_Memory_Read response, capped at the coding's 63 bytes.
    let chunk = usize::from(max_apdu.saturating_sub(3)).clamp(1, 63);

    let mut connection = bus.connect_device(ia).await.context("while attempting to connect to the device")?;
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

/// Read the per-machine load states after a download (the connection
/// is fresh — the procedure ended in a restart).
async fn read_load_states(
    bus: &KnxBus,
    ia: IndividualAddress,
    path: LoadControlPath,
    machines: usize,
) -> Result<Vec<u8>> {
    let mut connection = bus.connect_device(ia).await.context("while attempting to reconnect for verification")?;
    let states = read_states_on(&mut connection, path, machines).await;
    let _ = connection.close().await;
    states
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
