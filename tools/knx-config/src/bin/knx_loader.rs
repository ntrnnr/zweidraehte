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
    DeviceImage, Downloader, LoadControlPath, ProcedureKind, ProductData, assemble, compile, load_control_path,
    resolve_mods,
};
use zweidraehte_client::{IndividualAddress, KnxBus};
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
    // and the mask it runs on.
    let (program, _translations, archive) = load::load_program(&args.product)?;
    let product = ProductData::from_program(&program).context("while attempting to extract the product data")?;
    let mask_db = load::load_mask_db(args.master_data.as_deref(), archive.as_ref())?;
    let mask_version = product.mask_version.context("the product names no mask version")?;
    let mask = mask_db
        .mask(mask_version)
        .with_context(|| format!("the master data does not describe mask {mask_version:?}"))?;

    match args.command {
        Command::Load { mods, ia, program_ia, dry_run, dump_blobs } => {
            run_load(&args.target, program, product, &mask, &mods, ia, program_ia, dry_run, dump_blobs.as_deref()).await
        }
        Command::Unload { ia, mods, max_apdu } => {
            let ia = resolve_ia(ia, mods.as_deref())?;
            run_unload(&args.target, &product, &mask, ia, max_apdu).await
        }
        Command::Read { ia, mods, out, max_apdu } => {
            let ia = resolve_ia(ia, mods.as_deref())?;
            run_read(&args.target, &product, ia, max_apdu, &out).await
        }
    }
}

/// ETS's NegotiateMaxApduLength: the device's `PID_MAX_APDULENGTH`
/// (object 0, PID 56) bounded by the interface's own capacity. A
/// device that does not answer the read gets the TP1 standard-frame
/// 15 — correct for anything old enough to lack the property.
async fn negotiate_max_apdu(bus: &KnxBus, ia: IndividualAddress) -> u16 {
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

// ============================================================================
// load
// ============================================================================

#[allow(clippy::too_many_arguments)] // the subcommand's flags, passed through once
async fn run_load(
    target: &OptionalTargetArgs,
    program: zweidraehte_knxprod::schema::ApplicationProgram,
    mut product: ProductData,
    mask: &zweidraehte_client::download::MaskData<'_>,
    mods_path: &std::path::Path,
    ia_override: Option<IndividualAddress>,
    program_ia: bool,
    dry_run: bool,
    dump_blobs: Option<&std::path::Path>,
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

    let compiled = compile(mask, &product, &resolved.project).context("while attempting to compile the download")?;

    let ia = parse_ia(&mods.device.individual_address).map_err(anyhow::Error::msg)?;
    println!("Product:     {}", product.id);
    println!("Mask:        {:?} ({} path)", mask.version(), match compiled.path() {
        LoadControlPath::Memory(_) => "memory",
        LoadControlPath::Property => "property",
    });
    println!("Address:     {ia}");
    println!("Parameters:  {} values patched", resolved.project.parameters.len());
    println!("Links:       {} associations", resolved.project.links.len());
    println!("Objects:     {} in the group object table", product.com_objects.len());
    for (address, bytes) in compiled.image.regions() {
        println!("Region:      {address:#06X}, {} bytes", bytes.len());
    }
    println!("Procedure:   {} instructions", compiled.instructions.len());

    if let Some(dir) = dump_blobs {
        std::fs::create_dir_all(dir).with_context(|| format!("while attempting to create {}", dir.display()))?;
        for (address, bytes) in compiled.image.regions() {
            let path = dir.join(format!("region_{address:04X}.bin"));
            std::fs::write(&path, bytes).with_context(|| format!("while attempting to write {}", path.display()))?;
            println!("Wrote {}", path.display());
        }
    }

    if dry_run {
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
        println!("\nPut the device into programming mode (press its button), then press Enter…");
        std::io::stdin().read_line(&mut String::new()).context("while attempting to read the confirmation")?;
        let nm = bus.network_management();
        nm.write_individual_address(ia).await.context("while attempting to write the individual address")?;
        let found = nm
            .read_individual_addresses(Duration::from_secs(3))
            .await
            .context("while attempting to verify the address")?;
        if found.contains(&ia) {
            println!("Address {ia} written — take the device out of programming mode, then press Enter…");
            std::io::stdin().read_line(&mut String::new()).context("while attempting to read the confirmation")?;
        } else {
            bail!("no device in programming mode answered with {ia} — is the button pressed?");
        }
    }

    // ETS negotiates the write chunk before the procedure; so do we,
    // unless the mods file pins max_apdu explicitly. 52-byte chunks
    // instead of the standard frame's 12 cut the image phase ~4x.
    let mut resolved = resolved;
    if mods.device.max_apdu.is_none() {
        resolved.project.max_apdu = negotiate_max_apdu(&bus, ia).await;
    }

    println!("Downloading…");
    bus.configure_device(mask, &product, &resolved.project)
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
    let states = read_load_states(&bus, ia, compiled.path(), mask.lsm_model().machines.len()).await?;
    let rendered: Vec<String> = states.iter().map(|s| format!("{s:02X}")).collect();
    println!("Load states: [{}] (01 = Loaded)", rendered.join(" "));
    for (index, state) in states.iter().enumerate() {
        let machine = index as u8 + 1;
        if completed.contains(&machine) && *state != 0x01 {
            bail!("load state machine {machine} reports {state:#04X}, expected Loaded (01)");
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
    mask: &zweidraehte_client::download::MaskData<'_>,
    ia: IndividualAddress,
    max_apdu: Option<u16>,
) -> Result<()> {
    // The Unload template comes from the mask; the product only
    // contributes merge fragments where the family has them (System
    // B), so the real product is the right second argument even for a
    // teardown.
    let instructions =
        assemble(mask, product, ProcedureKind::UnloadAll).context("while attempting to assemble Unload-all")?;
    let path = load_control_path(mask)?;

    println!("Unloading {ia} ({} instructions)…", instructions.len());
    let bus = connect(target).await?;
    let max_apdu = match max_apdu {
        Some(fixed) => fixed,
        None => negotiate_max_apdu(&bus, ia).await,
    };
    let mut connection = bus.connect_device(ia).await.context("while attempting to connect to the device")?;
    let result = async {
        Downloader::with_path(&mut connection, path, max_apdu)
            .run(&instructions, &DeviceImage::new())
            .await
            .context("while attempting to run the unload procedure")?;

        // Show the clean slate — Unloaded (00h) on every machine.
        let machines = mask.lsm_model().machines.len().max(1);
        let states = read_states_on(&mut connection, path, machines).await?;
        let rendered: Vec<String> = states.iter().map(|s| format!("{s:02X}")).collect();
        println!("Load states: [{}] (00 = Unloaded)", rendered.join(" "));
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
        None => negotiate_max_apdu(&bus, ia).await,
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
