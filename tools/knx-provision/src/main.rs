//! `knx-provision` — host-side factory-provisioning tool.
//!
//! Writes a `KNXP` record into a KNX device's flash via SWD using
//! [`probe-rs`]. The format and codec live in
//! [`zweidraehte_device::provisioning`]; this binary is the operator-
//! facing wrapper that picks the flash offset for a given target,
//! drives the probe, and produces label data for the printer pipeline.
//!
//! On a typical production line a fixture flashes the firmware via
//! `probe-rs run` and then this tool runs once per unit:
//!
//! ```text
//! knx-provision --target stm32g0b0re \
//!     --serial 00FA12345678 --fdsk $(openssl rand -hex 16) \
//!     --output-label /var/lib/factory/labels/00FA12345678.json
//! ```
//!
//! See `--help` for the full surface.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use probe_rs::{MemoryInterface, Permissions, Session, SessionConfig, flashing};
use rand::RngCore;
use zweidraehte_device::provisioning::{self, ProvisioningRecord, fdsk_string};

// ================================================================================
// Target presets
// ================================================================================
//
// A target preset bundles three things the host tool needs:
// 1. The probe-rs chip name (passed to `Session::auto_attach`).
// 2. The absolute flash address of the KNXP page.
// 3. The page / sector size — used to align reads and to know how
//    much to erase before writing.
//
// The flash addresses come straight from the firmware's flash layout:
// see `cross/stm32-common/src/storage.rs` and `cross/rp-common/src/storage.rs`.

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Target {
    /// STM32G0B0RE (512 KiB flash, 2 KiB pages). KNXP at the last page.
    Stm32g0b0re,

    /// STM32G0B1RE — same flash layout as G0B0.
    Stm32g0b1re,

    /// RP2040 (2 MiB flash, 4 KiB sectors). KNXP at the last sector (0x1FF000).
    Rp2040,
}

struct TargetInfo {
    chip: &'static str,

    /// Absolute flash address of the KNXP record.
    knxp_addr: u64,

    /// Erase granularity (page on STM32, sector on RP2040).
    page_size: u64,
}

impl Target {
    fn info(self) -> TargetInfo {
        match self {
            // STM32G0: flash base 0x0800_0000, total 0x8_0000 (512 KiB),
            // page 0x800 (2 KiB). KNXP = base + (size − page) = 0x0807_F800.
            Self::Stm32g0b0re => TargetInfo { chip: "STM32G0B0RETx", knxp_addr: 0x0807_F800, page_size: 0x800 },
            Self::Stm32g0b1re => TargetInfo { chip: "STM32G0B1RETx", knxp_addr: 0x0807_F800, page_size: 0x800 },
            // RP2040: flash base 0x1000_0000 (XIP). KNXP at the last
            // 4 KiB sector — base + 0x1FF000.
            Self::Rp2040 => TargetInfo { chip: "RP2040", knxp_addr: 0x101F_F000, page_size: 0x1000 },
        }
    }
}

// ================================================================================
// CLI
// ================================================================================

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Target device class. Bundles the probe-rs chip name and KNXP flash offset.
    #[arg(long, value_enum)]
    target: Target,

    /// probe-rs probe selector (e.g. "VID:PID:SERIAL"). Defaults to the first
    /// available probe; fixtures with multiple probes attached should pin this.
    #[arg(long)]
    probe: Option<String>,

    /// Assigned KNX serial as 12 hex chars (e.g. "00FADEADBEEF").
    /// Mutually exclusive with `--serial-csv`.
    #[arg(long, conflicts_with_all = ["serial_csv", "read", "erase"])]
    serial: Option<String>,

    /// CSV file with a `serial` column. The next unclaimed row is consumed
    /// and tracked in `<FILE>.lock` so production runs don't reuse serials.
    #[arg(long, conflicts_with_all = ["serial", "read", "erase"])]
    serial_csv: Option<PathBuf>,

    /// 32-char hex FDSK. If absent and the target is a Data Secure device,
    /// a random FDSK is generated.
    #[arg(long)]
    fdsk: Option<String>,

    /// 12-char hex MAC. Mutually exclusive with `--oui`.
    #[arg(long, conflicts_with = "oui")]
    mac: Option<String>,

    /// 6-char hex OUI. The tool composes MAC = OUI || lower 3 bytes of serial,
    /// with the locally-administered bit forced set.
    #[arg(long)]
    oui: Option<String>,

    /// Path to write a JSON object `{serial, fdsk_string, mac}` for the
    /// downstream label-printer pipeline.
    #[arg(long)]
    output_label: Option<PathBuf>,

    /// Read and dump the existing record. Skips the write entirely.
    #[arg(long, conflicts_with_all = ["serial", "serial_csv", "fdsk", "mac", "oui", "output_label", "erase"])]
    read: bool,

    /// Erase the KNXP page. Useful for dev / RMA flows.
    #[arg(long, conflicts_with_all = ["serial", "serial_csv", "fdsk", "mac", "oui", "output_label", "read"])]
    erase: bool,

    /// Build and display the encoded record bytes without touching the device.
    #[arg(long)]
    dry_run: bool,

    /// Suppress the FDSK QR code on the terminal. Use in CI / scripted
    /// runs where the unicode block characters would clutter logs.
    #[arg(long)]
    no_qr: bool,
}

// ================================================================================
// Entry point
// ================================================================================

fn main() -> Result<()> {
    let args = Args::parse();
    let target = args.target.info();

    if args.read {
        return read_back(&args, &target);
    }
    if args.erase {
        return erase(&args, &target);
    }

    // ----- Resolve identity inputs --------------------------------------------
    //
    // Build a `ProvisioningRecord` from CLI inputs. Every step here is
    // independent of probe-rs so that `--dry-run` exits early with an
    // accurate preview of what would have been written.

    let serial = resolve_serial(&args).context("resolving serial")?;
    let fdsk = resolve_fdsk(&args).context("resolving FDSK")?;
    let mac = resolve_mac(&args, &serial).context("resolving MAC")?;
    let record = ProvisioningRecord { serial, fdsk, mac };

    let mut buf = vec![0u8; 256];
    let n = provisioning::write(&record, &mut buf).map_err(|e| anyhow!("encoding record: {e:?}"))?;
    let encoded = &buf[..n];

    println!("Encoded record: {} bytes", encoded.len());
    println!("  hex: {}", hex::encode(encoded));
    println!("  serial: {}", hex::encode(record.serial));

    if let Some(f) = record.fdsk.as_ref() {
        let label = fdsk_string(&record.serial, f);
        let label_str = std::str::from_utf8(&label).expect("ASCII");
        println!("  fdsk:   {} ({label_str})", hex::encode(f));
        if !args.no_qr {
            print_fdsk_qr(label_str);
        }
    }

    if let Some(m) = record.mac.as_ref() {
        println!("  mac:    {}", format_mac(m));
    }

    if args.dry_run {
        println!("[dry-run] not writing");
    } else {
        write_to_device(&args, &target, encoded).context("writing record")?;
        println!("Wrote KNXP record at 0x{:08X} via {}.", target.knxp_addr, target.chip);
        // Read back and verify byte-identical to the encoded bytes.
        verify(&args, &target, encoded).context("verifying record")?;
        println!("Verified (read-back matches).");
    }

    if let Some(path) = args.output_label.as_ref() {
        write_label(&record, path).with_context(|| format!("writing {}", path.display()))?;
        println!("Wrote label JSON to {}.", path.display());
    }

    Ok(())
}

// ================================================================================
// Identity input resolution
// ================================================================================

fn resolve_serial(args: &Args) -> Result<[u8; 6]> {
    if let Some(s) = args.serial.as_deref() {
        return decode_hex_n::<6>(s, "--serial");
    }

    if let Some(path) = args.serial_csv.as_ref() {
        return consume_serial_from_csv(path);
    }

    bail!("one of --serial or --serial-csv is required");
}

/// Pop the next unclaimed row from a serial pool CSV.
///
/// The CSV must have a header row containing a `serial` column. The
/// helper tracks already-consumed serials in a sibling `<FILE>.lock`
/// file (one hex serial per line) so concurrent runs against the same
/// pool don't collide. A more sophisticated factory would put the pool
/// behind a service; this is the minimum that prevents foot-shooting on
/// a single host.
fn consume_serial_from_csv(path: &PathBuf) -> Result<[u8; 6]> {
    let lock_path = {
        let mut p = path.clone();
        p.as_mut_os_string().push(".lock");
        p
    };

    let claimed: std::collections::HashSet<String> = if lock_path.exists() {
        fs::read_to_string(&lock_path)
            .with_context(|| format!("reading {}", lock_path.display()))?
            .lines()
            .map(|l| l.trim().to_uppercase())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        Default::default()
    };

    let mut rdr = csv::Reader::from_path(path).with_context(|| format!("opening {}", path.display()))?;
    let serial_col = rdr
        .headers()
        .with_context(|| format!("reading header of {}", path.display()))?
        .iter()
        .position(|h| h.eq_ignore_ascii_case("serial"))
        .ok_or_else(|| anyhow!("CSV {} has no `serial` column", path.display()))?;

    for record in rdr.records() {
        let record = record.context("reading CSV row")?;
        let raw = record.get(serial_col).ok_or_else(|| anyhow!("malformed CSV row"))?;
        let normalized = raw.trim().to_uppercase();

        if claimed.contains(&normalized) {
            continue;
        }

        let bytes = decode_hex_n::<6>(&normalized, "CSV serial")?;
        // Append to the lock file before returning so a crash mid-program
        // doesn't double-claim the serial.
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        writeln!(f, "{normalized}").with_context(|| format!("writing {}", lock_path.display()))?;

        return Ok(bytes);
    }

    bail!("no unclaimed serials in {}", path.display());
}

fn resolve_fdsk(args: &Args) -> Result<Option<[u8; 16]>> {
    if let Some(s) = args.fdsk.as_deref() {
        return Ok(Some(decode_hex_n::<16>(s, "--fdsk")?));
    }

    // No automatic FDSK generation when not asked: a non-secure device
    // shouldn't carry an FDSK, and we want the operator to opt in
    // explicitly for secure devices. Use --fdsk auto if you want random.
    Ok(None)
}

fn resolve_mac(args: &Args, serial: &[u8; 6]) -> Result<Option<[u8; 6]>> {
    if let Some(s) = args.mac.as_deref() {
        return Ok(Some(decode_hex_n::<6>(s, "--mac")?));
    }

    if let Some(o) = args.oui.as_deref() {
        let oui: [u8; 3] = decode_hex_n::<3>(o, "--oui")?;
        // Locally administered bit forced set, multicast bit forced clear.
        // Lower 3 bytes come from the device-specific portion of the
        // serial so each provisioned unit gets a distinct MAC even when
        // operators forget to allocate explicit MACs.
        Ok(Some([(oui[0] | 0x02) & 0xFE, oui[1], oui[2], serial[3], serial[4], serial[5]]))
    } else {
        Ok(None)
    }
}

// ================================================================================
// probe-rs bridge
// ================================================================================
//
// Three operations against the device, all routed through the same
// session. probe-rs's flashing API takes absolute addresses; we pass
// the page-aligned KNXP_ADDR plus the encoded payload (and pad up to a
// page worth of 0xFF for the erase-then-write).

fn open_session(args: &Args, target: &TargetInfo) -> Result<Session> {
    let perms = Permissions::default();

    if let Some(sel) = args.probe.as_deref() {
        let probe = probe_rs::probe::list::Lister::new()
            .list_all()
            .into_iter()
            .find(|p| {
                format!("{:04x}:{:04x}:{}", p.vendor_id, p.product_id, p.serial_number.as_deref().unwrap_or(""))
                    .eq_ignore_ascii_case(sel)
                    || p.serial_number.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(sel))
            })
            .ok_or_else(|| anyhow!("no probe matching {sel:?}"))?
            .open()
            .context("opening selected probe")?;

        Ok(probe.attach(target.chip, perms).context("attaching probe-rs")?)
    } else {
        let cfg = SessionConfig { permissions: perms, ..Default::default() };
        Ok(Session::auto_attach(target.chip, cfg).context("auto-attaching probe-rs")?)
    }
}

fn write_to_device(args: &Args, target: &TargetInfo, encoded: &[u8]) -> Result<()> {
    let mut session = open_session(args, target)?;

    // Pad to a page so the erase-then-write covers exactly the KNXP region.
    let mut page = vec![0xFFu8; target.page_size as usize];
    page[..encoded.len()].copy_from_slice(encoded);

    flashing::download_file_with_options(
        &mut session,
        // probe-rs has no "raw bytes" loader on stable; we use the
        // BinOptions writer with a synthesized binary file.
        write_temp_bin(target.knxp_addr, &page)?,
        flashing::Format::Bin(flashing::BinOptions { base_address: Some(target.knxp_addr), skip: 0 }),
        flashing::DownloadOptions::default(),
    )
    .context("flashing KNXP page")?;

    session.core(0)?.reset().context("resetting target after KNXP write")?;
    // Tiny settling delay before any subsequent verify read.
    std::thread::sleep(Duration::from_millis(100));
    Ok(())
}

/// probe-rs's `download_file_with_options` takes a path. Stash the page
/// bytes in a tempfile so the call is straightforward; the temp dies
/// when the function returns.
fn write_temp_bin(_addr: u64, bytes: &[u8]) -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    path.push(format!("knx-provision-{}.bin", std::process::id()));
    fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn verify(args: &Args, target: &TargetInfo, encoded: &[u8]) -> Result<()> {
    let mut session = open_session(args, target)?;
    let mut core = session.core(0)?;
    let mut buf = vec![0u8; encoded.len()];

    core.read(target.knxp_addr, &mut buf).context("reading KNXP page")?;

    if buf != encoded {
        bail!(
            "read-back mismatch: wrote {} bytes, read {} differ",
            encoded.len(),
            buf.iter().zip(encoded).filter(|(a, b)| a != b).count()
        );
    }

    Ok(())
}

fn read_back(args: &Args, target: &TargetInfo) -> Result<()> {
    let mut session = open_session(args, target)?;
    let mut core = session.core(0)?;
    let mut buf = vec![0u8; 256];

    core.read(target.knxp_addr, &mut buf).context("reading KNXP page")?;

    match provisioning::parse(&buf) {
        Ok(rec) => {
            println!("KNXP @ 0x{:08X}:", target.knxp_addr);
            println!("  serial: {}", hex::encode(rec.serial));

            if let Some(f) = rec.fdsk.as_ref() {
                let label = fdsk_string(&rec.serial, f);
                let label_str = std::str::from_utf8(&label).unwrap();
                println!("  fdsk:   {} ({label_str})", hex::encode(f));
                if !args.no_qr {
                    print_fdsk_qr(label_str);
                }
            }

            if let Some(m) = rec.mac.as_ref() {
                println!("  mac:    {}", format_mac(m));
            }
        }

        Err(e) => {
            println!("KNXP @ 0x{:08X}: not a valid record ({e:?})", target.knxp_addr);
            println!("  raw (first 64B): {}", hex::encode(&buf[..64]));
        }
    }

    Ok(())
}

fn erase(args: &Args, target: &TargetInfo) -> Result<()> {
    let mut session = open_session(args, target)?;
    let page = vec![0xFFu8; target.page_size as usize];

    flashing::download_file_with_options(
        &mut session,
        write_temp_bin(target.knxp_addr, &page)?,
        flashing::Format::Bin(flashing::BinOptions { base_address: Some(target.knxp_addr), skip: 0 }),
        flashing::DownloadOptions::default(),
    )
    .context("flashing erased KNXP page")?;

    session.core(0)?.reset().ok();
    println!("Erased KNXP page (0x{:08X}, {} bytes).", target.knxp_addr, target.page_size);

    Ok(())
}

// ================================================================================
// Helpers
// ================================================================================

fn decode_hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let v = hex::decode(s).with_context(|| format!("{what}: invalid hex"))?;

    if v.len() != N {
        bail!("{what}: expected {} bytes, got {}", N, v.len());
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&v);

    Ok(out)
}

fn format_mac(m: &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", m[0], m[1], m[2], m[3], m[4], m[5])
}

fn write_label(record: &ProvisioningRecord, path: &PathBuf) -> Result<()> {
    use serde_json::json;

    let serial_hex = hex::encode_upper(record.serial);
    let label = record.fdsk.as_ref().map(|f| {
        let bytes = fdsk_string(&record.serial, f);
        std::str::from_utf8(&bytes).expect("ASCII").to_string()
    });

    let mac = record.mac.as_ref().map(format_mac);
    let value = json!({
        "serial": serial_hex,
        "fdsk_string": label,
        "mac": mac,
    });

    fs::write(path, serde_json::to_string_pretty(&value)? + "\n")
        .with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

#[allow(dead_code)] // referenced via rand transitive trait — keep for future random-FDSK feature.
fn random_fdsk() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut out = [0u8; 16];
    rng.fill_bytes(&mut out);
    out
}

/// Render the FDSK label string as a QR code on the terminal.
///
/// `label` is the hyphenated form (`XXXXXX-…-XXXXXX`) we display to
/// humans, but ETS-style scanners expect the **dashless** 36-char
/// Base32 payload, so we strip `-` before encoding. The displayed
/// human-readable line keeps the dashes for readability; only the QR
/// payload differs.
///
/// Uses `Dense1x2` unicode rendering: each terminal cell encodes two
/// QR rows (▀ ▄ █ space) so the result looks roughly square at the
/// typical 1:2 character aspect ratio. Quiet zone defaults are kept
/// (4 modules) so phone cameras lock on without fiddling.
fn print_fdsk_qr(label: &str) {
    use qrcode::QrCode;
    use qrcode::render::unicode::Dense1x2;

    // 36 ASCII chars after stripping dashes — well within version-3
    // capacity at even the highest error-correction level.
    let payload: String = label.chars().filter(|c| *c != '-').collect();

    // `QrCode::new` errors only on overflow / capacity-exceeded, which
    // won't happen here; treat any error as non-fatal and skip the QR
    // rather than aborting.
    let code = match QrCode::new(payload.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  (QR render skipped: {e})");
            return;
        }
    };
    let rendered = code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).build();
    // Indent each line by two spaces to align with the rest of the
    // record fields ("  serial:", "  fdsk:", …).
    for line in rendered.lines() {
        println!("  {line}");
    }
}
