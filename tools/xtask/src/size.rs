//! Firmware size report: `cargo xtask size`.
//!
//! Device-stack changes that aim at flash or RAM need a number before and
//! after, taken the same way every time. This task builds a fixed set of
//! firmware targets and reports, per target, the flash image, the static RAM
//! and the share of `.text` that `cargo bloat` attributes to
//! `zweidraehte_device`, next to the committed baseline in
//! `tools/xtask/size-baseline.json`.
//!
//! Every target is measured twice:
//!
//! - with the `DEFMT_LOG` the firmware workspace commits — what ships;
//! - with `DEFMT_LOG=off` — the stack code without its logging, which is the
//!   honest number for refactors that do not touch log statements.
//!
//! The second variant builds into its own target directory so the two do not
//! invalidate each other's caches.
//!
//! `--type-sizes` answers the RAM question the section headers cannot: which
//! static types and task futures the RAM goes to. It rebuilds one target with
//! `-Zprint-type-sizes` (the pinned toolchain is nightly) in a third target
//! directory and lists the largest stack-related types.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::Args;
use serde_json::{Map, Value, json};

const BASELINE_FILE: &str = "tools/xtask/size-baseline.json";
const FIRMWARE_DIR: &str = "firmware";
const DEVICE_CRATE: &str = "zweidraehte_device";

// ============================================================================
// What we measure
// ============================================================================

/// One firmware binary. Firmware projects must be built from inside their
/// own directory, where `.cargo/config.toml` selects the target triple.
struct FirmwareTarget {
    dir: &'static str,
    binary: &'static str,
    triple: &'static str,
}

/// The targets cover both BCU families, plain and Data Secure, TP1, RF and
/// KNX/IP. STM32G0 is the constrained part; the RP2040 builds are the only
/// ones that compile the KNX/IP link layer.
const TARGETS: &[FirmwareTarget] = &[
    FirmwareTarget { dir: "stm32/g0_tp1_light_switch", binary: "stm32g0_tp1_light_switch", triple: THUMBV6M },
    FirmwareTarget {
        dir: "stm32/g0_tp1_system7_light_switch",
        binary: "stm32g0_tp1_system7_light_switch",
        triple: THUMBV6M,
    },
    FirmwareTarget {
        dir: "stm32/g0_tp1_secure_light_switch",
        binary: "stm32g0_tp1_secure_light_switch",
        triple: THUMBV6M,
    },
    FirmwareTarget {
        dir: "stm32/g0_tp1_system7_secure_light_switch",
        binary: "stm32g0_tp1_system7_secure_light_switch",
        triple: THUMBV6M,
    },
    FirmwareTarget {
        dir: "stm32/g0_knxrf_secure_light_switch",
        binary: "stm32g0_knxrf_secure_light_switch",
        triple: THUMBV6M,
    },
    FirmwareTarget { dir: "rp2040/tp1_light_switch", binary: "pico_tp1_light_switch", triple: THUMBV6M },
    FirmwareTarget { dir: "rp2040/eth_light_switch", binary: "pico_eth_light_switch", triple: THUMBV6M },
];

const THUMBV6M: &str = "thumbv6m-none-eabi";

/// The two logging configurations every target is built with.
#[derive(Clone, Copy)]
enum LogVariant {
    /// Whatever `firmware/.cargo/config.toml` sets — the shipped binary.
    Committed,
    /// `DEFMT_LOG=off`: the code without its log statements.
    Off,
}

impl LogVariant {
    const ALL: [LogVariant; 2] = [LogVariant::Committed, LogVariant::Off];

    fn key(self) -> &'static str {
        match self {
            LogVariant::Committed => "committed",
            LogVariant::Off => "log-off",
        }
    }

    /// The Cargo target directory, relative to the firmware workspace.
    fn target_dir(self) -> &'static str {
        match self {
            LogVariant::Committed => "target",
            LogVariant::Off => "target/size-defmt-off",
        }
    }
}

/// The numbers recorded per target and log variant.
#[derive(Clone, Copy, Default)]
struct Measurement {
    /// Every allocated section with file contents: code, read-only data,
    /// vector table and the `.data` initialisers.
    flash: u64,
    /// `.text` alone.
    text: u64,
    /// Static RAM: `.data` plus every allocated no-bits section
    /// (`.bss`, `.uninit`). Stack and heap are not included.
    ram: u64,
    /// The part of `.text` that `cargo bloat` attributes to the device
    /// crate. Approximate under LTO — inlined code lands in its caller.
    device: u64,
}

impl Measurement {
    const FIELDS: [&'static str; 4] = ["flash", "text", "ram", "device"];

    fn get(&self, field: &str) -> u64 {
        match field {
            "flash" => self.flash,
            "text" => self.text,
            "ram" => self.ram,
            "device" => self.device,
            _ => unreachable!("only the fields in FIELDS are queried"),
        }
    }

    fn to_json(self) -> Value {
        json!({ "flash": self.flash, "text": self.text, "ram": self.ram, "device": self.device })
    }

    fn from_json(value: &Value) -> Option<Self> {
        let field = |name: &str| value.get(name).and_then(Value::as_u64);

        Some(Self { flash: field("flash")?, text: field("text")?, ram: field("ram")?, device: field("device")? })
    }
}

// ============================================================================
// Command line
// ============================================================================

#[derive(Debug, Args)]
pub struct SizeArgs {
    /// Measure only the targets whose directory contains this substring.
    filter: Option<String>,

    /// Write the measured numbers into the committed baseline. With a
    /// filter, only the measured targets are replaced.
    #[arg(long)]
    update_baseline: bool,

    /// Also list the N largest functions of each target (shipped log level).
    #[arg(long, value_name = "N")]
    top: Option<usize>,

    /// Instead of the size table, rebuild the single target matching this
    /// substring with `-Zprint-type-sizes` and list its largest RAM types.
    #[arg(long, value_name = "TARGET", conflicts_with_all = ["update_baseline", "top"])]
    type_sizes: Option<String>,

    /// With `--type-sizes`: hide types smaller than this many bytes.
    #[arg(long, value_name = "BYTES", default_value_t = 128)]
    min_bytes: u64,
}

pub fn run_size(root: &Path, args: SizeArgs) -> Result<(), String> {
    if let Some(filter) = &args.type_sizes {
        let target = single_target(filter)?;
        return report_type_sizes(root, target, args.min_bytes);
    }

    let targets: Vec<&FirmwareTarget> = TARGETS
        .iter()
        .filter(|target| args.filter.as_deref().is_none_or(|filter| target.dir.contains(filter)))
        .collect();

    if targets.is_empty() {
        return Err(format!("no firmware target matches `{}`", args.filter.unwrap_or_default()));
    }

    let baseline = load_baseline(root)?;
    let mut measured: BTreeMap<&str, BTreeMap<&str, Measurement>> = BTreeMap::new();
    let mut top_functions = Vec::new();

    for target in &targets {
        for variant in LogVariant::ALL {
            eprintln!("Measuring {} ({})...", target.dir, variant.key());

            let bloat = run_cargo_bloat(root, target, variant)?;
            let sections = read_elf_sections(&elf_path(root, target, variant))?;
            let measurement = Measurement {
                flash: sections.flash,
                text: sections.text,
                ram: sections.ram,
                device: device_crate_bytes(&bloat),
            };

            if let (Some(n), LogVariant::Committed) = (args.top, variant) {
                top_functions.push((target.dir, largest_functions(&bloat, n)));
            }

            measured.entry(target.dir).or_default().insert(variant.key(), measurement);
        }
    }

    print_table(&measured, &baseline);

    for (dir, functions) in top_functions {
        println!("\nLargest functions in {dir}:");
        for (size, krate, name) in functions {
            println!("{size:>8}  {krate:<24} {name}");
        }
    }

    if args.update_baseline {
        store_baseline(root, baseline, &measured)?;
        eprintln!("\nUpdated {BASELINE_FILE}.");
    }

    Ok(())
}

fn single_target(filter: &str) -> Result<&'static FirmwareTarget, String> {
    let matches: Vec<&FirmwareTarget> = TARGETS.iter().filter(|target| target.dir.contains(filter)).collect();

    match matches.as_slice() {
        [target] => Ok(target),
        [] => Err(format!("no firmware target matches `{filter}`")),
        _ => Err(format!(
            "`{filter}` matches several targets ({}); name one",
            matches.iter().map(|target| target.dir).collect::<Vec<_>>().join(", ")
        )),
    }
}

// ============================================================================
// Building and attributing
// ============================================================================

/// Build the target through `cargo bloat` and return its JSON report.
///
/// `cargo bloat` does the release build itself, so the report and the ELF we
/// read afterwards come from the same compilation.
fn run_cargo_bloat(root: &Path, target: &FirmwareTarget, variant: LogVariant) -> Result<Value, String> {
    let firmware = root.join(FIRMWARE_DIR);
    let mut command = Command::new("cargo");

    command
        .current_dir(firmware.join(target.dir))
        .args(["bloat", "--release", "--message-format", "json", "-n", "0"])
        .env("CARGO_TARGET_DIR", firmware.join(variant.target_dir()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // An inherited `DEFMT_LOG` would silently replace the committed level,
    // because Cargo's `[env]` table does not override the environment.
    match variant {
        LogVariant::Committed => command.env_remove("DEFMT_LOG"),
        LogVariant::Off => command.env("DEFMT_LOG", "off"),
    };

    let output = command.output().map_err(|error| {
        format!("failed to start `cargo bloat` ({error}); install it with `cargo install cargo-bloat`")
    })?;

    if !output.status.success() {
        return Err(format!(
            "`cargo bloat` failed for {} ({}):\n{}",
            target.dir,
            variant.key(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("`cargo bloat` printed invalid JSON for {}: {error}", target.dir))
}

fn elf_path(root: &Path, target: &FirmwareTarget, variant: LogVariant) -> PathBuf {
    root.join(FIRMWARE_DIR).join(variant.target_dir()).join(target.triple).join("release").join(target.binary)
}

fn bloat_functions(bloat: &Value) -> impl Iterator<Item = (&str, &str, u64)> {
    bloat.get("functions").and_then(Value::as_array).into_iter().flatten().filter_map(|function| {
        Some((function.get("crate")?.as_str()?, function.get("name")?.as_str()?, function.get("size")?.as_u64()?))
    })
}

fn device_crate_bytes(bloat: &Value) -> u64 {
    bloat_functions(bloat).filter(|(krate, _, _)| *krate == DEVICE_CRATE).map(|(_, _, size)| size).sum()
}

fn largest_functions(bloat: &Value, n: usize) -> Vec<(u64, String, String)> {
    let mut functions: Vec<(u64, String, String)> =
        bloat_functions(bloat).map(|(krate, name, size)| (size, krate.to_owned(), strip_generics(name))).collect();

    functions.sort_by_key(|function| std::cmp::Reverse(function.0));
    functions.truncate(n);
    functions
}

/// Drop generic argument lists, so that
/// `<Layer<Tp1<Def, 22, 50, 14>> as Trait<Tp1<…>>>::process` stays readable.
///
/// A name that starts with `<` is a qualified path (`<X as Y>::m`); its
/// outermost bracket pair is structure, not arguments, and is kept.
fn strip_generics(name: &str) -> String {
    // Inside the qualified-path brackets, depth 1 is still the path itself.
    let mut in_qualified = name.starts_with('<');
    let mut result = String::with_capacity(name.len());
    let mut depth = 0usize;

    for character in name.chars() {
        let kept_depth = usize::from(in_qualified);

        match character {
            '<' => {
                if in_qualified && depth == 0 {
                    result.push('<');
                } else if depth == kept_depth && result.ends_with("::") {
                    // A turbofish (`f::<T>`) leaves nothing to show.
                    result.truncate(result.len() - 2);
                }
                depth += 1;
            }
            '>' => {
                depth = depth.saturating_sub(1);
                if in_qualified && depth == 0 {
                    result.push('>');
                    in_qualified = false;
                }
            }
            _ if depth <= kept_depth => result.push(character),
            _ => {}
        }
    }

    result
}

// ============================================================================
// ELF section sizes
// ============================================================================

struct SectionSizes {
    flash: u64,
    text: u64,
    ram: u64,
}

/// Sum the allocated sections of a 32-bit little-endian ELF.
///
/// Reading the section headers directly avoids depending on a particular
/// `size` tool being installed, and the arithmetic is the definition we want:
/// allocated sections with contents occupy flash (`.data` included, as its
/// initialiser image), allocated sections without contents occupy only RAM.
fn read_elf_sections(path: &Path) -> Result<SectionSizes, String> {
    const SHT_NOBITS: u32 = 8;
    const SHF_ALLOC: u32 = 0x2;

    let bytes = fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let invalid = || format!("{} is not a 32-bit little-endian ELF", path.display());

    if bytes.get(0..6) != Some(&[0x7F, b'E', b'L', b'F', 1, 1]) {
        return Err(invalid());
    }

    let u16_at = |offset: usize| bytes.get(offset..offset + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |offset: usize| bytes.get(offset..offset + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));

    let section_table = u32_at(0x20).ok_or_else(invalid)? as usize;
    let entry_size = u16_at(0x2E).ok_or_else(invalid)? as usize;
    let entry_count = u16_at(0x30).ok_or_else(invalid)? as usize;
    let names_index = u16_at(0x32).ok_or_else(invalid)? as usize;

    // Section header fields: name, type, flags, addr, offset, size.
    let header = |index: usize| {
        let base = section_table + index * entry_size;
        Some((u32_at(base)?, u32_at(base + 4)?, u32_at(base + 8)?, u32_at(base + 16)?, u32_at(base + 20)?))
    };

    let (_, _, _, names_offset, _) = header(names_index).ok_or_else(invalid)?;
    let section_name = |name_offset: u32| {
        let start = (names_offset + name_offset) as usize;
        let tail = bytes.get(start..)?;
        let end = tail.iter().position(|&byte| byte == 0)?;
        std::str::from_utf8(&tail[..end]).ok()
    };

    let mut sizes = SectionSizes { flash: 0, text: 0, ram: 0 };

    for index in 0..entry_count {
        let (name, kind, flags, _, size) = header(index).ok_or_else(invalid)?;
        let size = u64::from(size);

        if flags & SHF_ALLOC == 0 {
            continue;
        }

        let name = section_name(name).unwrap_or_default();

        if kind == SHT_NOBITS {
            sizes.ram += size;
        } else {
            sizes.flash += size;
            if name == ".data" {
                sizes.ram += size;
            }
        }

        if name == ".text" {
            sizes.text += size;
        }
    }

    Ok(sizes)
}

// ============================================================================
// Baseline and report
// ============================================================================

type Baseline = Map<String, Value>;

fn load_baseline(root: &Path) -> Result<Baseline, String> {
    let path = root.join(BASELINE_FILE);

    match fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(Value::Object(map)) => Ok(map),
            Ok(_) => Err(format!("{} does not hold a JSON object", path.display())),
            Err(error) => Err(format!("failed to parse {}: {error}", path.display())),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(error) => Err(format!("failed to read {}: {error}", path.display())),
    }
}

fn baseline_entry(baseline: &Baseline, dir: &str, variant: &str) -> Option<Measurement> {
    baseline.get(dir).and_then(|entry| entry.get(variant)).and_then(Measurement::from_json)
}

fn store_baseline(
    root: &Path,
    mut baseline: Baseline,
    measured: &BTreeMap<&str, BTreeMap<&str, Measurement>>,
) -> Result<(), String> {
    for (dir, variants) in measured {
        let entry = variants.iter().map(|(variant, measurement)| ((*variant).to_owned(), measurement.to_json()));
        baseline.insert((*dir).to_owned(), Value::Object(entry.collect()));
    }

    let path = root.join(BASELINE_FILE);
    let mut text = serde_json::to_string_pretty(&Value::Object(baseline))
        .map_err(|error| format!("failed to encode the baseline: {error}"))?;
    text.push('\n');

    fs::write(&path, text).map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn print_table(measured: &BTreeMap<&str, BTreeMap<&str, Measurement>>, baseline: &Baseline) {
    println!();
    print!("{:<42} {:<9}", "target", "log");
    for field in Measurement::FIELDS {
        print!(" {field:>9} {:>7}", "Δ");
    }
    println!();

    // Keep the table in the order of TARGETS, not alphabetical.
    for target in TARGETS {
        let Some(variants) = measured.get(target.dir) else { continue };

        for variant in LogVariant::ALL {
            let Some(current) = variants.get(variant.key()) else { continue };
            let previous = baseline_entry(baseline, target.dir, variant.key());

            print!("{:<42} {:<9}", target.dir, variant.key());
            for field in Measurement::FIELDS {
                let value = current.get(field);
                let delta = previous.map(|previous| value as i64 - previous.get(field) as i64);

                match delta {
                    Some(delta) => print!(" {value:>9} {delta:>+7}"),
                    None => print!(" {value:>9} {:>7}", "new"),
                }
            }
            println!();
        }
    }
}

// ============================================================================
// Type sizes
// ============================================================================

/// Wrapper types that repeat the size of the type they wrap and would
/// otherwise list every large type five times over.
const WRAPPERS: &[&str] = &[
    "core::mem::MaybeUninit<",
    "core::mem::ManuallyDrop<",
    "core::mem::MaybeDangling<",
    "core::cell::UnsafeCell<",
    "static_cell::StaticCell<",
    "embassy_executor::raw::util::UninitCell<",
    "embassy_executor::raw::TaskPool<",
    "embassy_executor::_export::TaskPoolHolder<",
];

fn report_type_sizes(root: &Path, target: &FirmwareTarget, min_bytes: u64) -> Result<(), String> {
    let firmware = root.join(FIRMWARE_DIR);
    let target_dir = firmware.join("target/size-type-sizes");
    let project = firmware.join(target.dir);

    // Type sizes are printed while a crate compiles, and the stack's generic
    // types are laid out in the firmware crate that instantiates them. Clean
    // that one package so the build below recompiles and reprints it.
    let clean = Command::new("cargo")
        .current_dir(&project)
        .args(["clean", "--release", "--package", target.binary])
        .env("CARGO_TARGET_DIR", &target_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to start `cargo clean`: {error}"))?;

    if !clean.success() {
        return Err(format!("`cargo clean` failed for {}", target.dir));
    }

    eprintln!("Building {} with -Zprint-type-sizes...", target.dir);

    let output = Command::new("cargo")
        .current_dir(&project)
        .args(["build", "--release"])
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("RUSTFLAGS", "-Zprint-type-sizes")
        .env_remove("DEFMT_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("failed to start Cargo: {error}"))?;

    if !output.status.success() {
        return Err(format!("build failed for {}:\n{}", target.dir, String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();

    for (name, size) in parse_type_sizes(&stdout) {
        if size >= min_bytes && is_stack_type(name) && !WRAPPERS.iter().any(|wrapper| name.starts_with(wrapper)) {
            types.insert(shorten_type(name), size);
        }
    }

    let mut types: Vec<(String, u64)> = types.into_iter().collect();
    types.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

    println!("\nTypes ≥ {min_bytes} B in {}:", target.dir);
    for (name, size) in types {
        println!("{size:>8}  {name}");
    }

    Ok(())
}

/// `print-type-size type: `NAME`: SIZE bytes, alignment: A bytes`
fn parse_type_sizes(output: &str) -> impl Iterator<Item = (&str, u64)> {
    output.lines().filter_map(|line| {
        let rest = line.strip_prefix("print-type-size type: `")?;
        let (name, rest) = rest.rsplit_once("`: ")?;
        let size = rest.split_once(" bytes")?.0.parse().ok()?;
        Some((name, size))
    })
}

fn is_stack_type(name: &str) -> bool {
    name.contains("zweidraehte") || name.starts_with("embassy_executor::raw::TaskStorage<")
}

/// Keep type names short enough to scan: drop the crate prefixes of our own
/// crates and every generic argument list.
fn shorten_type(name: &str) -> String {
    let mut shortened = String::with_capacity(name.len());
    let mut depth = 0usize;

    for character in name.chars() {
        match character {
            '<' => {
                if depth == 0 {
                    shortened.push_str("<…>");
                }
                depth += 1;
            }
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => shortened.push(character),
            _ => {}
        }
    }

    shortened.replace("zweidraehte_device::", "").replace("zweidraehte_proto::", "proto::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generics_are_stripped_from_plain_and_qualified_paths() {
        assert_eq!(strip_generics("zweidraehte_device::handle::<Tp1<Def, 22>>"), "zweidraehte_device::handle");
        assert_eq!(
            strip_generics("<zweidraehte_device::ApplicationLayer<Tp1<Def>> as Layer<Tp1<Def>>>::process"),
            "<zweidraehte_device::ApplicationLayer as Layer>::process"
        );
        assert_eq!(
            strip_generics("<Stack<Tp1<Def>>>::persist::<BusyGate>::{closure#0}"),
            "<Stack>::persist::{closure#0}"
        );
    }

    #[test]
    fn type_size_lines_parse_and_shorten() {
        let output = "print-type-size type: `zweidraehte_device::router::Outbox`: 360 bytes, alignment: 4 bytes\n\
                      print-type-size     field `.messages`: 352 bytes\n";

        let parsed: Vec<(&str, u64)> = parse_type_sizes(output).collect();
        assert_eq!(parsed, [("zweidraehte_device::router::Outbox", 360)]);
        assert_eq!(shorten_type("zweidraehte_device::StackResources<Tp1<Def>, 279>"), "StackResources<…>");
    }

    #[test]
    fn allocated_sections_split_into_flash_and_ram() {
        // A minimal ELF32 LE image: header, a string table and five sections.
        let names = b"\0.text\0.data\0.bss\0.comment\0.shstrtab\0";
        let name_offset = |name: &[u8]| {
            names.windows(name.len()).position(|window| window == name).expect("name is in the table") as u32
        };
        let sections: [(u32, u32, u32, u32); 6] = [
            (0, 0, 0, 0),                             // null section
            (name_offset(b".text\0"), 1, 0x6, 100),   // PROGBITS, ALLOC|EXEC
            (name_offset(b".data\0"), 1, 0x3, 20),    // PROGBITS, ALLOC|WRITE
            (name_offset(b".bss\0"), 8, 0x3, 300),    // NOBITS, ALLOC|WRITE
            (name_offset(b".comment\0"), 1, 0x0, 50), // not allocated
            (name_offset(b".shstrtab\0"), 3, 0x0, 0), // the names themselves
        ];

        let names_at = 52;
        let table_at = names_at + names.len();
        let mut image = vec![0u8; table_at + sections.len() * 40];

        image[..6].copy_from_slice(&[0x7F, b'E', b'L', b'F', 1, 1]);
        image[0x20..0x24].copy_from_slice(&(table_at as u32).to_le_bytes());
        image[0x2E..0x30].copy_from_slice(&40u16.to_le_bytes());
        image[0x30..0x32].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        image[0x32..0x34].copy_from_slice(&5u16.to_le_bytes());
        image[names_at..table_at].copy_from_slice(names);

        for (index, (name, kind, flags, size)) in sections.iter().enumerate() {
            let base = table_at + index * 40;
            image[base..base + 4].copy_from_slice(&name.to_le_bytes());
            image[base + 4..base + 8].copy_from_slice(&kind.to_le_bytes());
            image[base + 8..base + 12].copy_from_slice(&flags.to_le_bytes());
            image[base + 20..base + 24].copy_from_slice(&size.to_le_bytes());
        }
        // The string table section points at the names.
        let shstrtab = table_at + 5 * 40;
        image[shstrtab + 16..shstrtab + 20].copy_from_slice(&(names_at as u32).to_le_bytes());

        let path = std::env::temp_dir().join(format!("xtask-size-test-{}.elf", std::process::id()));
        fs::write(&path, &image).expect("temporary ELF is writable");
        let sizes = read_elf_sections(&path).expect("synthetic ELF parses");
        let _ = fs::remove_file(&path);

        assert_eq!((sizes.flash, sizes.text, sizes.ram), (120, 100, 320));
    }
}
