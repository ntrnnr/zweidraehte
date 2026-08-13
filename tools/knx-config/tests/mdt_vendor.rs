//! The vendor-XML integration tier: parse the real MDT Push Button
//! Lite program, apply a small mods set, compile the download, and
//! snapshot everything that would reach the device.
//!
//! The vendor XML is licensed material living in the git-ignored
//! `manuf_tool_data/`; the test skips silently when it is absent, the
//! repo convention for such files. Master data comes from
//! `MaskDb::resolve()` (env var, cache, or download) and its absence
//! also skips rather than fails.

use std::fmt::Write;

use knx_config::load;
use zweidraehte_client::download::{ProcedureKind, ProductData, assemble, compile, resolve_mods};
use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::mods::{DeviceMods, apply_mods};

const VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml"
);

/// A mods set exercising the interesting encodings: an enum switch
/// (P-4), a bit-packed parameter sharing its octet with a neighbour
/// (P-6, offset 402 bit 6), and group links incl. one object with a
/// listening address.
const MODS: &str = r#"
[device]
individual_address = "1.1.60"

[[param]]
id = "M-0083_A-009B-14-E59D_P-4"
value = 1

[[param]]
id = "M-0083_A-009B-14-E59D_P-6"
value = 0

[[link]]
com_object = 0
group_addresses = ["5/1/1", "5/1/3"]

[[link]]
com_object = 1
group_addresses = ["5/1/2"]
"#;

#[test]
fn vendor_program_compiles_to_a_stable_download() {
    let path = std::path::Path::new(VENDOR_XML);
    if !path.exists() {
        eprintln!("skipping: the licensed vendor XML is not on this machine");
        return;
    }
    let Ok(mask_db) = load::load_mask_db(None, None) else {
        eprintln!("skipping: no master data available (set KNX_MASTER_DATA)");
        return;
    };

    let (program, _, _) = load::load_program(path).expect("the vendor program parses");
    let mut product = ProductData::from_program(&program).expect("the product data extracts");
    let mask = mask_db.mask(product.mask_version.expect("the program names its mask")).expect("MV-0705 is described");

    let mut device = Device::new(program, None, None);
    let mods: DeviceMods = toml::from_str(MODS).expect("the mods parse");
    apply_mods(&mut device, &mods).expect("the mods apply");
    let resolved = resolve_mods(&device, &mods, &product).expect("the configuration resolves");
    product.com_objects = resolved.com_objects.clone();

    let compiled = compile(&mask, &product, &resolved.project).expect("the download compiles");

    // Everything device-bound in one report: the exact region bytes
    // and the procedure. Any drift in parsing, resolution, table
    // building or patching shows up as a snapshot diff.
    let mut report = String::new();
    let _ = writeln!(report, "parameters patched: {}", resolved.project.parameters.len());
    let _ = writeln!(report, "links: {}", resolved.project.links.len());
    for (address, bytes) in compiled.image.regions() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(report, "region {address:#06x} ({} bytes): {hex}", bytes.len());
    }
    for instruction in &compiled.instructions {
        let _ = writeln!(report, "{instruction:?}");
    }
    insta::assert_snapshot!("mdt_full_download", report);

    // The clean-slate path `knx-loader unload` runs: the mask's
    // Unload-all template against the same product.
    let unload = assemble(&mask, &product, ProcedureKind::UnloadAll).expect("the unload procedure assembles");
    let mut unload_report = String::new();
    for instruction in &unload {
        let _ = writeln!(unload_report, "{instruction:?}");
    }
    insta::assert_snapshot!("mdt_unload_all", unload_report);
}
