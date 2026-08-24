//! The vendor-XML integration tier: parse the real MDT Push Button
//! Lite program, apply a small product configuration, compile the download, and
//! snapshot everything that would reach the device.
//!
//! The vendor XML is licensed material living in the git-ignored
//! `manuf_tool_data/`; the test skips silently when it is absent, the
//! repo convention for such files. Master data comes from
//! `MaskDb::resolve()` (env var, cache, or download) and its absence
//! also skips rather than fails.

use std::fmt::Write;

use knx_config::load;
use std::collections::BTreeMap;

use zweidraehte_client::download::{
    DeviceConfiguration, DeviceIdentity, MembershipRole, ObjectMembership, ProcedureKind, ProductData, assemble,
    compile, resolve_product_configuration,
};
use zweidraehte_client::{GroupAddress, IndividualAddress};
use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::configuration::{ParameterSetting, ProductConfiguration, apply_configuration};
use zweidraehte_knxprod::runtime::model::ParameterValue;

const VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml"
);

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
    let settings = ProductConfiguration {
        parameters: vec![
            ParameterSetting { id: "M-0083_A-009B-14-E59D_P-4".into(), value: ParameterValue::Integer(1) },
            ParameterSetting { id: "M-0083_A-009B-14-E59D_P-6".into(), value: ParameterValue::Integer(0) },
        ],
        objects: Vec::new(),
    };
    apply_configuration(&mut device, &settings).expect("the project settings apply");
    let primary = GroupAddress::from_three_level(5, 1, 1);
    let additional = GroupAddress::from_three_level(5, 1, 3);
    let second = GroupAddress::from_three_level(5, 1, 2);
    let configuration = DeviceConfiguration {
        identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 60), serial_number: None },
        parameters: Vec::new(),
        object_memberships: vec![
            ObjectMembership { group_address: primary, com_object: 0, role: MembershipRole::Primary },
            ObjectMembership { group_address: additional, com_object: 0, role: MembershipRole::Additional },
            ObjectMembership { group_address: second, com_object: 1, role: MembershipRole::Primary },
        ],
        objects: Vec::new(),
        net_security: BTreeMap::new(),
        max_apdu: None,
    };
    let resolved =
        resolve_product_configuration(&device, &settings, configuration, &product).expect("the configuration resolves");
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
