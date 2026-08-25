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
    DeviceConfiguration, DeviceIdentity, DownloadScope, MembershipRole, ObjectMembership, ProcedureKind, ProductData,
    assemble, compile, compile_scoped, resolve_product_configuration,
};
use zweidraehte_client::{GroupAddress, IndividualAddress, pid};
use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::configuration::{ParameterSetting, ProductConfiguration, apply_configuration};
use zweidraehte_knxprod::runtime::model::ParameterValue;

const VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml"
);

const SYSTEM_B_VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/Weinzierl-420-1-KNX-TP-Push-Button-secure-5492-ETS5/",
    "M-00C5/M-00C5_A-040D-12-BC0E.xml"
);

const BCU2_VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/linggjanke_bcu2_secure_taster/M-00E1_A-E032-40-9322.xml"
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
        data_secure_enabled: false,
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
    product.configured_com_objects = Some(resolved.com_objects.clone());

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

#[test]
fn published_partial_procedures_compile_for_real_bcu2_and_system_b_products() {
    let Ok(mask_db) = load::load_mask_db(None, None) else {
        eprintln!("skipping: no master data available (set KNX_MASTER_DATA)");
        return;
    };
    for (path, expected) in [
        (std::path::Path::new(BCU2_VENDOR_XML), DownloadScope::ParametersAndGroupCommunication),
        (std::path::Path::new(SYSTEM_B_VENDOR_XML), DownloadScope::Parameters),
    ] {
        if !path.exists() {
            eprintln!("skipping {}: the licensed vendor XML is not on this machine", path.display());
            continue;
        }
        let (program, _, _) = load::load_program(path).expect("the vendor program parses");
        let mut product = ProductData::from_program(&program).expect("the product data extracts");
        let mask = mask_db.mask(product.mask_version.expect("the program names its mask")).expect("mask is described");
        let mut device = Device::new(program, None, None);
        let settings = ProductConfiguration { parameters: Vec::new(), objects: Vec::new() };
        apply_configuration(&mut device, &settings).expect("the default product configuration applies");
        let resolved = resolve_product_configuration(
            &device,
            &settings,
            DeviceConfiguration {
                identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 42), serial_number: None },
                data_secure_enabled: false,
                parameters: Vec::new(),
                object_memberships: Vec::new(),
                objects: Vec::new(),
                net_security: BTreeMap::new(),
                max_apdu: None,
            },
            &product,
        )
        .expect("the default configuration resolves");
        product.configured_com_objects = Some(resolved.com_objects);
        let project = resolved.project;

        let parameters =
            compile_scoped(&mask, &product, &project, DownloadScope::Parameters).expect("parameter procedure compiles");
        assert_eq!(parameters.scope(), expected, "{}", path.display());
        let full = compile(&mask, &product, &project).expect("full procedure compiles");
        assert!(
            parameters.instructions.len() < full.instructions.len(),
            "{} parameter procedure has {} steps, full has {}",
            path.display(),
            parameters.instructions.len(),
            full.instructions.len()
        );
        if path == std::path::Path::new(SYSTEM_B_VENDOR_XML) {
            for compiled in [&parameters, &full] {
                assert!(compiled.instructions.iter().any(|instruction| matches!(
                    instruction,
                    zweidraehte_client::download::Instruction::WriteProperty {
                        obj_idx: 4,
                        prop_id: pid::PROGRAM_VERSION,
                        data,
                        ..
                    } if data.as_slice() == product.task_identity.application_id
                )));
                assert!(
                    compiled.instructions.iter().any(|instruction| matches!(
                        instruction,
                        zweidraehte_client::download::Instruction::LoadImageProperty {
                            obj_idx: 4,
                            prop_id: pid::MCB_TABLE,
                            start_idx: 1,
                            count: 4,
                        }
                    )),
                    "{} must retain all four application MCB rows",
                    path.display()
                );
            }
        }

        let group = compile_scoped(&mask, &product, &project, DownloadScope::GroupCommunication)
            .expect("group procedure compiles");
        assert!(
            matches!(group.scope(), DownloadScope::GroupCommunication | DownloadScope::ParametersAndGroupCommunication),
            "{} selected {:?}",
            path.display(),
            group.scope()
        );
        if path == std::path::Path::new(SYSTEM_B_VENDOR_XML) {
            assert_eq!(group.scope(), DownloadScope::GroupCommunication);
            assert!(
                group.instructions.len() < full.instructions.len(),
                "System B group procedure has {} steps, full has {}",
                group.instructions.len(),
                full.instructions.len()
            );
            assert!(
                !group.instructions.iter().any(|instruction| matches!(
                    instruction,
                    zweidraehte_client::download::Instruction::LsmEvent {
                        lsm: zweidraehte_client::download::LsmTarget::Index(4 | 5),
                        ..
                    } | zweidraehte_client::download::Instruction::RelSegment {
                        lsm: zweidraehte_client::download::LsmTarget::Index(4 | 5),
                        ..
                    } | zweidraehte_client::download::Instruction::TaskSegment {
                        lsm: zweidraehte_client::download::LsmTarget::Index(4 | 5),
                        ..
                    } | zweidraehte_client::download::Instruction::WriteRelImage { obj_idx: 4 | 5, .. }
                )),
                "System B group-only procedure must not reload either application program"
            );
        }
    }
}
