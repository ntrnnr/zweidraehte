//! Generate MTXML / knxprod / knxproj from the light switch device definition.
//!
//! Produces a multi-device package containing both a KNX/IP variant
//! and a TP1 (TPUART) variant of the same light switch. Both share
//! the same application logic, parameters, and page layout — they
//! differ only in mask version and therefore medium type.
//!
//! Usage:
//!   cargo run --bin gen_light_switch_mtxml              # MTXML only
//!   cargo run --bin gen_light_switch_mtxml -- --knxprod  # signed .knxprod package
//!   cargo run --bin gen_light_switch_mtxml -- --knxproj  # signed .knxproj test project

use std::env;
use std::path::PathBuf;

use const_default::ConstDefault;

use devices::light_switch::{
    DEVICE_DESCRIPTOR_IP, DEVICE_DESCRIPTOR_TP1, LightSwitchDevice, LightSwitchParams, comm_objs,
    params::LIGHT_SWITCH_VIRTUAL_PARAMS,
    translations::LIGHT_SWITCH_TRANSLATIONS,
};
use knxprod::definition::page_layout::EtsPageLayout;
use knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use knxprod::{
    ApplicationProgramDef, CatalogEntryDef, CatalogSectionDef, DeviceInstanceDef, HardwareDef,
    KnxprodBuilder, ProductDef,
};

/// Hardware serial for the KNX/IP variant.
const SERIAL_NUMBER_IP: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03];

/// Hardware serial for the TP1 variant.
const SERIAL_NUMBER_TP1: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x04];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as raw bytes for the knxprod.
    let defaults = LightSwitchParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(
            &defaults as *const LightSwitchParams as *const u8,
            core::mem::size_of::<LightSwitchParams>(),
        )
    };

    let page_layout = LightSwitchDevice::page_layout();

    // Both variants share the same application logic — only the device
    // descriptor (and thus the mask version / medium type) differs.
    let app_ip = ApplicationProgramDef {
        name: "LightSwitch2",
        device: &DEVICE_DESCRIPTOR_IP,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(page_layout.clone()),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
    };

    let app_tp1 = ApplicationProgramDef {
        name: "LightSwitch2TP",
        device: &DEVICE_DESCRIPTOR_TP1,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(page_layout),
        modules: None,
        baggages: None,
        translations: Some(LIGHT_SWITCH_TRANSLATIONS),
    };

    // Build a multi-device package: two application programs, two hardware
    // definitions (one IP, one TP1), and a single catalog section with both.
    let mut builder = KnxprodBuilder::new(LightSwitchDevice::MANUFACTURER_ID);
    let app_ip_ref = builder.application_program(&app_ip);
    let app_tp1_ref = builder.application_program(&app_tp1);

    let hw_ip_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_IP,
        hardware_version: 1,
        name: "2-Button Light Switch IP",
        bus_current: None,
        products: vec![ProductDef {
            name: "Light Switch 2-fold (IP)",
            order_number: "LS-0002-IP",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_ip_ref],
    });

    let hw_tp1_ref = builder.hardware(HardwareDef {
        serial_number: SERIAL_NUMBER_TP1,
        hardware_version: 1,
        name: "2-Button Light Switch TP1",
        bus_current: Some(10),
        products: vec![ProductDef {
            name: "Light Switch 2-fold (TP1)",
            order_number: "LS-0002-TP",
            is_rail_mounted: false,
            visible_description: None,
        }],
        application_programs: vec![app_tp1_ref],
    });

    builder.catalog(CatalogSectionDef {
        name: "Push Buttons",
        entries: vec![
            CatalogEntryDef {
                name: "Light Switch 2-fold (IP)",
                hardware: hw_ip_ref,
                product_order_number: "LS-0002-IP",
                application_program: app_ip_ref,
            },
            CatalogEntryDef {
                name: "Light Switch 2-fold (TP1)",
                hardware: hw_tp1_ref,
                product_order_number: "LS-0002-TP",
                application_program: app_tp1_ref,
            },
        ],
        subsections: vec![],
    });

    let generate_knxproj = env::args().any(|arg| arg == "--knxproj");
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    // Register device instances for knxproj generation. This must happen
    // before the builder is consumed by the chainable configuration methods.
    if generate_knxproj {
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch IP",
            hardware: hw_ip_ref,
            product_order_number: "LS-0002-IP",
            application_program: app_ip_ref,
        });
        builder.device_instance(DeviceInstanceDef {
            name: "2-Button Light Switch TP1",
            hardware: hw_tp1_ref,
            product_order_number: "LS-0002-TP",
            application_program: app_tp1_ref,
        });
    }

    let out_dir: PathBuf = ["out", "LightSwitch2"].iter().collect();
    let builder = builder
        .output_dir(&out_dir)
        .schema_version(KnxSchemaVersion::V20);

    if generate_knxproj {
        let knxproj_path = builder
            .project_name("Test Project LightSwitch2fold")
            .master_data(MasterDataSource::Download)
            .write_knxproj()?;

        println!(
            "Generated: {} ({} bytes)",
            knxproj_path.display(),
            std::fs::metadata(&knxproj_path)?.len()
        );
    } else if generate_knxprod {
        let (output, knxprod_path) = builder.master_data(MasterDataSource::Download).build_all()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for (filename, _) in output.xml_files() {
            println!("Generated: {}", manuf_dir.join(filename).display());
        }
        println!(
            "\nGenerated: {} ({} bytes)",
            knxprod_path.display(),
            std::fs::metadata(&knxprod_path)?.len()
        );
    } else {
        let (output, paths) = builder.write_mtxml_with_paths()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for path in &paths {
            println!("Generated: {}", path.display());
        }

        println!("\nAll MTXML files generated successfully!");
        println!("Tip: Use --knxprod or --knxproj flag for signed packages");
    }

    Ok(())
}
