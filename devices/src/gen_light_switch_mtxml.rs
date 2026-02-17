//! Generate MTXML / knxprod from the light switch device definition.
//!
//! This demonstrates how a binary crate consumes the transport-agnostic
//! device definition from the `devices` crate and fills in the
//! platform-specific details for KNXPROD generation.
//!
//! Usage:
//!   cargo run --bin gen_light_switch_mtxml            # MTXML only
//!   cargo run --bin gen_light_switch_mtxml -- --knxprod  # full signed package

use std::env;
use std::path::PathBuf;

use const_default::ConstDefault;

use devices::light_switch::{
    DEVICE_DESCRIPTOR_IP, LightSwitchDevice, LightSwitchParams, comm_objs,
};
use knxprod::definition::page_layout::EtsPageLayout;
use knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use knxprod::{ApplicationProgramConfig, KnxprodBuilder};

/// Serial number for the demo light switch.
const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as raw bytes for the knxprod
    let defaults = LightSwitchParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(
            &defaults as *const LightSwitchParams as *const u8,
            core::mem::size_of::<LightSwitchParams>(),
        )
    };

    let config = ApplicationProgramConfig {
        name: "LightSwitch2",
        device: &DEVICE_DESCRIPTOR_IP,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: None,
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

        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "2-Button Light Switch",
        product_name: "Light Switch 2-fold",
        order_number: "LS-0002",
        is_rail_mounted: false,
        catalog_section: "Push Buttons",

        page_layout: Some(LightSwitchDevice::page_layout()),
        modules: None,
        baggages: None,
        translations: None,
    };

    let out_dir: PathBuf = ["out", config.name].iter().collect();
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        let (output, knxprod_path) = KnxprodBuilder::new(&config)
            .output_dir(&out_dir)
            .schema_version(KnxSchemaVersion::V20)
            .master_data(MasterDataSource::Download)
            .build_all()?;

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
        let (output, paths) = KnxprodBuilder::new(&config)
            .output_dir(&out_dir)
            .schema_version(KnxSchemaVersion::V20)
            .write_mtxml_with_paths()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for path in &paths {
            println!("Generated: {}", path.display());
        }

        println!("\nAll MTXML files generated successfully!");
        println!("Tip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
