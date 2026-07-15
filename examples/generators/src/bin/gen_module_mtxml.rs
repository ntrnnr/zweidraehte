//! Generate MTXML from the module test device definition.
//!
//! This binary generates a complete set of MTXML files demonstrating
//! KNX module support with a 4-channel dimmer device:
//! - ModuleApplicationProgram1.mtxml - Application program with ModuleDefs
//! - ModuleHardware1.mtxml - Hardware and product definition
//! - ModuleCatalog1.mtxml - Catalog section and item
//!
//! Use --knxprod flag to also generate a signed .knxprod package.

use std::env;
use std::path::PathBuf;

use devices::module_test_device::{
    BAGGAGES, DEVICE_DESCRIPTOR, DEVICE_VIRTUAL_PARAMS, DeviceParams, MODULE_TRANSLATIONS_DE, MODULE_TRANSLATIONS_EN,
    ModuleTestDevice, SERIAL_NUMBER,
};
use zweidraehte_knxprod::definition::page_layout::EtsPageLayout;
use zweidraehte_knxprod::signing::{KnxSchemaVersion, MasterDataSource};
use zweidraehte_knxprod::{ApplicationProgramDef, KnxprodBuilder, SingleDeviceDef};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = DeviceParams::default();
    let param_bytes = unsafe {
        core::slice::from_raw_parts(&defaults as *const DeviceParams as *const u8, core::mem::size_of::<DeviceParams>())
    };

    // Create module collection
    let modules = ModuleTestDevice::create_modules();

    // Combine all translations (German + English)
    let all_translations: Vec<_> =
        MODULE_TRANSLATIONS_DE.iter().chain(MODULE_TRANSLATIONS_EN.iter()).copied().collect();

    let app = ApplicationProgramDef {
        name: "ModuleDimmer4Ch",
        device: &DEVICE_DESCRIPTOR,
        params: DeviceParams::ETS_PARAMS_EXT,
        // Device-level virtual params (ETS-only, not stored in device memory)
        virtual_params: Some(DEVICE_VIRTUAL_PARAMS),
        param_defaults: param_bytes,
        comm_objects: &[], // No global comm objects for this test
        comm_object_refs: &[],
        union_fields: None,
        channel_name: "General",
        absolute_segment_address: None, // System B uses relative segments
        system7_layout: None,           // System B doesn't use System 7 layout
        application_hash: None,         // Use default 0000
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        page_layout: Some(ModuleTestDevice::page_layout()),
        modules: Some(modules),
        baggages: Some(BAGGAGES),
        // Combined German and English translations
        translations: Some(&all_translations),
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    // Output directory: out/<device>/
    let out_dir: PathBuf = ["out", app.name].iter().collect();

    let builder = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "4-Channel Dimmer Module Test",
        product_name: "4-Ch Dimmer (Module Test)",
        order_number: "MOD-DIM-4CH",
        is_rail_mounted: false,
        catalog_section: "Dimmer Actuators",
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .output_dir(&out_dir)
    .file_prefix("Module")
    .schema_version(KnxSchemaVersion::V20);

    // Check if --knxprod flag is provided
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        // Use KnxprodBuilder to generate everything including signed package
        let (output, knxprod_path) = builder.master_data(MasterDataSource::Download).build_all()?;

        // Print what was generated
        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for (filename, _) in output.xml_files() {
            println!("Generated: {}", manuf_dir.join(filename).display());
        }
        if !output.baggage_files.is_empty() {
            println!("Generated: Baggages/ directory with {} files", output.baggage_files.len());
        }
        println!("\nGenerated: {} ({} bytes)", knxprod_path.display(), std::fs::metadata(&knxprod_path)?.len());
        println!("\nVerify with: python3 manuf_tool_data/knx_verifier.py all .");
    } else {
        // Just generate MTXML files
        let (output, paths) = builder.write_mtxml_with_paths()?;

        let manuf_dir = out_dir.join(format!("M-{}", output.manufacturer_id));
        println!("Output directory: {}", manuf_dir.display());
        for path in &paths {
            println!("Generated: {}", path.display());
        }

        println!("\nAll MTXML files generated successfully!");
        println!("\nTip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
