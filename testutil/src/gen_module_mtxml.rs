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
use std::fs;
use std::path::PathBuf;

use knxprod::baggage_generator::{generate_baggages_xml, get_baggage_files_for_signing, write_baggage_files};
use knxprod::signing::{KnxSchemaVersion, MasterDataSource, SigningConfig, create_knxprod};
use testutil::devices::module_test_device::{
    BAGGAGES, DEVICE_DESCRIPTOR, DEVICE_VIRTUAL_PARAMS, DeviceParams, ModuleTestDevice, SERIAL_NUMBER,
};
use testutil::mtxml_gen::page_layout::EtsPageLayout;
use testutil::mtxml_gen::{ApplicationProgramConfig, CatalogGenerator, HardwareGenerator, MtxmlGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = DeviceParams::default();
    let param_bytes = unsafe {
        core::slice::from_raw_parts(&defaults as *const DeviceParams as *const u8, core::mem::size_of::<DeviceParams>())
    };

    // Create module collection
    let modules = ModuleTestDevice::create_modules();

    let config = ApplicationProgramConfig {
        name: "ModuleDimmer4Ch",
        device: &DEVICE_DESCRIPTOR,
        schema_version: Some(KnxSchemaVersion::V20),
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

        // Hardware/Catalog configuration
        serial_number: SERIAL_NUMBER,
        hardware_version: 1,
        hardware_name: "4-Channel Dimmer Module Test",
        product_name: "4-Ch Dimmer (Module Test)",
        order_number: "MOD-DIM-4CH",
        is_rail_mounted: false,
        catalog_section: "Dimmer Actuators",

        // Use the page layout from ModuleTestDevice
        page_layout: Some(ModuleTestDevice::page_layout()),
        modules: Some(modules),
        baggages: Some(BAGGAGES),
    };

    // Create output directory structure: out/<device>/M-XXXX/
    let manufacturer_id = format!("{:04X}", DEVICE_DESCRIPTOR.manufacturer_id);
    let out_dir: PathBuf = ["out", config.name, &format!("M-{}", manufacturer_id)].iter().collect();
    fs::create_dir_all(&out_dir)?;
    println!("Output directory: {}", out_dir.display());

    // Generate ApplicationProgram MTXML
    let app_xml = MtxmlGenerator::generate(&config)?;
    let app_path = out_dir.join("ModuleApplicationProgram1.mtxml");
    fs::write(&app_path, &app_xml)?;
    println!("Generated: {}", app_path.display());

    // Generate Hardware MTXML
    let hw_xml = HardwareGenerator::generate(&config)?;
    let hw_path = out_dir.join("ModuleHardware1.mtxml");
    fs::write(&hw_path, &hw_xml)?;
    println!("Generated: {}", hw_path.display());

    // Generate Catalog MTXML
    let cat_xml = CatalogGenerator::generate(&config)?;
    let cat_path = out_dir.join("ModuleCatalog1.mtxml");
    fs::write(&cat_path, &cat_xml)?;
    println!("Generated: {}", cat_path.display());

    // Write baggage files and Baggages.mtxml for MT project
    let schema_version = config.schema_version.unwrap_or_default();
    write_baggage_files(&out_dir, BAGGAGES)?;
    let baggages_xml = generate_baggages_xml(DEVICE_DESCRIPTOR.manufacturer_id, BAGGAGES, schema_version);
    // MT project expects Baggages.mtxml
    fs::write(out_dir.join("Baggages.mtxml"), &baggages_xml)?;
    println!("Generated: Baggages.mtxml and Baggages/ directory with {} files", BAGGAGES.len());

    println!("\nAll MTXML files generated successfully!");

    // Check if --knxprod flag is provided
    let generate_knxprod = env::args().any(|arg| arg == "--knxprod");

    if generate_knxprod {
        println!("\nGenerating signed .knxprod package...");

        // Build the application program ID from the device descriptor
        let app_number = format!("{:04X}", DEVICE_DESCRIPTOR.application_id);
        let app_version = format!("{:02X}", DEVICE_DESCRIPTOR.application_version);
        let application_program_id = format!("M-{}_A-{}-{}-0000", manufacturer_id, app_number, app_version);

        // Get baggage files for signing (includes Baggages.xml manifest and all baggage files)
        let baggage_files = get_baggage_files_for_signing(
            DEVICE_DESCRIPTOR.manufacturer_id,
            BAGGAGES,
            schema_version,
        )?;

        let signing_config = SigningConfig {
            manufacturer_id: manufacturer_id.clone(),
            application_program: app_xml.clone(),
            application_program_id,
            hardware: hw_xml.clone(),
            catalog: cat_xml.clone(),
            baggage_files,
        };

        let knxprod_bytes = create_knxprod(&signing_config, MasterDataSource::DownloadVersion(schema_version))?;
        // Write knxprod to out/<device>/<name>.knxprod
        let device_out_dir: PathBuf = ["out", config.name].iter().collect();
        let output_path = device_out_dir.join(format!("{}.knxprod", config.name));
        fs::write(&output_path, &knxprod_bytes)?;
        println!("Generated: {} ({} bytes)", output_path.display(), knxprod_bytes.len());
        println!("\nVerify with: python3 manuf_tool_data/knx_verifier.py all .");
    } else {
        println!("\nTip: Use --knxprod flag to also generate a signed .knxprod package");
    }

    Ok(())
}
